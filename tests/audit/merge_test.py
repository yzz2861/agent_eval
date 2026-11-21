import pytest

from detect_secrets.audit.merge import merge_adjudications
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from testing.factories import potential_secret_factory


def make_collection(*secrets):
    collection = SecretsCollection()
    for secret in secrets:
        collection[secret.filename].add(secret)

    return collection


def index_by_hash(collection):
    return {
        secret.secret_hash: secret
        for _, secret in collection
    }


def hash_of(secret):
    return PotentialSecret.hash_secret(secret)


@pytest.fixture
def forked_baselines():
    """A mainline and a maintenance branch, diverged from a common ancestor.

    Each branch adjudicates one finding on its own, and they disagree on a third.
    """
    ancestor = make_collection(
        potential_secret_factory(filename='config.py', secret='mainline-secret'),
        potential_secret_factory(filename='config.py', secret='maintenance-secret'),
        potential_secret_factory(filename='config.py', secret='contested-secret'),
    )
    mainline = make_collection(
        potential_secret_factory(
            filename='config.py', secret='mainline-secret', is_secret=True,
        ),
        potential_secret_factory(filename='config.py', secret='maintenance-secret'),
        potential_secret_factory(
            filename='config.py', secret='contested-secret', is_secret=True,
        ),
    )
    maintenance = make_collection(
        potential_secret_factory(filename='config.py', secret='mainline-secret'),
        potential_secret_factory(
            filename='config.py', secret='maintenance-secret', is_secret=False,
        ),
        potential_secret_factory(
            filename='config.py', secret='contested-secret', is_secret=False,
        ),
    )

    return ancestor, mainline, maintenance


class TestMergeAdjudications:
    def test_each_branch_carries_its_own_decision(self, forked_baselines):
        result = merge_adjudications(*forked_baselines)

        decisions = index_by_hash(result.decisions)
        assert decisions[hash_of('mainline-secret')].is_secret is True
        assert decisions[hash_of('maintenance-secret')].is_secret is False

    def test_similar_findings_in_same_file_do_not_share_a_verdict(self, forked_baselines):
        result = merge_adjudications(*forked_baselines)

        decisions = index_by_hash(result.decisions)
        mainline_secret = decisions[hash_of('mainline-secret')]
        maintenance_secret = decisions[hash_of('maintenance-secret')]

        assert mainline_secret.filename == maintenance_secret.filename == 'config.py'
        assert mainline_secret.type == maintenance_secret.type
        assert mainline_secret.is_secret != maintenance_secret.is_secret

    def test_conflicts_are_separated_from_decisions(self, forked_baselines):
        result = merge_adjudications(*forked_baselines)

        decisions = index_by_hash(result.decisions)
        conflicts = index_by_hash(result.conflicts)

        assert hash_of('contested-secret') not in decisions
        assert hash_of('contested-secret') in conflicts
        assert conflicts[hash_of('contested-secret')].is_secret is None
        assert not set(decisions) & set(conflicts)

    def test_merge_is_read_only(self, forked_baselines):
        ancestor, mainline, maintenance = forked_baselines

        merge_adjudications(ancestor, mainline, maintenance)

        for _, secret in ancestor:
            assert secret.is_secret is None
        assert index_by_hash(mainline)[hash_of('contested-secret')].is_secret is True
        assert index_by_hash(maintenance)[hash_of('contested-secret')].is_secret is False

    def test_manual_review_can_withdraw_a_carried_decision(self, forked_baselines):
        result = merge_adjudications(*forked_baselines)

        assert result.withdraw(
            potential_secret_factory(filename='config.py', secret='mainline-secret'),
        ) is True
        assert hash_of('mainline-secret') not in index_by_hash(result.decisions)

    def test_withdraw_returns_false_for_unknown_findings(self, forked_baselines):
        result = merge_adjudications(*forked_baselines)

        assert result.withdraw(
            potential_secret_factory(filename='config.py', secret='unknown-secret'),
        ) is False
        # Conflicts are not carried decisions, so there is nothing to withdraw.
        assert result.withdraw(
            potential_secret_factory(filename='config.py', secret='contested-secret'),
        ) is False

    def test_export_contains_hashes_but_no_plaintext(self, forked_baselines):
        result = merge_adjudications(*forked_baselines)

        for _, secret in result.decisions:
            assert secret.secret_value is None
        for _, secret in result.conflicts:
            assert secret.secret_value is None

        exported = result.json()
        assert set(exported) == {'decisions', 'conflicts'}

        decision_entries = exported['decisions']['config.py']
        assert all('hashed_secret' in entry for entry in decision_entries)
        assert 'mainline-secret' not in str(exported['decisions'])
        assert 'contested-secret' not in str(exported['conflicts'])

    def test_agreeing_branches_do_not_conflict(self):
        ancestor = make_collection(
            potential_secret_factory(filename='config.py', secret='secret'),
        )
        branches = [
            make_collection(
                potential_secret_factory(
                    filename='config.py', secret='secret', is_secret=True,
                ),
            )
            for _ in range(2)
        ]

        result = merge_adjudications(ancestor, *branches)

        decisions = index_by_hash(result.decisions)
        assert decisions[hash_of('secret')].is_secret is True
        assert not result.conflicts

    def test_ancestor_decision_carries_when_branches_leave_it_untouched(self):
        ancestor = make_collection(
            potential_secret_factory(
                filename='config.py', secret='secret', is_secret=False, is_verified=True,
            ),
        )
        branch = make_collection(
            potential_secret_factory(filename='config.py', secret='secret'),
        )

        result = merge_adjudications(ancestor, branch)

        carried = index_by_hash(result.decisions)[hash_of('secret')]
        assert carried.is_secret is False
        assert carried.is_verified is True

    def test_branch_can_only_adjudicate_within_its_scope(self):
        ancestor = make_collection(
            potential_secret_factory(filename='config.py', secret='secret'),
        )
        # This branch never saw the finding, so it cannot weigh in.
        out_of_scope_branch = make_collection(
            potential_secret_factory(filename='other.py', secret='other-secret'),
        )
        in_scope_branch = make_collection(
            potential_secret_factory(
                filename='config.py', secret='secret', is_secret=True,
            ),
        )

        result = merge_adjudications(ancestor, out_of_scope_branch, in_scope_branch)

        decisions = index_by_hash(result.decisions)
        assert decisions[hash_of('secret')].is_secret is True
        assert not result.conflicts

    def test_undecided_findings_are_not_carried(self, forked_baselines):
        ancestor, mainline, maintenance = forked_baselines
        for collection in (ancestor, mainline, maintenance):
            collection['config.py'].add(
                potential_secret_factory(filename='config.py', secret='untriaged-secret'),
            )

        result = merge_adjudications(ancestor, mainline, maintenance)

        assert hash_of('untriaged-secret') not in index_by_hash(result.decisions)
        assert hash_of('untriaged-secret') not in index_by_hash(result.conflicts)
