import json
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from detect_secrets.core.exception_policy import evaluate_collection
from detect_secrets.core.exception_policy import ExceptionRecord
from detect_secrets.core.exception_policy import ExceptionReport
from detect_secrets.core.exception_policy import ExceptionStatus
from detect_secrets.core.exception_policy import ExceptionStore
from detect_secrets.core.exception_policy import SecretIdentity
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import ConflictingExceptionError
from testing.factories import potential_secret_factory


SECRET_TYPE = 'High Entropy String'
SCOPE = 'payments-service'
RULE_VERSION = '1.2'
RULE_VERSIONS = {SECRET_TYPE: RULE_VERSION}
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
EXPIRES_AT = NOW + timedelta(days=90)


def make_record(
    secret='hunter2',
    type=SECRET_TYPE,
    scope=SCOPE,
    rule_version=RULE_VERSION,
    expires_at=EXPIRES_AT,
    rationale='approved false positive',
    decided_at=NOW,
    decided_by='alice',
):
    return ExceptionRecord(
        identity=SecretIdentity(
            secret_hash=PotentialSecret.hash_secret(secret),
            rule_id=type,
        ),
        scope=scope,
        rule_version=rule_version,
        expires_at=expires_at,
        rationale=rationale,
        decided_at=decided_at,
        decided_by=decided_by,
    )


def make_secret(secret='hunter2', filename='config/settings.py', line_number=10):
    return potential_secret_factory(
        type=SECRET_TYPE,
        filename=filename,
        secret=secret,
        line_number=line_number,
    )


def make_collection(*secrets):
    collection = SecretsCollection()
    for secret in secrets:
        collection.data[secret.filename].add(secret)
    return collection


def scan_report(store, collection, scope=SCOPE, rule_versions=None, at=NOW):
    return evaluate_collection(
        collection,
        store,
        scope,
        RULE_VERSIONS if rule_versions is None else rule_versions,
        at,
    )


class TestIdentityBinding:
    def test_file_move_does_not_revoke_exception(self):
        store = ExceptionStore([make_record()])
        moved = make_secret(filename='new/location/renamed.py', line_number=99)

        report = scan_report(store, make_collection(moved))

        assert [entry.status for entry in report.entries] == [ExceptionStatus.APPROVED]
        assert report.actionable == []

    def test_secret_rotation_does_not_inherit_exception(self):
        store = ExceptionStore([make_record(secret='hunter2')])
        rotated = make_secret(secret='hunter3')

        report = scan_report(store, make_collection(rotated))

        assert [entry.status for entry in report.entries] == [ExceptionStatus.NOT_FOUND]
        assert report.entries[0].reason == 'no exception covers this secret identity'

    def test_mixed_scan_result_summary(self):
        store = ExceptionStore([make_record(secret='known-placeholder')])
        collection = make_collection(
            make_secret(secret='known-placeholder', filename='a.py'),
            make_secret(secret='brand-new-secret', filename='b.py'),
        )

        report = scan_report(store, collection)

        by_filename = {entry.filename: entry.status for entry in report.entries}
        assert by_filename == {
            'a.py': ExceptionStatus.APPROVED,
            'b.py': ExceptionStatus.NOT_FOUND,
        }
        assert [entry.filename for entry in report.actionable] == ['b.py']


class TestScopeAndRuleVersion:
    def test_scope_expansion_requires_fresh_decision(self):
        store = ExceptionStore([make_record(scope='payments-service')])

        decision = store.decide(
            SecretIdentity.from_secret(make_secret()),
            scope='payments-service-and-billing',
            rule_version=RULE_VERSION,
            at=NOW,
        )

        assert decision.status is ExceptionStatus.SCOPE_MISMATCH
        assert 'payments-service' in decision.reason
        assert not decision.is_exempt

    def test_rule_semantic_upgrade_requires_fresh_decision(self):
        store = ExceptionStore([make_record(rule_version='1.2')])

        report = scan_report(
            store,
            make_collection(make_secret()),
            rule_versions={SECRET_TYPE: '2.0'},
        )

        entry = report.entries[0]
        assert entry.status is ExceptionStatus.RULE_VERSION_MISMATCH
        assert '1.2' in entry.reason
        assert '2.0' in entry.reason

    def test_missing_rule_version_is_an_error(self):
        with pytest.raises(ValueError):
            scan_report(
                ExceptionStore(),
                make_collection(make_secret()),
                rule_versions={},
            )


class TestExpiry:
    @pytest.mark.parametrize(
        'offset, expected',
        [
            (timedelta(seconds=-1), ExceptionStatus.APPROVED),
            (timedelta(0), ExceptionStatus.EXPIRED),
            (timedelta(seconds=1), ExceptionStatus.EXPIRED),
        ],
    )
    def test_expiry_boundary_uses_caller_snapshot(self, offset, expected):
        store = ExceptionStore([make_record()])

        decision = store.decide(
            SecretIdentity.from_secret(make_secret()),
            SCOPE,
            RULE_VERSION,
            at=EXPIRES_AT + offset,
        )

        assert decision.status is expected

    def test_naive_datetime_is_rejected(self):
        store = ExceptionStore([make_record()])

        with pytest.raises(ValueError):
            store.decide(
                SecretIdentity.from_secret(make_secret()),
                SCOPE,
                RULE_VERSION,
                at=datetime(2026, 6, 1, 12, 0, 0),
            )

    def test_expired_decision_is_explainable(self):
        store = ExceptionStore([make_record()])

        decision = store.decide(
            SecretIdentity.from_secret(make_secret()),
            SCOPE,
            RULE_VERSION,
            at=EXPIRES_AT + timedelta(days=1),
        )

        assert decision.status is ExceptionStatus.EXPIRED
        assert decision.record is not None
        assert 'expired' in decision.reason


class TestMerge:
    def test_identical_records_merge_cleanly(self):
        result = ExceptionStore([make_record()]).merge(ExceptionStore([make_record()]))

        assert result.ok
        assert len(result.store) == 1

    def test_disjoint_records_merge(self):
        result = ExceptionStore([make_record(secret='a')]).merge(
            ExceptionStore([make_record(secret='b')]),
        )

        assert result.ok
        assert len(result.store) == 2

    def test_conflicting_records_are_never_picked_arbitrarily(self):
        ours = ExceptionStore([make_record(rationale='branch A approval')])
        theirs = ExceptionStore([
            make_record(
                rationale='branch B approval',
                expires_at=EXPIRES_AT + timedelta(days=30),
            ),
        ])

        result = ours.merge(theirs)

        assert not result.ok
        assert len(result.conflicts) == 1
        conflict = result.conflicts[0]
        explanation = conflict.explain()
        assert 'branch A approval' in explanation
        assert 'branch B approval' in explanation
        assert 'expires_at' in conflict.differing_fields

        # Neither side is applied: the secret must be re-judged.
        assert len(result.store) == 0
        decision = result.store.decide(
            SecretIdentity.from_secret(make_secret()),
            SCOPE,
            RULE_VERSION,
            at=NOW,
        )
        assert decision.status is ExceptionStatus.NOT_FOUND

    def test_merge_is_deterministic(self):
        ours = ExceptionStore([make_record(secret='a'), make_record(secret='b')])
        theirs = ExceptionStore([make_record(secret='b'), make_record(secret='c')])

        first = ours.merge(theirs)
        second = theirs.merge(ours)

        assert first.store == second.store
        assert [c.binding_key for c in first.conflicts] == [
            c.binding_key for c in second.conflicts
        ]

    def test_store_add_rejects_conflicting_duplicate(self):
        store = ExceptionStore([make_record()])

        with pytest.raises(ConflictingExceptionError):
            store.add(make_record(rationale='different rationale'))


class TestSerialization:
    def test_store_round_trip(self):
        store = ExceptionStore([
            make_record(),
            make_record(secret='other', scope='other-scope'),
        ])

        restored = ExceptionStore.from_dict(json.loads(json.dumps(store.to_dict())))

        assert restored == store

    def test_record_keeps_rationale_but_never_plaintext(self):
        secret = make_secret(secret='super-secret-value')

        record = ExceptionRecord.grant(
            secret,
            scope=SCOPE,
            rule_version=RULE_VERSION,
            expires_at=EXPIRES_AT,
            rationale='approved by security review SEC-123',
            decided_at=NOW,
            decided_by='alice',
        )

        blob = json.dumps(ExceptionStore([record]).to_dict())
        assert 'super-secret-value' not in blob
        assert 'approved by security review SEC-123' in blob
        assert record.identity.secret_hash == PotentialSecret.hash_secret(
            'super-secret-value',
        )


class TestHistoricalReplay:
    def make_report(self, store, at=NOW):
        return scan_report(store, make_collection(make_secret()), at=at)

    def test_report_replays_against_same_store(self):
        store = ExceptionStore([make_record()])
        report = self.make_report(store)

        assert report.replay(store) == []

    def test_serialized_report_still_replays(self):
        store = ExceptionStore([make_record()])
        report = self.make_report(store)

        restored = ExceptionReport.from_dict(json.loads(json.dumps(report.to_dict())))

        assert restored.replay(store) == []

    def test_replay_uses_original_snapshot_not_wall_clock(self):
        store = ExceptionStore([make_record()])
        report = self.make_report(store, at=NOW)

        # Evaluating the same scan far in the future would expire the exception...
        future = scan_report(
            store,
            make_collection(make_secret()),
            at=NOW + timedelta(days=365),
        )
        assert future.entries[0].status is ExceptionStatus.EXPIRED

        # ...but the historical report still reproduces its original judgement.
        assert report.entries[0].status is ExceptionStatus.APPROVED
        assert report.replay(store) == []

    def test_replay_flags_changed_store(self):
        store = ExceptionStore([make_record()])
        report = self.make_report(store)

        mismatches = report.replay(ExceptionStore())

        assert len(mismatches) == 1
        assert 'approved' in mismatches[0]
        assert 'not_found' in mismatches[0]
