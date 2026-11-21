"""
This module performs a three-way merge of audit decisions (a.k.a. adjudications)
across baselines that have diverged from a common ancestor -- e.g. a mainline
baseline and a maintenance-branch baseline that were both audited independently.

Given an explicit ancestor baseline, and any number of branch baselines, decisions
are carried forward according to the following rules:

    1. A branch can only adjudicate findings within its own scope (i.e. secrets
       present in that branch's baseline).

    2. If no branch changed the ancestor's decision, the ancestor's decision
       carries forward as-is.

    3. Unlabelled findings are treated as abstentions: a branch that never
       adjudicated a finding does not override the ancestor's decision, nor
       does it conflict with branches that did.

    4. If only one distinct decision differs from the ancestor's (i.e. a single
       branch changed it, or all changing branches agree), that decision carries
       forward.

    5. If branches disagree, the finding is flagged as a conflict, and requires
       manual adjudication.

Findings are identified by (filename, secret type, hashed secret), so two similar
findings in the same file never share a single adjudication.

The merge is read-only: the inputs are never mutated, and the results never hold
plaintext secrets -- only their hashes participate in the exported output.
"""
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple

from ..core.potential_secret import PotentialSecret
from ..core.secrets_collection import SecretsCollection


# A decision is the (is_secret, is_verified) label pair attached to a finding.
Decision = Tuple[Optional[bool], bool]

# Findings that were never adjudicated carry no opinion, and cannot vote.
UNDECIDED: Decision = (None, False)

# Findings are keyed by identity, rather than by location, so that line numbers
# (which shift between branches) don't matter, and neighbouring findings in the
# same file are adjudicated independently.
FindingKey = Tuple[str, str, str]


class AdjudicationMerge:
    """Read-only result of :func:`merge_adjudications`.

    Carried decisions and unresolved conflicts are kept separate, so callers can
    act on them independently.
    """

    def __init__(self, decisions: SecretsCollection, conflicts: SecretsCollection) -> None:
        #: decisions that could be derived unambiguously
        self.decisions = decisions

        #: findings that branches disagree on, and need manual adjudication
        self.conflicts = conflicts

    def withdraw(self, secret: PotentialSecret) -> bool:
        """Manual review can revoke a carried decision.

        :param secret: the finding whose decision should be withdrawn
        :return: True if a matching decision was found and withdrawn
        """
        if secret.filename not in self.decisions.files:
            return False

        mapping = {
            item: item
            for item in self.decisions[secret.filename]
        }
        if secret not in mapping:
            return False

        self.decisions[secret.filename].discard(mapping[secret])
        return True

    def json(self) -> Dict[str, Any]:
        """Custom JSON encoder. Plaintext secrets never participate in this export."""
        return {
            'decisions': self.decisions.json(),
            'conflicts': self.conflicts.json(),
        }


def merge_adjudications(
    ancestor: SecretsCollection,
    *branches: SecretsCollection,
) -> AdjudicationMerge:
    """Derives which audit decisions to carry forward from diverged baselines.

    This function is read-only: neither the ancestor nor the branches are modified.

    :param ancestor: the common baseline the branches diverged from
    :param branches: the diverged baselines, each defining its own scope of
        adjudicatable findings
    """
    ancestor_index = _index(ancestor)
    branch_indexes = [_index(branch) for branch in branches]

    keys = set(ancestor_index)
    for index in branch_indexes:
        keys |= set(index)

    decisions = SecretsCollection()
    conflicts = SecretsCollection()

    for key in sorted(keys):
        ancestor_decision: Decision = (
            _decision_of(ancestor_index[key])
            if key in ancestor_index
            else UNDECIDED
        )
        changed_decisions = {
            decision
            for index in branch_indexes
            if key in index
            for decision in [_decision_of(index[key])]
            if decision not in (ancestor_decision, UNDECIDED)
        }

        representative = ancestor_index.get(key) or next(
            index[key]
            for index in branch_indexes
            if key in index
        )
        carried = _copy_without_plaintext(representative)

        if len(changed_decisions) > 1:
            # Branches disagree: a human needs to adjudicate this one.
            carried.is_secret = None
            carried.is_verified = False
            conflicts[carried.filename].add(carried)
            continue

        if changed_decisions:
            carried.is_secret, carried.is_verified = changed_decisions.pop()
        else:
            carried.is_secret, carried.is_verified = ancestor_decision

        if carried.is_secret is None and not carried.is_verified:
            # Nothing was ever decided about this finding.
            continue

        decisions[carried.filename].add(carried)

    return AdjudicationMerge(decisions=decisions, conflicts=conflicts)


def _decision_of(secret: PotentialSecret) -> Decision:
    return secret.is_secret, secret.is_verified


def _index(collection: SecretsCollection) -> Dict[FindingKey, PotentialSecret]:
    return {
        (filename, secret.type, secret.secret_hash): secret
        for filename, secret in collection
    }


def _copy_without_plaintext(secret: PotentialSecret) -> PotentialSecret:
    return PotentialSecret.load_secret_from_dict(secret.json())
