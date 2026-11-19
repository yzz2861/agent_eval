import json

import pytest

from detect_secrets.exception_policy import (
    DecisionState,
    DuplicateDecisionError,
    ExceptionStore,
    RuleVersion,
    Scope,
    SecretIdentity,
    merge_stores,
)
from tests.exception_policy.conftest import make_approved_record


def _identity(suffix="x"):
    return SecretIdentity.from_hashed_secret("AWS", f"hash-{suffix}")


def _record(decision_id, identity, now, expiry, **kwargs):
    return make_approved_record(
        identity,
        Scope.from_string("acme", "config"),
        RuleVersion.parse("AWS", "1.0.0"),
        now,
        expiry,
        decision_id=decision_id,
        **kwargs,
    )


def test_add_is_append_only_and_rejects_duplicates(store, approved_record):
    initial_len = len(store.records)
    with pytest.raises(DuplicateDecisionError):
        store.add(approved_record)
    assert len(store.records) == initial_len


def test_records_accessor_returns_defensive_copy(store):
    store.records.clear()
    assert len(store.records) == 1


def test_heads_hide_superseded_records(now, expiry):
    identity = _identity()
    first = _record("d1", identity, now, expiry)
    second = _record(
        "d2", identity, now, expiry, rationale="renewed", supersedes=("d1",),
    )
    store = ExceptionStore([first, second])
    heads = store.heads_for(identity)
    assert [record.decision_id for record in heads] == ["d2"]


def test_active_conflicts_detect_divergent_approvals(now, expiry):
    identity = _identity()
    branch_a = _record("a", identity, now, expiry)
    branch_b = _record("b", identity, now, expiry, decided_by="bob")
    store = ExceptionStore([branch_a, branch_b])
    conflicts = store.active_conflicts()
    assert len(conflicts) == 1
    assert conflicts[0].decision_ids == ["a", "b"]


def test_revocation_clears_conflict(now, expiry):
    identity = _identity()
    branch_a = _record("a", identity, now, expiry)
    branch_b = _record(
        "b", identity, now, expiry, decided_by="bob",
        state=DecisionState.REVOKED,
    )
    assert ExceptionStore([branch_a, branch_b]).active_conflicts() == []


def test_file_round_trip(tmp_path, store):
    path = tmp_path / "exceptions.json"
    store.write(path)
    reloaded = ExceptionStore.read(path)
    assert reloaded.to_dict() == store.to_dict()


def test_rejects_unknown_version():
    with pytest.raises(ValueError):
        ExceptionStore.from_dict({"version": 999, "records": []})


def test_merge_unions_and_dedupes_shared_records(now, expiry, store):
    other = ExceptionStore(list(store.records))
    merged = merge_stores([store, other])
    assert len(merged.records) == len(store.records)


def test_merge_surfaces_divergent_heads_instead_of_picking(now, expiry):
    identity = _identity()
    left = ExceptionStore([_record("a", identity, now, expiry)])
    right = ExceptionStore(
        [_record("b", identity, now, expiry, decided_by="bob")],
    )
    merged = merge_stores([left, right])
    assert [conflict.decision_ids for conflict in merged.active_conflicts()] == [["a", "b"]]
