import datetime as dt

from detect_secrets.core.potential_secret import PotentialSecret

from detect_secrets.exception_policy import (
    DecisionStatus,
    ExceptionEngine,
    ExceptionStore,
    RuleVersion,
    Scope,
    SecretIdentity,
    build_record,
    conflict_detail_to_dict,
    merge_exception_stores,
)
from tests.exception_policy.conftest import SECRET_VALUE, make_approved_record, make_finding

UTC = dt.timezone.utc


def _identity():
    return SecretIdentity.from_hashed_secret(
        "AWSKeyDetector",
        PotentialSecret.hash_secret(SECRET_VALUE),
    )


def _branch_record(decision_id, now, expiry, **kwargs):
    kwargs.setdefault("decided_by", "alice")
    kwargs.setdefault("rationale", "branch decision")
    return make_approved_record(
        _identity(),
        Scope.from_string("acme", "config"),
        RuleVersion.parse("AWSKeyDetector", "1.4.0"),
        now,
        expiry,
        decision_id=decision_id,
        **kwargs,
    )


def test_clean_merge_has_no_conflicts(now, expiry, approved_record):
    left = ExceptionStore([approved_record])
    right = ExceptionStore([approved_record])
    report = merge_exception_stores([left, right])
    assert not report.has_conflicts
    assert report.merged_decision_ids == ["decision-1"]


def test_conflicting_branches_are_explained_not_auto_resolved(now, expiry):
    left = ExceptionStore([_branch_record("a", now, expiry)])
    right = ExceptionStore(
        [_branch_record("b", now, expiry, decided_by="bob",
                        rationale="branch B disagrees")],
    )
    report = merge_exception_stores([left, right])
    assert report.has_conflicts
    detail = report.conflicts[0]
    assert sorted(detail.conflict.decision_ids) == ["a", "b"]
    assert "decided_by" in detail.differing_fields
    assert "rationale" in detail.differing_fields

    payload = conflict_detail_to_dict(detail)
    assert payload["candidate_decision_ids"] == ["a", "b"]

    engine = ExceptionEngine(report.store)
    decision = engine.evaluate(make_finding(), now)
    assert decision.status is DecisionStatus.CONFLICT
    assert all(record.decision_id in ("a", "b") for record in decision.matching_records)


def test_resolution_requires_a_new_superseding_decision(now, expiry):
    left = ExceptionStore([_branch_record("a", now, expiry)])
    right = ExceptionStore([_branch_record("b", now, expiry, decided_by="bob")])
    merged = merge_exception_stores([left, right]).store

    resolution = build_record(
        _identity(),
        Scope.from_string("acme", "config"),
        RuleVersion.parse("AWSKeyDetector", "1.4.0"),
        decided_by="security-board",
        rationale="explicit post-merge decision",
        created_at=now,
        expires_at=expiry,
        decision_id="resolution",
        supersedes=("a", "b"),
    )
    merged.add(resolution)
    assert merged.active_conflicts() == []
    engine = ExceptionEngine(merged)
    decision = engine.evaluate(make_finding(), now)
    assert decision.status is DecisionStatus.EXEMPT
    assert decision.matching_records[0].decision_id == "resolution"
