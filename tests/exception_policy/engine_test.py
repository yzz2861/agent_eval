import datetime as dt

import pytest

from detect_secrets.exception_policy import (
    DecisionState,
    DecisionStatus,
    ExceptionEngine,
    ExceptionStore,
    build_record,
)
from tests.exception_policy.conftest import make_finding


def test_moved_file_keeps_exception(store, now, expiry):
    # Same secret content, new path inside the approved subtree.
    engine = ExceptionEngine(store)
    moved = make_finding(path="config/nested/renamed.yaml")
    decision = engine.evaluate(moved, now + dt.timedelta(days=1))
    assert decision.status is DecisionStatus.EXEMPT
    assert decision.is_exempt
    assert decision.matching_records[0].decision_id == "decision-1"


def test_rotated_secret_does_not_inherit_exception(store, now):
    engine = ExceptionEngine(store)
    rotated = make_finding(secret_value="brand-new-rotated-key")
    decision = engine.evaluate(rotated, now)
    assert decision.status is DecisionStatus.NO_EXCEPTION
    assert not decision.is_exempt


def test_clock_boundary_just_before_expiry_is_exempt(store, now, expiry):
    engine = ExceptionEngine(store)
    decision = engine.evaluate(
        make_finding(), expiry - dt.timedelta(seconds=1),
    )
    assert decision.status is DecisionStatus.EXEMPT


def test_clock_boundary_at_exact_expiry_is_expired(store, now, expiry):
    engine = ExceptionEngine(store)
    decision = engine.evaluate(make_finding(), expiry)
    assert decision.status is DecisionStatus.EXPIRED


def test_not_yet_valid_before_effective_time(identity, approved_scope, rule, now):
    record = build_record(
        identity, approved_scope, rule,
        decided_by="alice", rationale="future grant",
        created_at=now,
        effective_at=now + dt.timedelta(days=2),
        expires_at=now + dt.timedelta(days=10),
        decision_id="future",
    )
    engine = ExceptionEngine(ExceptionStore([record]))
    decision = engine.evaluate(make_finding(), now + dt.timedelta(days=1))
    assert decision.status is DecisionStatus.NOT_YET_VALID


def test_scope_widening_requires_new_decision(store, now):
    engine = ExceptionEngine(store)
    outside = make_finding(path="other-service/app.yaml")
    decision = engine.evaluate(outside, now)
    assert decision.status is DecisionStatus.SCOPE_WIDENED
    assert "scope" in decision.reasons[0]


def test_other_project_never_matches(store, now):
    engine = ExceptionEngine(store)
    foreign = make_finding(path="config/app.yaml", project="different-project")
    assert engine.evaluate(foreign, now).status is DecisionStatus.SCOPE_WIDENED


def test_rule_major_upgrade_forces_rejudgement(store, now):
    engine = ExceptionEngine(store)
    upgraded = make_finding(rule_version="2.0.0")
    decision = engine.evaluate(upgraded, now)
    assert decision.status is DecisionStatus.RULE_UPGRADED


def test_rule_minor_bump_keeps_exception(store, now):
    engine = ExceptionEngine(store)
    compatible = make_finding(rule_version="1.9.0")
    assert engine.evaluate(compatible, now).status is DecisionStatus.EXEMPT


def test_revoked_record_denies(identity, approved_scope, rule, now, expiry):
    record = build_record(
        identity, approved_scope, rule,
        decided_by="alice", rationale="withdrawn",
        created_at=now, expires_at=expiry,
        state=DecisionState.REVOKED, decision_id="rev",
    )
    engine = ExceptionEngine(ExceptionStore([record]))
    assert engine.evaluate(make_finding(), now).status is DecisionStatus.REVOKED


def test_snapshot_is_required_and_aware(store):
    engine = ExceptionEngine(store)
    with pytest.raises(ValueError):
        engine.evaluate(make_finding(), dt.datetime(2026, 1, 1))


def test_historical_replay_is_deterministic(store, now, expiry):
    # Same immutable store + same snapshot always yields the same verdict,
    # including a report generated before the exception expired.
    engine = ExceptionEngine(store)
    historical_snapshot = now + dt.timedelta(days=5)
    first = engine.evaluate(make_finding(), historical_snapshot)
    second = engine.evaluate(make_finding(), historical_snapshot)
    assert first.status == second.status == DecisionStatus.EXEMPT

    after_expiry = engine.evaluate(make_finding(), expiry + dt.timedelta(days=1))
    assert after_expiry.status is DecisionStatus.EXPIRED


def test_evaluate_many_returns_one_decision_per_finding(store, now):
    engine = ExceptionEngine(store)
    findings = [
        make_finding(path="config/a.yaml"),
        make_finding(secret_value="unknown", path="config/b.yaml"),
    ]
    decisions = engine.evaluate_many(findings, now)
    assert [decision.status for decision in decisions] == [
        DecisionStatus.EXEMPT,
        DecisionStatus.NO_EXCEPTION,
    ]
