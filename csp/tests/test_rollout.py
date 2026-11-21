from __future__ import annotations

from datetime import datetime, timezone

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.rollout import (
    Approval,
    ApprovalLedger,
    DecisionEngine,
    Observation,
    PolicyWindow,
    Review,
    ReviewStatus,
    decide,
    decide_for_request,
)

T0 = datetime(2026, 3, 1, 8, tzinfo=timezone.utc)
T1 = datetime(2026, 3, 2, 8, tzinfo=timezone.utc)
T2 = datetime(2026, 3, 3, 8, tzinfo=timezone.utc)
T3 = datetime(2026, 3, 4, 8, tzinfo=timezone.utc)


def test_two_overlapping_approvals_report_the_approvers_actually_used() -> None:
    ledger = ApprovalLedger()
    ledger.approve(
        "approval-a",
        "checkout-pilot",
        "/checkout/",
        starts_at=T0,
        ends_at=T3,
        approved_by="alice",
        policy_id="csp-v2",
    )
    ledger.approve(
        "approval-b",
        "checkout-pilot",
        "/checkout/",
        starts_at=T0,
        ends_at=T3,
        approved_by="bob",
        policy_id="csp-v2",
    )

    before_revocation = ledger.decide(
        "/checkout/payment",
        "checkout-pilot",
        at=T1,
        policy_id="csp-v2",
    )
    assert before_revocation.enforce is True
    assert before_revocation.mode.value == "enforce"
    assert before_revocation.approval_ids == ("approval-a", "approval-b")
    assert before_revocation.approved_by == ("alice", "bob")

    ledger.revoke("approval-a", at=T2, by="secops", reason="pilot owner withdrew")
    after_revocation = ledger.decide(
        "/checkout/payment",
        "checkout-pilot",
        at=T2.replace(hour=12),
        policy_id="csp-v2",
    )

    assert after_revocation.enforce is True
    assert after_revocation.approval_ids == ("approval-b",)
    assert after_revocation.approved_by == ("bob",)
    assert any(rejection.code == "revoked" and rejection.approval_id == "approval-a" for rejection in after_revocation.rejections)

    # A decision is a snapshot. Revoking an approval later must not rewrite the
    # decision that was already handed to a request.
    assert before_revocation.approval_ids == ("approval-a", "approval-b")
    assert before_revocation.approved_by == ("alice", "bob")


def test_observation_data_is_never_promoted_to_a_new_audience_credential() -> None:
    observation = Observation(
        "obs-legacy",
        audience="legacy-pilot",
        path="/checkout/",
        observed_at=T0,
        policy_id="csp-v2",
    )
    borrowed_observation = Approval(
        "borrowed-obs",
        audience="new-pilot",
        path="/checkout/",
        source="observation",
        approved_by="alice",
        policy_id="csp-v2",
    )

    decision = decide(
        "/checkout/payment",
        "new-pilot",
        at=T1,
        policy_id="csp-v2",
        approvals=[borrowed_observation],
        observations=[observation],
    )

    assert decision.enforce is False
    assert decision.mode.value == "report_only"
    assert decision.reason == "observation_is_not_a_release_credential"
    assert decision.rejection_codes() == ("observation_credential",)
    assert decision.used_approvals == ()

    observation_as_credential = decide(
        "/checkout/payment",
        "new-pilot",
        at=T1,
        policy_id="csp-v2",
        approvals=[observation],
    )
    assert observation_as_credential.enforce is False
    assert observation_as_credential.reason == "observation_is_not_a_release_credential"


def test_approval_mapping_derived_from_observation_is_rejected() -> None:
    approval = Approval.from_mapping(
        {
            "approval_id": "copied-observation",
            "audience": "new-pilot",
            "path": "/checkout/",
            "derived_from_observation": True,
            "approved_by": "alice",
        }
    )

    decision = decide("/checkout/payment", "new-pilot", at=T1, approvals=[approval])

    assert approval.source.value == "observation"
    assert decision.enforce is False
    assert decision.reason == "observation_is_not_a_release_credential"


def test_path_audience_window_policy_and_review_must_all_match() -> None:
    base = {
        "id": "approval-a",
        "audience": "checkout-pilot",
        "path": "/checkout/",
        "starts_at": T0,
        "ends_at": T3,
        "approved_by": "alice",
        "policy_id": "csp-v2",
    }

    assert decide("/checkout/", "checkout-pilot", at=T1, policy_id="csp-v2", approvals=[base]).enforce is True
    assert decide("/admin/", "checkout-pilot", at=T1, policy_id="csp-v2", approvals=[base]).rejection_codes() == ("path_mismatch",)
    assert decide("/checkout/", "other-pilot", at=T1, policy_id="csp-v2", approvals=[base]).rejection_codes() == ("audience_mismatch",)
    assert decide("/checkout/", "checkout-pilot", at=T0, policy_id="csp-v3", approvals=[base]).rejection_codes() == ("policy_mismatch",)
    assert decide("/checkout/", "checkout-pilot", at=T3, policy_id="csp-v2", approvals=[base]).rejection_codes() == ("expired",)

    pending = {**base, "review_status": "pending"}
    assert decide("/checkout/", "checkout-pilot", at=T1, policy_id="csp-v2", approvals=[pending]).rejection_codes() == ("review_pending",)


def test_an_external_review_can_complete_a_pending_approval() -> None:
    approval = Approval(
        "approval-a",
        audience="checkout-pilot",
        path="/checkout/",
        starts_at=T0,
        ends_at=T3,
        review_status=ReviewStatus.PENDING,
        approved_by="alice",
        policy_id="csp-v2",
    )
    review = Review(
        "approved",
        approval_id="approval-a",
        reviewed_by="carol",
        reviewed_at=T1,
    )

    before_review = decide("/checkout/", "checkout-pilot", at=T0.replace(hour=9), policy_id="csp-v2", approvals=[approval], reviews=[review])
    after_review = decide("/checkout/", "checkout-pilot", at=T1, policy_id="csp-v2", approvals=[approval], reviews=[review])

    assert before_review.rejection_codes() == ("review_pending",)
    assert after_review.enforce is True
    assert after_review.approved_by == ("carol",)


def test_a_review_revocation_mid_window_drops_only_that_approval() -> None:
    first = Approval(
        "approval-a",
        audience="checkout-pilot",
        path="/checkout/",
        starts_at=T0,
        ends_at=T3,
        approved_by="alice",
    )
    second = Approval(
        "approval-b",
        audience="checkout-pilot",
        path="/checkout/",
        starts_at=T0,
        ends_at=T3,
        approved_by="bob",
    )
    revocation = Review("revoked", approval_id="approval-a", reviewed_by="secops", reviewed_at=T2)

    before = decide("/checkout/", "checkout-pilot", at=T1, approvals=[first, second], reviews=[revocation])
    after = decide("/checkout/", "checkout-pilot", at=T2, approvals=[first, second], reviews=[revocation])

    assert before.approved_by == ("alice", "bob")
    assert after.approved_by == ("bob",)
    assert after.rejection_codes() == ("review_revoked",)


def test_policy_window_and_decision_headers() -> None:
    window = PolicyWindow(start=T0, end=T3)
    assert window.contains(T0) is True
    assert window.contains(T1) is True
    assert window.contains(T3) is False
    assert window.contains(T0.replace(hour=7)) is False

    approval = Approval(
        "approval-a",
        audience="checkout-pilot",
        path="/checkout/",
        window=window,
        approved_by="alice",
        policy_id="csp-v2",
    )
    decision = decide("/checkout/", "checkout-pilot", at=T1, policy_id="csp-v2", approvals=[approval], policy="default-src 'self'")
    assert decision.header_name == HEADER
    assert decision.headers() == {HEADER: "default-src 'self'"}

    response = HttpResponse()
    decision.apply(response)
    assert response[HEADER] == "default-src 'self'"

    report_only = decide("/checkout/", "unknown", at=T1, approvals=[approval])
    assert report_only.header_name == HEADER_REPORT_ONLY


def test_decide_for_request_uses_request_path_and_audience() -> None:
    request = RequestFactory().get("/checkout/payment")
    request.csp_audiences = {"checkout-pilot"}
    approval = Approval(
        "approval-a",
        audience="checkout-pilot",
        path="/checkout/",
        starts_at=T0,
        ends_at=T3,
        approved_by="alice",
    )

    decision = decide_for_request(request, at=T1, approvals=[approval], config={})

    assert decision.enforce is True
    assert decision.path == "/checkout/payment"
    assert request.csp_rollout_decision is decision


@override_settings(
    CSP_ROLLOUT={
        "POLICY_ID": "csp-v2",
        "APPROVALS": [
            {
                "id": "approval-a",
                "audience": "checkout-pilot",
                "path": "/checkout/",
                "starts_at": T0,
                "ends_at": T3,
                "approved_by": "alice",
                "policy_id": "csp-v2",
            }
        ],
    }
)
def test_decide_for_request_reads_rollout_setting() -> None:
    request = RequestFactory().get("/checkout/payment")
    request.csp_audiences = {"checkout-pilot"}

    decision = decide_for_request(request, at=T1)

    assert decision.enforce is True
    assert decision.approval_ids == ("approval-a",)


def test_decision_engine_and_ledger_unknown_revocation() -> None:
    engine = DecisionEngine(
        approvals=[
            Approval(
                "approval-a",
                audience="checkout-pilot",
                path="/checkout/",
                starts_at=T0,
                ends_at=T3,
                approved_by="alice",
            )
        ]
    )
    assert engine.decide("/checkout/", "checkout-pilot", at=T1).enforce is True

    ledger = ApprovalLedger()
    with pytest.raises(KeyError):
        ledger.revoke("missing", at=T1)
