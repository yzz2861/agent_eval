.. _rollout-chapter:

=====================================
Audience-scoped CSP rollout decisions
=====================================

Moving a site from ``Content-Security-Policy-Report-Only`` to an enforced
``Content-Security-Policy`` is safest when the change is limited to a small,
explicitly approved audience.  django-csp exposes that decision as an
independent, immutable runtime object rather than deriving it from the
presence of a report-only policy.

The implementation lives in ``csp.rollout``.  The same API is available from
``csp.decision`` for callers that prefer a decision-oriented import path.


The decision inputs
===================

An enforcement decision is produced only when an :class:`~csp.rollout.Approval`
matches *all* of these dimensions:

* **Path** - the approval path scope covers the request path.  Exact paths,
  path prefixes (``/checkout/`` covers ``/checkout/payment``), and shell-style
  patterns (``/checkout/*``) are supported.
* **Audience** - the approval audience intersects the request audience.
* **Policy window** - the decision time is inside the approval's half-open
  effective window.
* **Review status** - the latest review available at the decision time is
  ``approved``.
* **Policy identity** - when both the decision and the approval supply a
  policy id, they must match.
* **Credential kind** - only records whose kind is ``approval`` can authorize
  enforcement.

When no approval qualifies, the decision falls back to ``report_only`` and
records a rejection reason for every candidate.  The fallback is deliberate:
the absence of an approval never means "enforce everywhere".


Approvals, observations, and credentials
========================================

Report-only telemetry is useful for deciding whether a policy is ready, but it
is not an approval.  An :class:`~csp.rollout.Observation` is therefore never
treated as a credential.  An approval that is copied from observation data
(``source="observation"`` or ``derived_from_observation=True``) is rejected
with ``observation_credential``.  This prevents an observation made for one
audience from being replayed as release permission for a different audience.

A new audience needs a distinct approval record for that audience, even when
the supporting evidence came from an older observation.


Basic use
=========

.. code-block:: python

    from datetime import datetime, timezone

    from csp.rollout import Approval, decide

    window_start = datetime(2026, 3, 1, 8, tzinfo=timezone.utc)
    window_end = datetime(2026, 3, 4, 8, tzinfo=timezone.utc)

    approval = Approval(
        "approval-17",
        audience="checkout-pilot",
        path="/checkout/",
        starts_at=window_start,
        ends_at=window_end,
        approved_by="alice",
        policy_id="csp-v2",
    )

    decision = decide(
        path="/checkout/payment",
        audience="checkout-pilot",
        at=datetime(2026, 3, 2, 12, tzinfo=timezone.utc),
        policy_id="csp-v2",
        approvals=[approval],
    )

    assert decision.enforce is True
    assert decision.approved_by == ("alice",)

The decision exposes the approvals that were actually effective at the moment
of evaluation:

* ``decision.used_approvals`` - the full immutable approval records.
* ``decision.approval_ids`` - their ids.
* ``decision.approved_by`` - the reviewers who authorized them.
* ``decision.rejections`` - why other candidate approvals were not used.

Use ``decision.header_name`` when selecting the response header.  If the
policy document is supplied as well, ``decision.headers()`` and
``decision.apply(response)`` apply the correct header for the selected mode.


Overlapping approvals and mid-window revocation
===============================================

Two approvals may cover the same request at the same time.  The decision lists
both while both are effective.  Revoking one approval during the window does
not rewrite decisions that were already produced; the next decision simply uses
the remaining approval:

.. code-block:: python

    from csp.rollout import ApprovalLedger

    ledger = ApprovalLedger()
    ledger.approve(
        "approval-a",
        "checkout-pilot",
        "/checkout/",
        starts_at=window_start,
        ends_at=window_end,
        approved_by="alice",
        policy_id="csp-v2",
    )
    ledger.approve(
        "approval-b",
        "checkout-pilot",
        "/checkout/",
        starts_at=window_start,
        ends_at=window_end,
        approved_by="bob",
        policy_id="csp-v2",
    )

    before = ledger.decide(
        "/checkout/payment",
        "checkout-pilot",
        at=datetime(2026, 3, 2, 12, tzinfo=timezone.utc),
        policy_id="csp-v2",
    )
    assert before.approval_ids == ("approval-a", "approval-b")
    assert before.approved_by == ("alice", "bob")

    ledger.revoke("approval-a", at=datetime(2026, 3, 3, tzinfo=timezone.utc))

    after = ledger.decide(
        "/checkout/payment",
        "checkout-pilot",
        at=datetime(2026, 3, 3, 12, tzinfo=timezone.utc),
        policy_id="csp-v2",
    )
    assert after.approval_ids == ("approval-b",)
    assert after.approved_by == ("bob",)

    # The earlier decision remains the record of what the request actually used.
    assert before.approval_ids == ("approval-a", "approval-b")


Django request integration
==========================

``decide_for_request`` reads the path from ``request.path_info`` and the
audience from ``request.csp_audiences``, ``request.csp_audience``, or
``request.audiences``.  The audience is not inferred from a request header.
Approval data can be passed directly or supplied through a ``CSP_ROLLOUT``
setting:

.. code-block:: python

    CSP_ROLLOUT = {
        "POLICY_ID": "csp-v2",
        "APPROVALS": [
            {
                "id": "approval-17",
                "audience": "checkout-pilot",
                "path": "/checkout/",
                "starts_at": "2026-03-01T08:00:00+00:00",
                "ends_at": "2026-03-04T08:00:00+00:00",
                "approved_by": "alice",
                "review_status": "approved",
            }
        ],
        "REVIEWS": [],
        "OBSERVATIONS": [],
    }

    from csp.rollout import decide_for_request

    decision = decide_for_request(request)
    request.csp_rollout_decision = decision

The resulting decision is request-local.  It can be logged, attached to error
reports, or used by middleware to choose between the enforced and report-only
header without consulting a second, shared rollout state.
