"""Demonstrate scoped maintenance notifications from a TUF target diff.

Run from the repository root:

    python examples/scoped_review/demo.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tuf.api.metadata import TargetFile
from tuf.maintenance import (
    AbandonedNotificationError,
    BatchState,
    DeliveryChannel,
    DraftState,
    EvidenceKind,
    NotificationGenerator,
    PolicyControl,
    ScopedDiffReview,
    ScopePolicy,
    SharedDigest,
    StaleReviewError,
)

PUMP = "pump-crew"
VALVE = "valve-crew"
REVIEWER = "security-operations"


def target(path: str, digest: str, component: str) -> TargetFile:
    return TargetFile(
        4096,
        {"sha256": digest},
        path,
        {"custom": {"component_id": component}},
    )


def h(char: str) -> str:
    return char * 64


def owner_map() -> dict[str, str]:
    return {
        "site-a/pump/controller-v1": PUMP,
        "site-a/pump/controller-v2": PUMP,
        "site-a/pump/sensor-main": PUMP,
        "site-a/pump/sensor-backup": PUMP,
        "site-a/pump/telemetry": PUMP,
        "site-a/pump/diagnostics": PUMP,
        "site-a/pump/legacy-notes": PUMP,
        "site-a/valve/actuator": VALVE,
        "site-a/valve/legacy-notes": VALVE,
    }


def snapshots() -> tuple[dict[str, TargetFile], dict[str, TargetFile]]:
    old = {
        "site-a/pump/controller-v1": target(
            "site-a/pump/controller-v1", h("1"), "pump-controller"
        ),
        "site-a/pump/sensor-main": target(
            "site-a/pump/sensor-main", h("2"), "pump-sensor"
        ),
        "site-a/pump/telemetry": target(
            "site-a/pump/telemetry", h("3"), "pump-telemetry"
        ),
        "site-a/pump/diagnostics": target(
            "site-a/pump/diagnostics", h("4"), "pump-diagnostics"
        ),
        "site-a/pump/legacy-notes": target(
            "site-a/pump/legacy-notes", h("5"), "pump-legacy"
        ),
        "site-a/valve/actuator": target(
            "site-a/valve/actuator", h("6"), "valve-actuator"
        ),
        "site-a/valve/legacy-notes": target(
            "site-a/valve/legacy-notes", h("7"), "valve-legacy"
        ),
    }
    new = {
        "site-a/pump/controller-v2": target(
            "site-a/pump/controller-v2", h("8"), "pump-controller"
        ),
        "site-a/pump/sensor-main": target(
            "site-a/pump/sensor-main", h("9"), "pump-sensor"
        ),
        "site-a/pump/sensor-backup": target(
            "site-a/pump/sensor-backup", h("9"), "pump-sensor"
        ),
        "site-a/pump/telemetry": target(
            "site-a/pump/telemetry", h("a"), "pump-telemetry"
        ),
        "site-a/pump/diagnostics": target(
            "site-a/pump/diagnostics", h("a"), "pump-diagnostics"
        ),
        "site-a/valve/actuator": target(
            "site-a/valve/actuator", h("b"), "valve-actuator"
        ),
    }
    return old, new


def show_pump_notice(review: ScopedDiffReview) -> None:
    view = review.for_scope(PUMP)
    text = view.render_text()
    print(text)
    print()
    print("pump totals:", json.dumps(view.totals.as_dict(), sort_keys=True))
    print(
        "reviewer totals:",
        json.dumps(review.reviewer_view.totals.as_dict(), sort_keys=True),
    )
    print("pump deletion notes:", view.deletion_notes)
    print("old artifacts for pump:", [a.path for a in view.old_artifacts])
    print()

    serialized = json.dumps(view.as_dict())
    assert "site-a/valve" not in text
    assert "site-a/valve" not in serialized
    assert view.totals.removed == 1
    assert review.reviewer_view.totals.removed == 2
    assert all("valve" not in note for note in view.deletion_notes)
    print("scope check: pump notice has no valve path and local removals=1")
    print("             while reviewer removals=2 is never exposed")
    print()


def show_evidence(review: ScopedDiffReview) -> None:
    view = review.for_scope(PUMP)
    print("independent evidence in the pump review:")
    for change in view.changes:
        kinds = ", ".join(sorted(kind.value for kind in change.evidence_kinds))
        print("  " + change.kind.value + " " + change.path + " [" + kinds + "]")
        for evidence in change.evidence:
            if isinstance(evidence, DeliveryChannel):
                print("    channel proof names only: " + evidence.path)
            elif isinstance(evidence, SharedDigest):
                print("    shared digest peers: " + ", ".join(evidence.peers))
    print()

    channels = [
        change
        for change in view.changes
        if EvidenceKind.DELIVERY_CHANNEL in change.evidence_kinds
    ]
    assert len(channels) == 2
    first, second = channels
    assert first.path not in json.dumps(second.as_dict())
    assert second.path not in json.dumps(first.as_dict())
    print("channel check: two changes, each with its own path-only proof")
    print()


def show_policy_boundary(
    control: PolicyControl,
    review: ScopedDiffReview,
    old: dict[str, TargetFile],
    new: dict[str, TargetFile],
) -> None:
    generator = NotificationGenerator(control)
    batch = generator.open_batch(review)
    pump_draft = batch.generate(PUMP)
    batch.close()
    print("draft before policy change:", pump_draft.state.value)
    print()

    owners = owner_map()
    owners["site-a/pump/sensor-backup"] = REVIEWER
    control.replace(ScopePolicy(2, owners))

    boundary = batch.abandonment
    assert boundary is not None
    assert pump_draft.state is DraftState.ABANDONED
    assert batch.state is BatchState.ABANDONED
    assert batch.deliverable() == ()
    print("policy changed at boundary version:", boundary.policy_version)
    print("reason:", boundary.reason)
    print("abandoned drafts:", boundary.draft_ids)
    print("deliverable drafts after boundary:", len(batch.deliverable()))
    print()

    try:
        batch.deliver()
    except AbandonedNotificationError as error:
        print("delivery refused:", error)

    try:
        generator.open_batch(review)
    except StaleReviewError as error:
        print("stale review refused:", error)
    print()

    rerun = ScopedDiffReview.build(old, new, control.policy)
    fresh = NotificationGenerator(control).open_batch(rerun)
    fresh_draft = fresh.generate(PUMP)
    text = fresh_draft.render()
    assert "site-a/pump/sensor-backup" not in text
    print("after the boundary, the reassigned channel is hidden:")
    print(
        "  sensor-backup in fresh pump notice:",
        "site-a/pump/sensor-backup" in text,
    )
    fresh.close()
    fresh.deliver()


def main() -> None:
    old, new = snapshots()
    policy = ScopePolicy(1, owner_map())
    control = PolicyControl(policy)
    review = ScopedDiffReview.build(old, new, policy)

    print("== pump-crew maintenance notice ==")
    show_pump_notice(review)
    show_evidence(review)
    print("== policy change during notification generation ==")
    show_policy_boundary(control, review, old, new)


if __name__ == "__main__":
    main()
