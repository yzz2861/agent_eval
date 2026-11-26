#!/usr/bin/env python3
"""Replay a duplicate-ticket attachment through anchor revoke and reassignment.

Run from the repository root::

    python examples/identity_resolution/replay.py

The four bundles are ordinary STIX 2.1 documents.  Only the import order and
the analyst decisions change between the reported runs.
"""

import importlib
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

stix2 = importlib.import_module("stix2")


HERE = Path(__file__).resolve().parent

BUNDLES = {
    "case-alpha": "case_alpha_bundle.json",
    "case-beta": "case_beta_bundle.json",
    "case-review": "case_review_bundle.json",
    "legacy": "legacy_event_bundle.json",
}


def load_bundle(name):
    with (HERE / BUNDLES[name]).open(encoding="utf-8") as handle:
        return json.load(handle)


def build_service(order=None):
    service = stix2.ImportService()
    for name in order or ("case-alpha", "case-beta", "case-review", "legacy"):
        service.ingest(load_bundle(name), batch=name)
    return service


def relationship(service, external_id):
    return next(
        candidate.object for candidate in service.candidates(external_id)
    )


def candidate_for_ticket(service, ticket, batch):
    return next(
        candidate for candidate in service.candidates(ticket)
        if candidate.batch == batch
    )


def describe(resolution):
    if resolution.candidate is None:
        return "{} ({})".format(resolution.status.value, resolution.reason)
    target = resolution.candidate
    return "{} {} [{}, modified {}] ({})".format(
        resolution.status.value,
        target.stix_id,
        target.batch,
        target.version.isoformat() if target.version else "unversioned",
        resolution.reason,
    )


def show_attachment(label, attachment):
    print("{}".format(label))
    for reference, resolution in sorted(attachment.references.items()):
        print("  {:<58} {}".format(reference, describe(resolution)))
    print("  attachment: {}".format(attachment.status.value))


def main():
    service = build_service()

    print("=" * 78)
    print("Candidate occupancy")
    print("=" * 78)
    for slot in service.occupancy("identity--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"):
        print("  identity--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        for candidate in slot.candidates:
            print("    {:<12} {}  revoked={}".format(
                candidate.batch,
                candidate.version.isoformat() if candidate.version else "-",
                candidate.revoked,
            ))
        print("    claimants={} same-version-conflict={}".format(
            len(slot.candidates), slot.conflicted,
        ))

    early = relationship(service, "EVT-7781")
    late = relationship(service, "EVT-7782")

    print()
    print("=" * 78)
    print("1. Pre-merge event: only earlier versions are visible")
    print("=" * 78)
    show_attachment("EVT-7781 (modified 2024-03-05)", service.attach(early))

    print()
    print("=" * 78)
    print("2. Analyst confirms both ticket anchors against the post-merge batch")
    print("=" * 78)
    service.confirm_anchor(
        "TKT-0042",
        candidate=candidate_for_ticket(service, "TKT-0042", "case-beta"),
        confirmed_by="analyst.li",
        note="case merge review",
    )
    service.confirm_anchor(
        "TKT-0043",
        candidate=candidate_for_ticket(service, "TKT-0043", "case-beta"),
        confirmed_by="analyst.li",
        note="case merge review",
    )
    show_attachment("EVT-7781 with anchors", service.attach(early))

    print()
    print("=" * 78)
    print("3. Anchors revoked: deterministic fallback reassigns the event")
    print("=" * 78)
    service.revoke_anchor("TKT-0042", revoked_by="reviewer.chen")
    service.revoke_anchor("TKT-0043", revoked_by="reviewer.chen")
    show_attachment("EVT-7781 after revoke", service.attach(early))

    print()
    print("=" * 78)
    print("4. Review flag and batch provenance")
    print("=" * 78)
    service.archive("case-beta")
    reviewed = service.resolve(
        "TKT-0042", version="2024-04-15T00:00:00Z", batch="case-other",
    )
    print("  visible at 2024-04-15, beta archived: {}".format(describe(reviewed)))
    service.unarchive("case-beta")

    post_merge = service.resolve(
        "TKT-0042", version="2024-06-15T00:00:00Z", batch="case-beta",
    )
    print("  visible at 2024-06-15, referrer in case-beta: {}".format(
        describe(post_merge),
    ))

    print()
    print("=" * 78)
    print("5. Branch archive changes the candidate set, not the rule order")
    print("=" * 78)
    service.archive("case-alpha")
    show_attachment(
        "EVT-7781 with case-alpha archived", service.attach(early),
    )
    service.unarchive("case-alpha")

    print()
    print("=" * 78)
    print("6. Reordered receipt and snapshot restore reproduce the decision")
    print("=" * 78)
    shuffled = build_service(("case-review", "legacy", "case-beta", "case-alpha"))
    baseline = build_service()
    same_snapshot = baseline.snapshot() == shuffled.snapshot()
    same_attachment = baseline.attach(early).to_dict() == shuffled.attach(early).to_dict()
    print("  reordered ingest produces the same snapshot:   {}".format(same_snapshot))
    print("  reordered ingest produces the same attachment: {}".format(same_attachment))

    snapshot = service.snapshot(name="after-anchor-revoke")
    restored = stix2.ImportService.restore(snapshot)
    same_after_restore = restored.attach(early).to_dict() == service.attach(early).to_dict()
    print("  restored snapshot produces the same attachment: {}".format(
        same_after_restore,
    ))

    print()
    print("=" * 78)
    print("7. Replay of confirm -> revoke -> reassignment")
    print("=" * 78)
    replay_service = build_service()
    beta_identity_key = candidate_for_ticket(
        replay_service, "TKT-0042", "case-beta",
    ).key
    steps = replay_service.replay([
        {
            "action": "confirm",
            "reference": "TKT-0042",
            "candidate": beta_identity_key,
            "by": "analyst.li",
            "at": "2024-07-01T09:00:00Z",
            "note": "post-merge identity",
        },
        {
            "action": "revoke",
            "reference": "TKT-0042",
            "by": "reviewer.chen",
            "at": "2024-07-02T09:00:00Z",
            "note": "anchor withdrawn",
        },
    ], referrer=early)
    for step in steps:
        print("  {}. {:<8} {} -> {}".format(
            step.index, step.action, step.reference, describe(step.resolution),
        ))

    print()
    print("Replay complete.")

    return {
        "occupancy": service.occupancy(
            "identity--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ),
        "same_snapshot": same_snapshot,
        "same_attachment": same_attachment,
        "same_after_restore": same_after_restore,
        "replay": steps,
    }


if __name__ == "__main__":
    main()
