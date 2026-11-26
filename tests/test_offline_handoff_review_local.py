from __future__ import annotations

import json
import unittest

from in_toto.handoff import minimal_supplement, review_handoff

LAYOUT = {
    "id": "layout",
    "revision": 1,
    "effective_at": 0,
    "expires": 1000,
    "received_at": 1,
    "steps": [{"name": "build", "threshold": 1}],
}


def review_case(**overrides):
    case = {
        "business_as_of": 100,
        "receipt_as_of": 200,
        "layouts": [dict(LAYOUT)],
        "links": [
            {
                "id": "link-1",
                "step": "build",
                "keyid": "key-1",
                "signed_at": 90,
                "received_at": 100,
                "signature_valid": True,
            }
        ],
    }
    case.update(overrides)
    return review_handoff(case)


def test_mechanical_clock_offset_uses_signed_boundary_inclusively():
    link = {
        "id": "boundary",
        "step": "build",
        "source": "builder-1",
        "keyid": "key-1",
        "signed_at": 105,
        "received_at": 120,
        "signature_valid": True,
        # Archive rewriting must not become the business time.
        "archive_timestamp": 9_999_999,
        "mtime": 9_999_999,
    }

    accepted = review_case(
        links=[link],
        clocks=[{"source": "builder-1", "offset": 5}],
        business_as_of=100,
    )
    assert accepted.business.accepted is True
    assert accepted.business.selected_ids == ["boundary"]

    before_boundary = review_case(
        links=[link],
        clocks=[{"source": "builder-1", "offset": 5}],
        business_as_of=99,
    )
    assert before_boundary.business.accepted is False
    assert before_boundary.business.outside_ids == ["boundary"]


def test_clock_uncertainty_across_cutoff_is_explicit_and_policy_can_include():
    link = {
        "id": "uncertain-clock",
        "step": "build",
        "signed_at": 105,
        "received_at": 120,
        "signature_valid": True,
        "clock_offset": 5,
        "offset_uncertainty": 3,
    }

    result = review_case(links=[link], business_as_of=100)
    assert result.business.decision == "inconclusive"
    assert result.business.unresolved_ids == ["uncertain-clock"]

    included = review_case(
        links=[link],
        business_as_of=100,
        boundary_policy="include",
    )
    assert included.business.accepted is True


def test_backfill_enters_business_slice_but_not_historical_receipt_slice():
    layout = dict(LAYOUT)
    layout["steps"] = [{"name": "build"}, {"name": "test"}]
    links = [
        {
            "id": "build",
            "step": "build",
            "keyid": "k1",
            "signed_at": 90,
            "received_at": 100,
            "signature_valid": True,
        },
        {
            "id": "backfilled-test",
            "step": "test",
            "keyid": "k2",
            "signed_at": 95,
            "received_at": 210,
            "signature_valid": True,
        },
    ]

    result = review_case(
        layouts=[layout],
        links=links,
        business_as_of=100,
        receipt_as_of=200,
    )

    assert result.business.accepted is True
    assert result.business.selected_ids == ["backfilled-test", "build"]
    assert result.receipt.accepted is False
    assert result.receipt.selected_ids == ["build"]
    assert result.receipt.outside_ids == ["backfilled-test"]
    assert result.receipt.minimal_supplement == ["backfilled-test"]
    assert result.paired.accepted is False


def test_minimal_supplement_for_late_receipt_is_single_early_link():
    layout = dict(LAYOUT)
    layout["steps"] = [{"name": "build"}, {"name": "test"}]
    links = [
        {"id": "build", "step": "build", "signed_at": 90, "received_at": 91},
        {
            "id": "late-test",
            "step": "test",
            "signed_at": 95,
            "received_at": 210,
        },
    ]
    supplements = [
        {
            "id": "zz-irrelevant",
            "step": "other",
            "signed_at": 96,
            "received_at": 100,
        },
        {
            "id": "early-test",
            "step": "test",
            "signed_at": 96,
            "received_at": 150,
            "signature_valid": True,
        },
    ]

    result = review_handoff(
        business_as_of=100,
        receipt_as_of=200,
        layouts=[layout],
        links=links,
        supplements=supplements,
    )

    assert result.receipt.accepted is False
    assert result.receipt.minimal_supplement == ["early-test"]
    assert result.receipt.minimal_supplement.to_accepted is True
    assert minimal_supplement(
        business_as_of=100,
        receipt_as_of=200,
        axis="receipt",
        layouts=[layout],
        links=links,
        supplements=list(reversed(supplements)),
    ) == ["early-test"]


def test_revision_records_select_highest_visible_revision_without_order_drift():
    layouts = [
        {
            "id": "layout",
            "revision": 1,
            "effective_at": 0,
            "received_at": 5,
            "steps": [{"name": "build"}, {"name": "audit"}],
        },
        {
            "id": "layout",
            "revision": 2,
            "effective_at": 50,
            "received_at": 30,
            "steps": [{"name": "build"}],
        },
    ]
    links = [
        {
            "id": "build-link",
            "revision": 1,
            "step": "build",
            "signed_at": 10,
            "received_at": 11,
            "signature_valid": False,
        },
        {
            "id": "build-link",
            "revision": 2,
            "step": "build",
            "signed_at": 60,
            "received_at": 12,
            "signature_valid": True,
        },
    ]

    for ordered_layouts in (layouts, list(reversed(layouts))):
        result = review_handoff(
            business_as_of=100,
            receipt_as_of=20,
            layouts=ordered_layouts,
            links=list(reversed(links)),
        )
        assert result.business.selected_layout_revision == 2
        assert result.business.accepted is True
        assert result.receipt.selected_layout_revision == 1
        assert result.receipt.accepted is False
        assert [
            r.id for r in result.receipt.requirements if r.status == "rejected"
        ] == ["audit"]


def test_revocation_is_selected_on_each_time_axis():
    links = [
        {
            "id": "build",
            "step": "build",
            "keyid": "k1",
            "signed_at": 10,
            "received_at": 20,
            "signature_valid": True,
        }
    ]
    revocations = [
        {
            "id": "revoke-k1",
            "target": "k1",
            "business_time": 50,
            "received_at": 150,
        }
    ]

    result = review_case(
        links=links,
        revocations=revocations,
        business_as_of=100,
        receipt_as_of=100,
    )
    assert result.business.accepted is False
    assert "revoked" in result.business.assessments[0].reasons
    assert result.receipt.accepted is True
    assert result.receipt.revocation_ids == []


def test_revocation_revision_can_reinstate_key():
    links = [
        {
            "id": "build",
            "step": "build",
            "keyid": "k1",
            "signed_at": 10,
            "received_at": 20,
        }
    ]
    revocations = [
        {
            "id": "revoke",
            "revision": 1,
            "target": "k1",
            "status": "revoked",
            "business_time": 20,
            "received_at": 21,
        },
        {
            "id": "revoke",
            "revision": 2,
            "target": "k1",
            "status": "reinstated",
            "business_time": 30,
            "received_at": 31,
        },
    ]

    result = review_case(
        links=links,
        revocations=list(reversed(revocations)),
        business_as_of=100,
        receipt_as_of=100,
    )
    assert result.business.revocation_ids == []
    assert result.business.accepted is True


def test_historical_layout_reference_is_pinned():
    layouts = [
        {
            "id": "layout",
            "revision": 1,
            "effective_at": 0,
            "expires": 1000,
            "received_at": 1,
            "steps": [{"name": "build"}, {"name": "legacy-audit"}],
        },
        {
            "id": "layout",
            "revision": 2,
            "effective_at": 50,
            "expires": 1000,
            "received_at": 2,
            "steps": [{"name": "build"}],
        },
    ]
    links = [
        {
            "id": "old-build",
            "step": "build",
            "layout_ref": {"id": "layout", "revision": 1},
            "signed_at": 10,
            "received_at": 11,
        },
        {
            "id": "old-audit",
            "step": "legacy-audit",
            "layout_ref": {"id": "layout", "revision": 1},
            "signed_at": 12,
            "received_at": 13,
        },
    ]

    result = review_case(layouts=layouts, links=links)
    business = result.business
    requirement_keys = {
        (r.layout_revision, r.id): r.status for r in business.requirements
    }
    assert requirement_keys[(1, "build")] == "accepted"
    assert requirement_keys[(1, "legacy-audit")] == "accepted"
    assert (2, "build") not in requirement_keys
    assert business.accepted is True


def test_minimal_threshold_supplement_is_order_independent_and_lexicographic():
    layout = dict(LAYOUT)
    layout["steps"] = [{"name": "build", "threshold": 2}]
    current = [
        {
            "id": "k1-link",
            "step": "build",
            "keyid": "k1",
            "signed_at": 10,
            "received_at": 11,
        }
    ]
    candidates = [
        {
            "id": "zz-second",
            "step": "build",
            "keyid": "k9",
            "signed_at": 12,
            "received_at": 13,
        },
        {
            "id": "aa-second",
            "step": "build",
            "keyid": "k2",
            "signed_at": 12,
            "received_at": 13,
        },
    ]

    result = review_handoff(
        business_as_of=100,
        receipt_as_of=200,
        layouts=[layout],
        links=current,
        supplements=candidates,
    )
    assert result.business.requirements[0].status == "rejected"
    assert result.business.minimal_supplement == ["aa-second"]

    shuffled = review_handoff(
        business_as_of=100,
        receipt_as_of=200,
        layouts=[layout],
        links=list(reversed(current)),
        supplements=list(reversed(candidates)),
    )
    assert shuffled.business.minimal_supplement == ["aa-second"]


def test_minimal_supplement_can_find_revocation_that_flips_acceptance():
    revocation = {
        "id": "new-revocation",
        "target": "key-1",
        "business_time": 50,
        "received_at": 60,
    }
    result = review_case(supplements=[revocation])
    assert result.accepted is True
    assert result.minimal_supplement == ["new-revocation"]
    assert result.minimal_supplement.to_accepted is False


def test_shuffled_inputs_do_not_drift_result():
    links = [
        {
            "id": f"link-{index}",
            "step": "build",
            "keyid": f"key-{index}",
            "signed_at": 80 + index,
            "received_at": 90 + index,
            "signature_valid": True,
        }
        for index in range(4)
    ]
    layout = dict(LAYOUT)
    layout["steps"] = [{"name": "build", "threshold": 3}]
    supplements = [
        {
            "id": "extra",
            "step": "build",
            "keyid": "key-9",
            "signed_at": 88,
            "received_at": 95,
            "signature_valid": True,
        }
    ]

    def fingerprint(order: int):
        if order:
            ordered_links = list(reversed(links))
            ordered_supplements = list(reversed(supplements))
        else:
            ordered_links = links
            ordered_supplements = supplements
        report = review_handoff(
            business_as_of=100,
            receipt_as_of=200,
            layouts=[layout],
            links=ordered_links,
            clocks=[{"source": "unused", "offset": order}],
            revocations=[
                {
                    "id": "r",
                    "target": "nobody",
                    "business_time": 1,
                    "received_at": 2,
                }
            ],
            supplements=ordered_supplements,
        )
        return json.dumps(
            {
                "decision": report.decision,
                "business": {
                    "decision": report.business.decision,
                    "selected_ids": report.business.selected_ids,
                    "requirements": [
                        (r.id, r.status, r.valid_ids)
                        for r in report.business.requirements
                    ],
                    "minimal": list(report.business.minimal_supplement),
                },
                "receipt": {
                    "decision": report.receipt.decision,
                    "selected_ids": report.receipt.selected_ids,
                    "minimal": list(report.receipt.minimal_supplement),
                },
            },
            sort_keys=True,
        )

    first = fingerprint(0)
    for order in range(1, 6):
        assert fingerprint(order) == first


def test_freeze_receipt_time_ignores_archive_timestamp_rewrite():
    from in_toto.handoff import freeze_receipt_time

    record = {
        "id": "x",
        "archive_timestamp": 1,
        "archived_at": 2,
        "received_at": 30,
    }
    assert freeze_receipt_time(record) == 30
    assert freeze_receipt_time({"id": "y", "archive_timestamp": 1}) is None


def test_separate_trusted_receipt_log_overrides_archive_fields():
    result = review_handoff(
        business_as_of=100,
        receipt_as_of=100,
        layouts=[{"id": "L", "steps": [{"name": "build"}]}],
        links=[
            {
                "id": "link-a",
                "step": "build",
                "signed_at": 10,
                "archive_timestamp": 1,
                "archived_at": 2,
            }
        ],
        receipts=[{"link_id": "link-a", "trusted_received_at": 50}],
    )
    assert result.receipt.accepted is True
    assert result.receipt.selected_ids == ["link-a"]


class OfflineHandoffBehaviorTests(unittest.TestCase):
    def test_mechanical_clock_offset_boundary(self):
        test_mechanical_clock_offset_uses_signed_boundary_inclusively()

    def test_clock_uncertainty_boundary(self):
        test_clock_uncertainty_across_cutoff_is_explicit_and_policy_can_include()

    def test_backfill_two_slices(self):
        test_backfill_enters_business_slice_but_not_historical_receipt_slice()

    def test_minimal_late_receipt(self):
        test_minimal_supplement_for_late_receipt_is_single_early_link()

    def test_revision_selection(self):
        test_revision_records_select_highest_visible_revision_without_order_drift()

    def test_revocation_time_selection(self):
        test_revocation_is_selected_on_each_time_axis()

    def test_revocation_revision_reinstate(self):
        test_revocation_revision_can_reinstate_key()

    def test_historical_layout_reference(self):
        test_historical_layout_reference_is_pinned()

    def test_minimal_threshold_order(self):
        test_minimal_threshold_supplement_is_order_independent_and_lexicographic()

    def test_minimal_revocation_flip(self):
        test_minimal_supplement_can_find_revocation_that_flips_acceptance()

    def test_shuffled_inputs(self):
        test_shuffled_inputs_do_not_drift_result()

    def test_receipt_freeze(self):
        test_freeze_receipt_time_ignores_archive_timestamp_rewrite()

    def test_external_receipt_log(self):
        test_separate_trusted_receipt_log_overrides_archive_fields()
