"""Deterministic ranking, allocation and under-review tests."""

import pytest

from detect_secrets.sampling.loader import load_findings
from detect_secrets.sampling.loader import load_queue_map
from detect_secrets.sampling.models import Finding
from detect_secrets.sampling.randomness import order_findings
from detect_secrets.sampling.randomness import stable_rank
from detect_secrets.sampling.stratify import allocate_evenly
from detect_secrets.sampling.stratify import allocate_proportionally
from detect_secrets.sampling.stratify import allocate_sample
from detect_secrets.sampling.stratify import build_strata
from detect_secrets.sampling.stratify import select_sample
from detect_secrets.sampling.stratify import under_reviewed_strata


def _finding(finding_id, queue="q", detector="d"):
    return Finding(
        finding_id=finding_id,
        filename=finding_id,
        line_number=1,
        hashed_secret="h",
        detector_types=[detector],
        source_queue=queue,
    )


def test_stable_rank_is_seed_specific_and_replayable():
    finding = _finding("a.py:1:h")
    assert stable_rank(7, finding.finding_id) == stable_rank(7, finding.finding_id)
    assert stable_rank(7, finding.finding_id) != stable_rank(8, finding.finding_id)


def test_negative_seed_rejected():
    with pytest.raises(ValueError):
        stable_rank(-1, "a.py:1:h")


def test_ordering_is_total_and_without_replacement():
    findings = [_finding("id-{}".format(index)) for index in range(20)]
    first = order_findings(99, findings)
    second = order_findings(99, findings)

    assert [item.finding_id for item in first] == [
        item.finding_id for item in second
    ]
    assert len({item.finding_id for item in first}) == len(findings)


def test_allocation_is_round_robin_and_capped_by_population():
    strata = {
        ("q1", "d1"): [_finding("q1-{}".format(i)) for i in range(2)],
        ("q2", "d1"): [_finding("q2-{}".format(i)) for i in range(5)],
    }
    allocation = allocate_evenly(strata, 6)

    assert allocation[("q1", "d1")] == 2
    assert allocation[("q2", "d1")] == 4
    assert sum(allocation.values()) == 6


def test_proportional_allocation_favours_large_strata():
    strata = {
        ("large", "d1"): [_finding("l-{}".format(i), queue="large") for i in range(8)],
        ("small", "d1"): [_finding("s-{}".format(i), queue="small") for i in range(2)],
    }
    allocation = allocate_proportionally(strata, 5)

    assert sum(allocation.values()) == 5
    assert allocation[("large", "d1")] >= allocation[("small", "d1")]
    assert allocation[("small", "d1")] <= 1


def test_proportional_allocation_can_give_small_stratum_zero_slots():
    strata = {
        ("large", "d1"): [_finding("l-{}".format(i), queue="large") for i in range(98)],
        ("small", "d1"): [_finding("s-{}".format(i), queue="small") for i in range(2)],
    }
    allocation = allocate_proportionally(strata, 10)

    assert allocation[("small", "d1")] == 0
    flagged = under_reviewed_strata(strata, allocation, threshold=0.1)
    assert ("small", "d1") in flagged


def test_allocation_never_exceeds_budget_or_population():
    strata = {("q", "d"): [_finding("{}".format(i)) for i in range(3)]}
    assert allocate_evenly(strata, 10)[("q", "d")] == 3
    assert allocate_evenly(strata, 0)[("q", "d")] == 0


def test_queue_caps_starve_a_queue_without_hiding_it():
    strata = {
        ("payments", "d1"): [
            _finding("p-{}".format(i), queue="payments") for i in range(5)
        ],
        ("legacy", "d1"): [
            _finding("g-{}".format(i), queue="legacy") for i in range(2)
        ],
    }
    allocation = allocate_sample(
        strata,
        sample_budget=7,
        mode="even",
        queue_caps={"legacy": 0},
    )

    assert allocation[("legacy", "d1")] == 0
    assert allocation[("payments", "d1")] == 5
    flagged = under_reviewed_strata(strata, allocation, threshold=0.1)
    assert ("legacy", "d1") in flagged


def test_unknown_allocation_mode_rejected():
    with pytest.raises(ValueError):
        allocate_sample({}, 5, mode="mystery")


def test_plugin_multiplicity_does_not_change_weight(baseline_file, queue_map_file):
    findings = load_findings(str(baseline_file), load_queue_map(str(queue_map_file)))
    strata = build_strata(findings)
    allocation = allocate_evenly(strata, 7)
    selected = select_sample(strata, allocation, seed=123)

    all_selected = [
        finding.finding_id
        for members in selected.values()
        for finding in members
    ]
    # The merged finding is selected at most once even though two plugins hit it.
    assert all_selected.count("src/payments/api.py:10:hash-aaa") <= 1


def test_under_review_threshold_validation():
    with pytest.raises(ValueError):
        under_reviewed_strata({}, {}, threshold=1.5)
