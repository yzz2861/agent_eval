"""End-to-end plan, replay and exception-verification tests."""

import json

from detect_secrets.sampling.planner import build_plan
from detect_secrets.sampling.planner import verify_exception


REVIEWED_IDS = {
    "src/payments/api.py:10:hash-aaa",
    "src/payments/api.py:20:hash-bbb",
    "src/payments/api.py:30:hash-ccc",
    "src/payments/worker.py:5:hash-ddd",
}


def test_plan_is_byte_stable_across_runs(baseline_file, queue_map_file, reviewed_file):
    kwargs = dict(
        seed=20261123,
        sample_budget=5,
        queue_map_path=str(queue_map_file),
        reviewed_path=str(reviewed_file),
        allocation_mode="proportional",
        queue_caps={"legacy": 0},
    )
    first = build_plan(str(baseline_file), **kwargs).to_dict()
    second = build_plan(str(baseline_file), **kwargs).to_dict()

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_different_seeds_can_change_selection(baseline_file, queue_map_file):
    first = build_plan(str(baseline_file), seed=1, sample_budget=3,
                       queue_map_path=str(queue_map_file))
    second = build_plan(str(baseline_file), seed=2, sample_budget=3,
                        queue_map_path=str(queue_map_file))

    assert first.selected_ids != second.selected_ids


def test_small_queue_shows_under_reviewed_despite_healthy_aggregate(
    baseline_file,
    queue_map_file,
    reviewed_file,
):
    plan = build_plan(
        str(baseline_file),
        seed=42,
        sample_budget=5,
        queue_map_path=str(queue_map_file),
        reviewed_path=str(reviewed_file),
        under_review_threshold=0.5,
        queue_caps={"legacy": 0},
    ).to_dict()

    rows = plan["report"]["strata"]
    legacy_rows = [row for row in rows if row["source_queue"] == "legacy"]
    payments_rows = [row for row in rows if row["source_queue"] == "payments"]

    assert legacy_rows
    assert all(row["under_reviewed"] for row in legacy_rows)
    assert all(row["sample_size"] == 0 for row in legacy_rows)
    # The aggregate number must not be allowed to hide the starved queue.
    assert plan["report"]["aggregate"]["strata_under_reviewed"] >= 1
    assert any(not row["under_reviewed"] for row in payments_rows)


def test_proportional_mode_records_mode_and_caps_in_plan(
    baseline_file,
    queue_map_file,
):
    plan = build_plan(
        str(baseline_file),
        seed=7,
        sample_budget=4,
        queue_map_path=str(queue_map_file),
        allocation_mode="proportional",
        queue_caps={"legacy": 1},
    ).to_dict()

    assert plan["allocation_mode"] == "proportional"
    assert plan["queue_caps"] == {"legacy": 1}


def test_review_annotations_never_manufactured_by_sampler(
    baseline_file,
    queue_map_file,
):
    plan = build_plan(
        str(baseline_file),
        seed=42,
        sample_budget=7,
        queue_map_path=str(queue_map_file),
    ).to_dict()
    assert plan["report"]["aggregate"]["total_reviewed"] == 0


def test_verify_exception_detects_missed_review(
    baseline_file,
    queue_map_file,
    reviewed_file,
):
    plan = build_plan(
        str(baseline_file),
        seed=42,
        sample_budget=7,
        queue_map_path=str(queue_map_file),
        reviewed_path=str(reviewed_file),
    )
    sampled_not_reviewed = next(
        finding_id
        for finding_id in sorted(plan.selected_ids)
        if finding_id not in REVIEWED_IDS
    )
    result = verify_exception(plan, sampled_not_reviewed, str(reviewed_file))

    assert result["known"] is True
    assert result["in_sample"] is True
    assert result["reviewed"] is False
    assert result["missed_by_manual_review"] is True


def test_verify_exception_for_unknown_id(baseline_file, queue_map_file):
    plan = build_plan(
        str(baseline_file),
        seed=42,
        sample_budget=3,
        queue_map_path=str(queue_map_file),
    )
    result = verify_exception(plan, "missing.py:9:hash-zzz")

    assert result["known"] is False
    assert result["missed_by_manual_review"] is True


def test_verify_exception_reports_multi_plugin_hit_once(
    baseline_file,
    queue_map_file,
    reviewed_file,
):
    plan = build_plan(
        str(baseline_file),
        seed=42,
        sample_budget=7,
        queue_map_path=str(queue_map_file),
        reviewed_path=str(reviewed_file),
    )
    result = verify_exception(
        plan,
        "src/payments/api.py:10:hash-aaa",
        str(reviewed_file),
    )
    assert result["plugin_hit_count"] == 2
    assert result["reviewed"] is True
    assert result["missed_by_manual_review"] is False
