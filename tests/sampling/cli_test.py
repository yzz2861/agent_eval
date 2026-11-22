"""CLI smoke tests for plan rendering and exception verification."""

import json

from detect_secrets.sampling.cli import main
from detect_secrets.sampling.cli import render_text_report
from detect_secrets.sampling.planner import build_plan


REVIEWED_IDS = {
    "src/payments/api.py:10:hash-aaa",
    "src/payments/api.py:20:hash-bbb",
    "src/payments/api.py:30:hash-ccc",
    "src/payments/worker.py:5:hash-ddd",
}


def test_plan_text_report_flags_under_reviewed_queue(
    baseline_file,
    queue_map_file,
    reviewed_file,
    tmp_path,
    capsys,
):
    caps_path = tmp_path / "caps.json"
    caps_path.write_text(json.dumps({"legacy": 0}))

    exit_code = main([
        "plan",
        str(baseline_file),
        "--seed", "42",
        "--budget", "5",
        "--queue-map", str(queue_map_file),
        "--queue-caps", str(caps_path),
        "--reviewed", str(reviewed_file),
        "--under-review-threshold", "0.5",
    ])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "aggregate:" in output
    assert "UNDER-REVIEWED" in output
    assert "legacy" in output


def test_plan_json_output_is_written_to_file(
    baseline_file,
    queue_map_file,
    tmp_path,
):
    output_path = tmp_path / "plan.json"
    exit_code = main([
        "plan",
        str(baseline_file),
        "--seed", "42",
        "--budget", "5",
        "--queue-map", str(queue_map_file),
        "--allocation-mode", "proportional",
        "--output", str(output_path),
    ])

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["seed"] == 42
    assert payload["allocation_mode"] == "proportional"
    assert "selection" in payload
    assert "report" in payload


def test_verify_returns_nonzero_for_missed_exception(
    baseline_file,
    queue_map_file,
    reviewed_file,
    capsys,
):
    plan = build_plan(
        str(baseline_file),
        seed=42,
        sample_budget=7,
        queue_map_path=str(queue_map_file),
        reviewed_path=str(reviewed_file),
    )
    missed_id = next(
        finding_id
        for finding_id in sorted(plan.selected_ids)
        if finding_id not in REVIEWED_IDS
    )

    exit_code = main([
        "verify",
        str(baseline_file),
        "--finding-id", missed_id,
        "--seed", "42",
        "--budget", "7",
        "--queue-map", str(queue_map_file),
        "--reviewed", str(reviewed_file),
    ])

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["missed_by_manual_review"] is True


def test_verify_returns_zero_for_reviewed_exception(
    baseline_file,
    queue_map_file,
    reviewed_file,
    capsys,
):
    exit_code = main([
        "verify",
        str(baseline_file),
        "--finding-id", "src/payments/api.py:10:hash-aaa",
        "--seed", "42",
        "--budget", "7",
        "--queue-map", str(queue_map_file),
        "--reviewed", str(reviewed_file),
    ])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["reviewed"] is True


def test_render_text_report_contains_all_strata():
    plan_dict = {
        "seed": 1,
        "sample_budget": 2,
        "allocation_mode": "even",
        "under_review_threshold": 0.1,
        "report": {
            "aggregate": {
                "total_findings": 3,
                "total_sampled": 2,
                "aggregate_sample_fraction": 0.666667,
                "total_reviewed": 1,
                "aggregate_human_coverage": 0.333333,
                "total_unreviewed": 2,
                "strata_under_reviewed": 1,
            },
            "strata": [
                {
                    "source_queue": "legacy",
                    "primary_detector": "JSON Web Token",
                    "population_size": 1,
                    "sample_size": 0,
                    "sample_fraction": 0.0,
                    "reviewed_findings": 0,
                    "human_coverage": 0.0,
                    "unreviewed_findings": 1,
                    "review_rate_in_sample_95ci": [0.0, 0.0],
                    "under_reviewed": True,
                },
            ],
        },
    }
    rendered = render_text_report(plan_dict)
    assert "legacy" in rendered
    assert "UNDER-REVIEWED" in rendered
