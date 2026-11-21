# SPDX-License-Identifier: Apache-2.0
"""Pytest coverage for the local B102 cutover validation harness.

The tests run the real harness against the fixed, checked-in corpus and
assert the three recorded facts (entered / completed / hit) plus the
coverage-gap responsibilities. They never touch the network.
"""
import importlib.util
import sys
from pathlib import Path

CUTOVER_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CUTOVER_ROOT.parent


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "run_cutover_check", CUTOVER_ROOT / "run_cutover_check.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_cutover_check"] = module
    spec.loader.exec_module(module)
    return module


harness = _load_harness()


def _row(matrix, rule_id, suffix):
    for row in matrix:
        if row["rule_id"] == rule_id and row["input_file"].endswith(suffix):
            return row
    raise AssertionError("missing row %s %s" % (rule_id, suffix))


def test_corpus_is_fixed_and_local():
    files = harness._fixed_corpus_files()
    assert files
    assert all(path.startswith("cutover/corpus") for path in files)
    corpus_root = CUTOVER_ROOT / "corpus"
    assert all((corpus_root / path.split("cutover/corpus/", 1)[1]).exists()
               for path in files)


def test_validation_records_three_facts_for_every_rule_and_file():
    files, observations, _, _ = harness.run_validation()
    for rule_key, by_file in observations.items():
        assert set(by_file) == set(files), rule_key
        for observation in by_file.values():
            assert isinstance(observation.entered, bool)
            assert isinstance(observation.completed, bool)
            assert isinstance(observation.hit, bool)
            assert observation.completed is True


def test_direct_exec_is_covered_by_both_rules():
    files, observations, _, _ = harness.run_validation()
    legacy = observations[(harness.LEGACY_RULE, "exec_used")]
    replacement = observations[("X901", "guard_exec_used")]
    target = "cutover/corpus/app/main_direct_exec.py"
    assert legacy[target].entered and legacy[target].hit
    assert replacement[target].entered and replacement[target].hit


def test_nested_exec_is_a_syntax_coverage_gap():
    files, observations, _, _ = harness.run_validation()
    legacy = observations[(harness.LEGACY_RULE, "exec_used")]
    replacement = observations[("X901", "guard_exec_used")]
    target = "cutover/corpus/app/nested_exec.py"
    assert legacy[target].hit is True
    assert replacement[target].entered is True
    assert replacement[target].hit is False
    rows, gaps = harness.build_coverage_analysis(files, observations)
    classifications = {row["input_file"]: row["gap_classification"] for row in rows}
    assert classifications[target] == "syntax-coverage-gap"
    assert any(
        gap["input_file"] == target and gap["blocks_cutover"] for gap in gaps
    )


def test_legacy_root_is_a_directory_coverage_gap():
    files, observations, _, _ = harness.run_validation()
    rows, gaps = harness.build_coverage_analysis(files, observations)
    classifications = {row["input_file"]: row["gap_classification"] for row in rows}
    assert (
        classifications["cutover/corpus/legacy/legacy_direct_exec.py"]
        == "directory-coverage-gap"
    )
    assert (
        classifications["cutover/corpus/legacy/legacy_nested_exec.py"]
        == "directory-coverage-gap"
    )
    assert len(gaps) == 3


def test_new_eval_alert_does_not_offset_exec_gaps():
    files, observations, legacy_run, replacement_run = harness.run_validation()
    rows, gaps = harness.build_coverage_analysis(files, observations)
    record = harness._build_record(
        files, observations, legacy_run, replacement_run, rows, gaps
    )
    assert record["cutover_decision"]["approved"] is False
    assert record["cutover_decision"]["blocking_gap_count"] == 3
    eval_findings = record["new_only_findings"]
    assert len(eval_findings) == 1
    assert eval_findings[0]["input_file"].endswith("eval_and_exec.py")
    assert any(
        gap["input_file"] == "cutover/corpus/app/nested_exec.py" for gap in gaps
    )


def test_broken_syntax_file_is_marked_skipped_not_covered_silently():
    files, observations, _, _ = harness.run_validation()
    target = "cutover/corpus/legacy/legacy_broken_syntax.py"
    for rule_key, by_file in observations.items():
        assert by_file[target].parse_status == "skipped"
        assert "skipped" in by_file[target].note
