"""Tests for the offline mask consistency checker."""

import json
import os

import pytest

from mask_audit import MaskRange, SessionSchema, check_consistency
from mask_audit.models import (
    SEVERITY_ERROR,
    SEVERITY_INFO,
    SEVERITY_MANUAL,
    SEVERITY_VIOLATION,
)
from mask_audit.cli import main as cli_main
from mask_audit.tokens import leaf_tokens

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "files", "mask_audit")


def _read(name):
    path = os.path.join(FIXTURE_DIR, name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture()
def original_sql():
    return _read("original.sql")


@pytest.fixture()
def schema():
    return SessionSchema(
        database_zones={
            "zone_a": "controlled-a",
            "zone_b": "controlled-b",
            "zone_c": "controlled-c",
        },
        placeholder_zones={"<DB>": "controlled-a"},
    )


@pytest.fixture()
def permits(original_sql):
    ranges = []
    for name, zone in (
        ("zone_a", "controlled-a"),
        ("zone_b", "controlled-b"),
    ):
        start = original_sql.index(name)
        ranges.append(
            MaskRange(start, start + len(name), "database", "<DB>", zone),
        )
    return ranges


def _codes(report, severity=None):
    return [
        finding.code
        for finding in report.findings
        if severity is None or finding.severity == severity
    ]


def test_placeholder_leaves_are_merged_with_offsets():
    leaves = leaf_tokens("ALTER TABLE <DB>.t_orders ADD x INT;")
    placeholders = [token for token in leaves if token.is_placeholder]
    assert len(placeholders) == 1
    placeholder = placeholders[0]
    assert placeholder.value == "<DB>"
    assert placeholder.start == 12
    assert placeholder.end == 16
    assert "".join(token.value for token in leaves) == (
        "ALTER TABLE <DB>.t_orders ADD x INT;"
    )


def test_leaf_offsets_track_lines_and_columns():
    leaves = leaf_tokens("SELECT 1;\nALTER TABLE zone_a.t ADD c INT;")
    database = next(token for token in leaves if token.value == "zone_a")
    assert database.start == 22
    line = "SELECT 1;\nALTER TABLE zone_a.t ADD c INT;".count(
        "\n", 0, database.start,
    ) + 1
    assert line == 2


def test_compliant_masked_copy_passes(original_sql, permits, schema):
    review_sql = _read("review_masked_ok.sql")
    report = check_consistency(original_sql, review_sql, permits, schema)
    assert not report.has_errors
    assert _codes(report, SEVERITY_INFO) == ["masked_token", "masked_token"]
    assert len(report.resolutions) == 4
    review_resolutions = [
        item for item in report.resolutions if item.masked
    ]
    assert [item.zone for item in review_resolutions] == [
        "controlled-a",
        "controlled-b",
    ]
    first = report.findings[0]
    assert first.original_location.line == 2
    assert first.original_location.column == 13


def test_target_database_swap_is_caught(original_sql, permits, schema):
    review_sql = _read("review_masked_swap.sql")
    report = check_consistency(original_sql, review_sql, permits, schema)
    assert report.has_errors
    errors = _codes(report, SEVERITY_ERROR)
    assert "token_mismatch" in errors
    drift = next(
        finding
        for finding in report.findings
        if finding.code == "target_zone_drift"
    )
    assert drift.expected_zone == "controlled-b"
    assert drift.actual_zone == "controlled-c"
    assert drift.original_value == "zone_b"
    assert drift.review_value == "zone_c"


def test_mask_without_permit_is_violation(schema):
    original = "ALTER TABLE zone_a.t_orders ADD COLUMN note VARCHAR(64);"
    review = "ALTER TABLE <DB>.t_orders ADD COLUMN note VARCHAR(64);"
    report = check_consistency(original, review, [], schema)
    violations = _codes(report, SEVERITY_VIOLATION)
    assert violations == ["mask_without_permit"]
    assert report.has_errors


def test_concrete_change_outside_mask_is_error(schema):
    original = "CREATE TABLE zone_b.t_audit (id INT);"
    review = "CREATE TABLE zone_b.t_audit2 (id INT);"
    report = check_consistency(original, review, [], schema)
    assert "token_mismatch" in _codes(report, SEVERITY_ERROR)


def test_keyword_case_and_whitespace_are_ignored(schema):
    original = "CREATE TABLE zone_b.t_audit (id INT);"
    review = "create  table   zone_b.t_audit (id INT);"
    report = check_consistency(original, review, [], schema)
    assert not any(
        finding.code == "token_mismatch" for finding in report.findings
    )


def test_unknown_database_zone_goes_manual():
    original = "ALTER TABLE zone_x.t ADD c INT;"
    schema = SessionSchema(database_zones={})
    report = check_consistency(original, original, [], schema)
    manual = _codes(report, SEVERITY_MANUAL)
    assert "unknown_database_zone" in manual
    assert report.requires_manual_review


def test_unsupported_statement_goes_manual(schema):
    original = "SELECT * FROM zone_a.t_orders;"
    report = check_consistency(original, original, [], schema)
    assert "unsupported_statement" in _codes(report, SEVERITY_MANUAL)


def test_comment_only_statement_goes_manual(schema):
    original = "/* nothing but a comment */"
    report = check_consistency(original, original, [], schema)
    assert "unsupported_statement" in _codes(report, SEVERITY_MANUAL)


def test_token_structure_mismatch_is_error(schema):
    original = "CREATE TABLE zone_b.t_audit (id INT);"
    review = "CREATE TABLE zone_b.t_audit (id INT, extra INT);"
    report = check_consistency(original, review, [], schema)
    assert "token_structure_mismatch" in _codes(report, SEVERITY_ERROR)


def test_placeholder_mismatch_is_violation(original_sql, permits, schema):
    review_sql = _read("review_masked_ok.sql").replace("<DB>", "<SCHEMA>")
    report = check_consistency(original_sql, review_sql, permits, schema)
    assert "mask_placeholder_mismatch" in _codes(
        report, SEVERITY_VIOLATION,
    )


def test_comment_change_is_detected_outside_mask(schema):
    original = "-- old note\nALTER TABLE zone_a.t ADD c INT;"
    review = "-- new note\nALTER TABLE zone_a.t ADD c INT;"
    report = check_consistency(original, review, [], schema)
    assert "token_mismatch" in _codes(report, SEVERITY_ERROR)


def test_create_schema_resolves_database_and_zone():
    original = "CREATE SCHEMA IF NOT EXISTS zone_b;"
    schema = SessionSchema(database_zones={"zone_b": "controlled-b"})
    report = check_consistency(original, original, [], schema)
    resolution = report.resolutions[0]
    assert resolution.database == "zone_b"
    assert resolution.zone == "controlled-b"
    assert not report.has_errors


def test_statement_count_mismatch_goes_manual(schema):
    original = "CREATE TABLE zone_b.t (id INT);"
    review = (
        "CREATE TABLE zone_b.t (id INT); "
        "CREATE TABLE zone_b.u (id INT);"
    )
    report = check_consistency(original, review, [], schema)
    assert "statement_count_mismatch" in _codes(report, SEVERITY_MANUAL)


def test_report_serialization_is_json_ready(original_sql, permits, schema):
    review_sql = _read("review_masked_ok.sql")
    report = check_consistency(original_sql, review_sql, permits, schema)
    payload = report.as_dict()
    assert payload["ok"] is True
    json.dumps(payload)


def test_cli_exit_codes_and_fixture_files(capsys, tmp_path):
    base = FIXTURE_DIR
    permits_path = os.path.join(base, "mask_ranges.json")
    schema_path = os.path.join(base, "session_schema.json")
    original_path = os.path.join(base, "original.sql")
    ok_path = os.path.join(base, "review_masked_ok.sql")
    swap_path = os.path.join(base, "review_masked_swap.sql")

    ok_code = cli_main(
        [original_path, ok_path, "--permits", permits_path,
         "--schema", schema_path],
    )
    ok_payload = json.loads(capsys.readouterr().out)
    assert ok_code == 0
    assert ok_payload["ok"] is True

    swap_code = cli_main(
        [original_path, swap_path, "--permits", permits_path,
         "--schema", schema_path],
    )
    swap_payload = json.loads(capsys.readouterr().out)
    assert swap_code == 1
    assert swap_payload["ok"] is False
    assert "target_zone_drift" in [
        finding["code"] for finding in swap_payload["findings"]
    ]


def test_non_database_placeholder_is_not_treated_as_database(schema):
    original = "CREATE TABLE zone_b.t_audit (id INT);"
    review = "CREATE TABLE zone_b.<DB> (id INT);"
    start = original.index("t_audit")
    permits = [
        MaskRange(
            start,
            start + len("t_audit"),
            "other",
            "<DB>",
            "controlled-b",
        ),
    ]
    report = check_consistency(original, review, permits, schema)
    resolution = next(
        item for item in report.resolutions
        if item.statement_index == 0 and not item.masked
        and item.database == "zone_b"
    )
    assert resolution.zone == "controlled-b"
    assert not report.requires_manual_review


def test_permit_with_wrong_zone_reports_drift(original_sql, schema):
    review_sql = _read("review_masked_ok.sql")
    bad_permits = []
    for name in ("zone_a", "zone_b"):
        start = original_sql.index(name)
        bad_permits.append(
            MaskRange(
                start,
                start + len(name),
                "database",
                "<DB>",
                "controlled-c",
            ),
        )
    report = check_consistency(original_sql, review_sql, bad_permits, schema)
    assert "target_zone_drift" in _codes(report, SEVERITY_ERROR)


def test_comment_text_can_be_masked_under_permit(schema):
    original = "-- secret note\nALTER TABLE zone_a.t ADD c INT;"
    review = "-- <NOTE>\nALTER TABLE zone_a.t ADD c INT;"
    start = original.index("secret note")
    permits = [
        MaskRange(
            start,
            start + len("secret note"),
            "other",
            "<NOTE>",
        ),
    ]
    report = check_consistency(original, review, permits, schema)
    assert not report.has_errors
    assert "masked_token" in _codes(report, SEVERITY_INFO)


def test_comment_change_without_permit_is_error(schema):
    original = "-- secret note\nALTER TABLE zone_a.t ADD c INT;"
    review = "-- other note\nALTER TABLE zone_a.t ADD c INT;"
    report = check_consistency(original, review, [], schema)
    assert "token_mismatch" in _codes(report, SEVERITY_ERROR)


def test_unqualified_table_does_not_require_zone(schema):
    sql = "CREATE TABLE t_audit (id INT);"
    report = check_consistency(sql, sql, [], schema)
    assert not report.has_errors
    resolution = report.resolutions[0]
    assert resolution.object_name == "t_audit"
    assert resolution.zone is None
