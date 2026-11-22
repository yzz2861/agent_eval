"""Tests for the offline, bounded migration review."""

import json

import pytest

from sqlparse import review


DECLARATIONS = (
    "CREATE VIEW temp_audit AS\n"
    "    SELECT id, actor FROM audit_log WHERE actor IS NOT NULL;\n"
    "CREATE VIEW forensic_snapshot AS\n"
    "    SELECT * FROM temp_audit;\n"
)


def test_rename_keeps_identity_and_trace():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "ALTER VIEW temp_audit RENAME TO archive_audit;",
    )

    assert result.safe
    assert result.status == "safe"
    assert result.name_reuse == ()
    assert result.incomplete_dependencies == ()

    report = result.evidence[0]
    assert report.obtainable
    assert report.reason == "renamed"
    assert report.renames == (("temp_audit", "archive_audit"),)
    assert report.paths[0].path == (
        "forensic_snapshot",
        "archive_audit",
        "audit_log",
    )
    assert [finding.kind for finding in result.renames] == [
        review.FindingKind.RENAMED
    ]


def test_drop_of_only_dependency_chain_blocks_evidence():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "DROP VIEW temp_audit;",
    )

    assert not result.safe
    assert result.status == "unsafe"
    report = result.evidence[0]
    assert not report.obtainable
    assert report.reason == "incomplete_dependency"
    assert report.missing_anchors == ("audit_log",)
    assert report.broken_at == ("temp_audit",)
    assert result.incomplete_dependencies
    assert result.name_reuse == ()
    assert any(
        finding.kind is review.FindingKind.INCOMPLETE_DEPENDENCY
        and finding.severity == "error"
        for finding in result.findings
    )


def test_name_reuse_is_kept_separate_from_incomplete_dependency():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "DROP VIEW temp_audit; CREATE VIEW temp_audit AS SELECT * FROM other_log;",
    )

    assert not result.safe
    assert result.evidence[0].obtainable is False
    assert result.evidence[0].reason == "name_reuse"
    assert result.name_reuse
    assert result.incomplete_dependencies == ()
    assert all(
        finding.category is review.FindingCategory.NAME_REUSE
        for finding in result.name_reuse
    )


def test_alternative_dependency_path_keeps_evidence_obtainable():
    declarations = (
        "CREATE VIEW a AS SELECT * FROM evidence_log;\n"
        "CREATE VIEW b AS SELECT * FROM evidence_log;\n"
        "CREATE VIEW snap AS SELECT * FROM a UNION ALL SELECT * FROM b;\n"
    )

    result = review.review(declarations, ["snap"], "DROP VIEW a;")

    assert result.safe
    report = result.evidence[0]
    assert report.obtainable
    assert report.reason == "ok"
    assert report.paths[0].count == 1
    assert result.incomplete_dependencies
    assert all(
        finding.severity == "warning"
        for finding in result.incomplete_dependencies
    )


def test_dropping_every_chain_blocks_evidence():
    declarations = (
        "CREATE VIEW a AS SELECT * FROM evidence_log;\n"
        "CREATE VIEW b AS SELECT * FROM evidence_log;\n"
        "CREATE VIEW snap AS SELECT * FROM a UNION ALL SELECT * FROM b;\n"
    )

    result = review.review(
        declarations, ["snap"], "DROP VIEW a; DROP VIEW b;"
    )

    assert not result.safe
    assert result.evidence[0].reason == "incomplete_dependency"


def test_frozen_object_name_reuse_is_reported_as_name_reuse():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "DROP VIEW forensic_snapshot; "
        "CREATE VIEW forensic_snapshot AS SELECT * FROM temp_audit;",
    )

    assert not result.safe
    assert result.evidence[0].reason == "name_reuse"
    assert result.name_reuse
    assert result.incomplete_dependencies == ()


def test_dropped_frozen_object_has_no_evidence():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "DROP VIEW forensic_snapshot;",
    )

    assert not result.safe
    assert result.evidence[0].reason == "frozen_object_missing"
    assert any(
        finding.kind is review.FindingKind.FROZEN_OBJECT_MISSING
        for finding in result.findings
    )


def test_frozen_object_rename_is_traceable():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "ALTER VIEW forensic_snapshot RENAME TO forensic_snapshot_v2;",
    )

    assert result.safe
    report = result.evidence[0]
    assert report.obtainable
    assert report.reason == "renamed"
    assert report.resolved_name == "forensic_snapshot_v2"


def test_replace_that_removes_a_dependency_blocks_evidence():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "CREATE OR REPLACE VIEW temp_audit AS SELECT * FROM other_log;",
    )

    assert not result.safe
    assert result.evidence[0].reason == "incomplete_dependency"
    assert result.name_reuse == ()


def test_create_or_replace_keeps_object_identity():
    result = review.review(
        "CREATE VIEW v AS SELECT * FROM t;",
        ["v"],
        "CREATE OR REPLACE VIEW v AS SELECT * FROM t;",
    )

    assert result.safe
    assert result.name_reuse == ()
    view = next(relation for relation in result.relations if relation.name == "v")
    assert view.redefinition_count == 1


def test_dependency_extraction_handles_ctes_and_subqueries():
    declarations = (
        "CREATE VIEW v AS\n"
        "    WITH c AS (SELECT * FROM base)\n"
        "    SELECT * FROM c JOIN joined_table ON 1 = 1;\n"
        "CREATE TABLE snap AS\n"
        "    SELECT * FROM (SELECT * FROM v) nested;\n"
    )

    result = review.review(declarations, ["snap"], "")

    by_name = {relation.name: relation for relation in result.relations}
    assert by_name["v"].dependencies == ("base", "joined_table")
    assert by_name["snap"].dependencies == ("v",)
    assert result.safe


def test_schema_qualified_and_quoted_names_preserve_lineage():
    declarations = (
        "CREATE VIEW \"S\".\"Temp\" AS SELECT * FROM \"S\".\"Audit\";\n"
        "CREATE VIEW snap AS SELECT * FROM s.temp;\n"
    )

    result = review.review(
        declarations,
        ["snap"],
        "ALTER VIEW S.Temp RENAME TO S.Archive;",
    )

    assert result.safe
    report = result.evidence[0]
    assert report.reason == "renamed"
    assert report.paths[0].path == ("snap", "s.archive", "s.audit")


def test_unsupported_ddl_is_rejected_and_not_applied():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "DROP INDEX idx;",
    )

    assert not result.safe
    assert any(
        finding.kind is review.FindingKind.UNSUPPORTED_STATEMENT
        for finding in result.findings
    )
    live_names = {
        relation.name for relation in result.relations if relation.alive
    }
    assert {"temp_audit", "forensic_snapshot"} <= live_names
    assert result.evidence[0].obtainable


def test_drop_if_exists_unknown_name_is_not_an_error():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "DROP VIEW IF EXISTS does_not_exist;",
    )

    assert result.safe
    assert result.findings == ()


def test_drop_accepts_multiple_names():
    declarations = (
        "CREATE VIEW a AS SELECT * FROM evidence;\n"
        "CREATE VIEW b AS SELECT * FROM evidence;\n"
        "CREATE VIEW snap AS SELECT * FROM a JOIN b ON 1 = 1;\n"
    )

    result = review.review(declarations, ["snap"], "DROP VIEW a, b;")

    assert not result.safe
    assert result.evidence[0].reason == "incomplete_dependency"


@pytest.mark.parametrize(
    "freeze",
    [
        ["snap"],
        "snap",
        {"snap": None},
        [{"name": "snap"}],
        [review.FrozenObject("snap")],
        [("snap", ())],
    ],
)
def test_freeze_list_shapes(freeze):
    parsed = review.parse_freeze_list(freeze)
    assert [item.name for item in parsed] == ["snap"]


def test_explicit_anchor_requirement():
    result = review.review(
        DECLARATIONS,
        {"forensic_snapshot": {"requires": ["audit_log"]}},
        "DROP TABLE audit_log;",
    )

    assert not result.safe
    report = result.evidence[0]
    assert report.reason == "incomplete_dependency"
    assert report.missing_anchors == ("audit_log",)


def test_rename_onto_a_live_name_is_a_conflict():
    declarations = (
        "CREATE VIEW a AS SELECT * FROM t;\n"
        "CREATE VIEW b AS SELECT * FROM t;\n"
    )

    result = review.review(
        declarations,
        [],
        "ALTER VIEW a RENAME TO b;",
    )

    assert not result.safe
    assert any(
        finding.kind is review.FindingKind.NAME_CONFLICT
        for finding in result.findings
    )


def test_duplicate_create_without_replace_is_a_conflict():
    result = review.review(
        "CREATE VIEW v AS SELECT * FROM t;\n"
        "CREATE VIEW v AS SELECT * FROM t;\n",
        ["v"],
        "",
    )

    assert not result.safe
    assert any(
        finding.kind is review.FindingKind.NAME_CONFLICT
        for finding in result.findings
    )


def test_result_is_json_serialisable():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "ALTER VIEW temp_audit RENAME TO archive_audit;",
    )

    payload = json.loads(result.to_json())
    assert payload["safe"] is True
    assert payload["evidence"][0]["reason"] == "renamed"
    assert payload["findings"][0]["kind"] == "renamed"
    assert payload["findings"][0]["category"] == "trace"


def test_review_files_reads_three_inputs(tmp_path):
    (tmp_path / "decl.sql").write_text(DECLARATIONS, encoding="utf-8")
    (tmp_path / "freeze.txt").write_text(
        "forensic_snapshot\n", encoding="utf-8"
    )
    (tmp_path / "migration.sql").write_text(
        "DROP VIEW temp_audit;\n", encoding="utf-8"
    )

    result = review.review_files(
        tmp_path / "decl.sql",
        tmp_path / "freeze.txt",
        tmp_path / "migration.sql",
    )

    assert not result.safe
    assert result.evidence[0].reason == "incomplete_dependency"


def test_limits_return_an_unsafe_result_instead_of_raising():
    result = review.review(
        DECLARATIONS,
        ["forensic_snapshot"],
        "",
        max_objects=1,
    )

    assert not result.safe
    assert any(
        finding.kind is review.FindingKind.LIMIT_EXCEEDED
        for finding in result.findings
    )
