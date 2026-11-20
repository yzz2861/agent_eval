"""Tests for the diagnostic-structure leak audit (unittest style)."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from struct_leak_audit import AuditConfig, Severity, audit_file, audit_source, to_json
from struct_leak_audit.model import (
    CONSTANT_FIELD,
    KNOWN_PROJECTION,
    MEMCPY_COPY,
    UNBOUND_INDIRECT,
    WHOLE_STRUCT_COPY,
)

CASE_DIR = Path(__file__).parent / "struct_leak_cases"

CONFIG = AuditConfig(
    public_struct="diag_public",
    report_functions=("host_report",),
    projection_functions=("project_public",),
)


class StructLeakAuditTest(unittest.TestCase):
    def _report(self, result, name):
        return next(report for report in result.reports if report.name == name)

    def _codes(self, report):
        return [finding.code for finding in report.findings]

    def test_safe_snippet_uses_only_constant_fields(self):
        result = audit_file(CASE_DIR / "safe_report.c", CONFIG)
        safe = self._report(result, "report_safe")
        self.assertEqual(safe.verdict, Severity.SAFE)
        self.assertEqual(self._codes(safe), [CONSTANT_FIELD, CONSTANT_FIELD])
        rendered = {finding.expression for finding in safe.findings}
        self.assertIn("0", rendered)
        self.assertTrue(any("redacted" in expr for expr in rendered))

    def test_same_named_field_is_not_treated_as_internal_copy(self):
        result = audit_file(CASE_DIR / "safe_report.c", CONFIG)
        safe = self._report(result, "report_safe")
        for finding in safe.findings:
            self.assertEqual(finding.severity, Severity.SAFE)

    def test_trusted_projection_is_safe(self):
        result = audit_file(CASE_DIR / "safe_report.c", CONFIG)
        projection = self._report(result, "report_via_projection")
        self.assertEqual(projection.verdict, Severity.SAFE)
        self.assertEqual(self._codes(projection), [KNOWN_PROJECTION])

    def test_unbound_indirect_call_remains_review(self):
        result = audit_file(CASE_DIR / "safe_report.c", CONFIG)
        indirect = self._report(result, "report_indirect")
        self.assertEqual(indirect.verdict, Severity.REVIEW)
        self.assertEqual(self._codes(indirect), [UNBOUND_INDIRECT])
        self.assertEqual(indirect.findings[0].source, "emit")

    def test_unsafe_assignment_points_to_real_source(self):
        result = audit_file(CASE_DIR / "unsafe_report.c", CONFIG)
        assignment = self._report(result, "report_by_assignment")
        self.assertEqual(assignment.verdict, Severity.UNSAFE)
        self.assertEqual(self._codes(assignment), [WHOLE_STRUCT_COPY])
        source = assignment.findings[0].source
        self.assertIn("source", source)
        self.assertIn("diag_public", source)

    def test_unsafe_memcpy_points_to_real_source(self):
        result = audit_file(CASE_DIR / "unsafe_report.c", CONFIG)
        memcpy = self._report(result, "report_by_memcpy")
        self.assertEqual(memcpy.verdict, Severity.UNSAFE)
        self.assertEqual(self._codes(memcpy), [MEMCPY_COPY])
        self.assertEqual(memcpy.findings[0].source, "source")

    def test_designated_and_aggregate_constant_initializers_are_safe(self):
        source = """
struct diag_public { int id; const char *name; };
struct diag_internal { int id; const char *name; };
void host_report(const struct diag_public *r);
void designated(void) {
    struct diag_public r = { .id = 7, .name = "x" };
    host_report(&r);
}
void aggregate(void) {
    struct diag_public r = { 1, "lit" };
    host_report(&r);
}
"""
        result = audit_source(source, CONFIG)
        for report in result.reports:
            self.assertEqual(report.verdict, Severity.SAFE, report.name)
            self.assertTrue(all(
                finding.code == CONSTANT_FIELD for finding in report.findings))

    def test_one_internal_field_marks_review_while_constant_field_is_safe(self):
        source = """
struct diag_public { int id; const char *name; };
struct diag_internal { int id; const char *name; };
void host_report(const struct diag_public *r);
void mixed(struct diag_internal *source) {
    struct diag_public r;
    r.id = source->id;
    r.name = "fixed";
    host_report(&r);
}
"""
        from struct_leak_audit import audit_source
        result = audit_source(source, CONFIG)
        mixed = self._report(result, "mixed")
        self.assertEqual(mixed.verdict, Severity.REVIEW)
        codes = self._codes(mixed)
        self.assertEqual(codes, ["field_from_source", CONSTANT_FIELD])
        self.assertEqual(mixed.findings[0].source, "source->id")

    def test_overall_verdicts_and_json_payload(self):
        safe = audit_file(CASE_DIR / "safe_report.c", CONFIG)
        unsafe = audit_file(CASE_DIR / "unsafe_report.c", CONFIG)
        self.assertEqual(safe.verdict, Severity.REVIEW)
        self.assertEqual(unsafe.verdict, Severity.UNSAFE)
        payload = json.loads(to_json(unsafe))
        codes = {item["code"] for fn in payload["functions"] for item in fn["findings"]}
        self.assertIn("whole_struct_copy", codes)
        self.assertIn("memcpy_copy", codes)


if __name__ == "__main__":
    unittest.main()
