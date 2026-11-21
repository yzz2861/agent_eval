"""Tests for read-only ELF disclosure auditing."""
import hashlib
import json
import os
import subprocess
import sys
import unittest

from elftools.elf.disclosure import (
    DisclosurePolicy,
    audit_path,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "test", "testfiles_for_disclosure")
APPROVED = os.path.join(FIXTURES, "approved.elf")
LEAKY = os.path.join(FIXTURES, "leaky.elf")
POLICY_JSON = os.path.join(FIXTURES, "policy.json")
SCRIPT = os.path.join(ROOT, "scripts", "elf_disclosure.py")
POLICY = DisclosurePolicy(
    symbols=frozenset({"public_api"}),
    compile_units=frozenset({"public_unit.c", "leaky_unit.c"}),
)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.digest()


class DisclosureAuditTest(unittest.TestCase):
    def test_approved_fixture_passes(self):
        report = audit_path(APPROVED, POLICY)
        self.assertTrue(report.approved)
        self.assertEqual([symbol.name for symbol in report.symbols],
                         ["public_api"])
        symbol = report.symbols[0]
        self.assertEqual(symbol.section, ".text")
        self.assertEqual(symbol.type, "STT_FUNC")
        self.assertEqual(symbol.value, 0)
        self.assertGreater(symbol.size, 0)
        self.assertEqual(symbol.section_range["start"], 0)
        self.assertIsNotNone(symbol.file_range)
        self.assertTrue(any(
            location["path"].endswith("public_unit.c")
            for location in symbol.source_locations))
        self.assertEqual(len(report.compile_units), 1)
        self.assertTrue(report.compile_units[0].approved)
        self.assertEqual(report.findings, [])

    def test_name_cleared_fixture_fails_on_indirect_source(self):
        report = audit_path(LEAKY, POLICY)
        self.assertFalse(report.approved)
        self.assertEqual(report.symbols, [])
        self.assertEqual(report.unnamed_symbol_count, 1)
        codes = {finding.code for finding in report.findings}
        self.assertIn("unapproved_source", codes)
        self.assertIn("unapproved_source_file", codes)
        self.assertIn("stripped_name_source_leak", codes)
        subjects = " ".join(
            finding.subject or "" for finding in report.findings)
        self.assertIn("secret_impl.c", subjects)
        self.assertEqual(len(report.compile_units), 1)
        self.assertTrue(report.compile_units[0].approved)
        self.assertIn("/build/secret_impl.c", report.compile_units[0].files)
    def test_missing_symbol_approval_is_a_finding(self):
        policy = DisclosurePolicy(
            compile_units=frozenset({"public_unit.c"}))
        report = audit_path(APPROVED, policy)
        self.assertFalse(report.approved)
        findings = {finding.code: finding for finding in report.findings}
        self.assertIn("unapproved_symbol", findings)
        self.assertEqual(findings["unapproved_symbol"].subject,
                         "public_api")

    def test_shared_debug_file_is_isolated_by_object_scope(self):
        report = audit_path(APPROVED, POLICY, debug_file=LEAKY)
        self.assertTrue(report.approved)
        self.assertEqual(report.excluded_compile_unit_count, 1)
        self.assertEqual(report.compile_units, [])
        self.assertEqual(report.findings, [])

    def test_audit_preserves_input_bytes(self):
        before = (_sha256(APPROVED), _sha256(LEAKY))
        audit_path(APPROVED, POLICY)
        audit_path(LEAKY, POLICY)
        audit_path(APPROVED, POLICY, debug_file=LEAKY)
        after = (_sha256(APPROVED), _sha256(LEAKY))
        self.assertEqual(before, after)

    def test_policy_path_suffix_and_glob_matching(self):
        policy = DisclosurePolicy(
            symbols=frozenset({"public_*"}),
            compile_units=frozenset({"src/public_unit.c"}))
        self.assertTrue(policy.allows_symbol("public_api"))
        self.assertFalse(policy.allows_symbol("private_api"))
        self.assertTrue(policy.allows_compile_unit(
            "/build/src/public_unit.c"))
        self.assertFalse(policy.allows_compile_unit(
            "/build/src/secret_impl.c"))

    def _run_cli(self, *args):
        return subprocess.run(
            [sys.executable, SCRIPT, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_cli_passes_approved_object(self):
        completed = self._run_cli(APPROVED, "--policy", POLICY_JSON)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("RESULT: PASS", completed.stdout)
        self.assertNotIn("RESULT: FAIL", completed.stdout)

    def test_cli_fails_bundle_with_leaky_object(self):
        completed = self._run_cli(
            APPROVED, LEAKY, "--policy", POLICY_JSON, "--json")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["approved"])
        self.assertTrue(payload["read_only"])
        self.assertEqual(len(payload["objects"]), 2)
        by_path = {item["object"]: item for item in payload["objects"]}
        self.assertTrue(by_path[APPROVED]["approved"])
        self.assertFalse(by_path[LEAKY]["approved"])
        leaky_codes = {
            finding["code"] for finding in by_path[LEAKY]["findings"]
        }
        self.assertIn("stripped_name_source_leak", leaky_codes)


if __name__ == "__main__":
    unittest.main()
