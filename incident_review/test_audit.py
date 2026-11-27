"""Tests for the incident re-audit logic against the two committed fixtures."""

import unittest
from pathlib import Path

import audit

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ScopeGapCaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = audit.audit_case(FIXTURES / "case_scope_gap")

    def test_target_observed_in_both_backups(self):
        sightings = self.audit.target_sightings
        self.assertEqual(sightings["b1"], ["legacy-root"])
        self.assertEqual(sightings["b2"], ["retired-root-2023"])

    def test_alias_rename_bridged_by_public_identity(self):
        self.assertEqual(len(self.audit.alias_renames), 1)
        rename = self.audit.alias_renames[0]
        self.assertIn("legacy-root", rename)
        self.assertIn("retired-root-2023", rename)

    def test_every_collection_inconclusive(self):
        for finding in self.audit.findings:
            classes = {cls for cls, _ in finding.evidence}
            self.assertIn(audit.EVIDENCE_INCONCLUSIVE, classes)
            self.assertNotIn(audit.EVIDENCE_ABSENT_IN_SCOPE, classes)
            self.assertFalse(finding.scope_complete)
            self.assertTrue(finding.record_consistent)
            self.assertTrue(finding.temporal_ok)

    def test_conclusion_is_weak_observed(self):
        conclusion = self.audit.conclusion
        self.assertEqual(conclusion["outcome"], audit.EVIDENCE_OBSERVED)
        self.assertEqual(conclusion["historical_absence_strength"], "weak")


class FullInventoryCaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = audit.audit_case(FIXTURES / "case_full_inventory")

    def test_target_observed_only_in_earliest_backup(self):
        self.assertEqual(self.audit.target_sightings, {"b0": ["legacy-root"]})
        self.assertEqual(self.audit.alias_renames, [])

    def test_later_collections_prove_absence(self):
        findings = {f.collection_id: f for f in self.audit.findings}
        for cid in ("c1", "c2"):
            finding = findings[cid]
            classes = {cls for cls, _ in finding.evidence}
            self.assertIn(audit.EVIDENCE_ABSENT_IN_SCOPE, classes)
            self.assertNotIn(audit.EVIDENCE_INCONCLUSIVE, classes)
            self.assertTrue(finding.scope_complete)
            self.assertEqual(finding.scope_gap, [])
            self.assertTrue(finding.record_consistent)

    def test_conclusion_is_strong_observed_then_absent(self):
        conclusion = self.audit.conclusion
        self.assertEqual(conclusion["outcome"], "observed_then_absent")
        self.assertEqual(conclusion["historical_absence_strength"], "strong")


class EvidenceClassesTest(unittest.TestCase):
    def test_all_three_evidence_classes_reachable(self):
        classes = set()
        for case in ("case_scope_gap", "case_full_inventory"):
            result = audit.audit_case(FIXTURES / case)
            for finding in result.findings:
                classes.update(cls for cls, _ in finding.evidence)
        self.assertEqual(classes, {
            audit.EVIDENCE_OBSERVED,
            audit.EVIDENCE_ABSENT_IN_SCOPE,
            audit.EVIDENCE_INCONCLUSIVE,
        })

    def test_reports_render_with_labels(self):
        gap_report = audit.render_markdown(audit.audit_case(FIXTURES / "case_scope_gap"))
        full_report = audit.render_markdown(audit.audit_case(FIXTURES / "case_full_inventory"))
        self.assertIn("确有观察", gap_report)
        self.assertIn("确有观察", full_report)
        self.assertIn("无法排除", gap_report)
        self.assertIn("能证明在声明范围内缺席", full_report)


if __name__ == "__main__":
    unittest.main()
