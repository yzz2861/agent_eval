#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import unittest

from Registry.SequenceAudit import (
    audit_hives,
    audit_sequences,
    compare_hives,
    parse_approval_note,
)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, "tests", "reg_samples", "audit_recipients_baseline.hive")
CURRENT = os.path.join(ROOT, "tests", "reg_samples", "audit_recipients_current.hive")
ALIASES = {"bob": ["rob", "robert"]}
APPROVAL = {
    "id": "APR-TEST-1",
    "key": "AuditConfig",
    "value_name": "AuditRecipients",
    "action": "append",
    "baseline_ordinal": 3,
    "member": "bob",
}


class SequenceAuditTests(unittest.TestCase):
    def test_approved_duplicate_append_maps_to_original_ordinal(self):
        report = audit_hives(BASELINE, CURRENT, "AuditConfig", "AuditRecipients",
                             APPROVAL, aliases=ALIASES)
        result = report.to_dict()

        self.assertEqual(result["before"]["values"],
                         ["alice", "", "bob", "alice", "rob"])
        self.assertEqual(result["after"]["values"],
                         ["alice", "", "bob", "alice", "rob", "bob"])
        self.assertEqual(len(result["added"]), 1)
        self.assertEqual(result["added"][0]["current_ordinal"], 6)
        self.assertEqual(result["authorized_appends"][0]["baseline_ordinal"], 3)
        self.assertEqual(result["authorized_appends"][0]["approval_id"], "APR-TEST-1")
        self.assertEqual(result["unauthorized_appends"], [])
        self.assertEqual(result["set_before"], result["set_after"])
        self.assertTrue(result["set_misses_occurrence_change"])

    def test_reorder_only_is_not_append(self):
        comparison = compare_hives(BASELINE, CURRENT, "AuditConfig", "ReorderOnly")
        self.assertTrue(comparison.reorder_only)
        self.assertEqual(comparison.added, [])
        self.assertEqual(comparison.removed, [])
        self.assertEqual(
            [(m["after_ordinal"], m["before_ordinal"]) for m in comparison.matches],
            [(1, 4), (2, 1), (3, 3), (4, 2)],
        )

        report = audit_hives(BASELINE, CURRENT, "AuditConfig", "ReorderOnly", APPROVAL)
        self.assertEqual(report.decisions, [])
        self.assertIn("reorder-only", report.verdict)

    def test_unapproved_append_is_rejected(self):
        report = audit_hives(BASELINE, CURRENT, "AuditConfig", "DeniedAppend",
                             APPROVAL, aliases=ALIASES)
        result = report.to_dict()

        self.assertEqual(len(result["added"]), 1)
        self.assertEqual(result["added"][0]["value"], "eve")
        self.assertEqual(result["authorized_appends"], [])
        self.assertEqual(result["unauthorized_appends"][0]["status"], "unauthorized")

    def test_approval_note_can_supply_ordinal(self):
        parsed = parse_approval_note('CHG-7 批准追加原序号 4 的重复成员 “alice”')
        self.assertEqual(parsed["baseline_ordinal"], 4)
        self.assertEqual(parsed["value"], "alice")

    def test_alias_append_maps_to_cited_baseline_ordinal(self):
        report = audit_sequences(
            ["bob"],
            ["bob", "robert"],
            {"id": "APR-ALIAS", "baseline_ordinal": 1},
            aliases={"bob": ["robert"]},
        )

        self.assertEqual(report.authorized[0]["status"], "authorized")
        self.assertEqual(report.authorized[0]["baseline_ordinal"], 1)
        self.assertEqual(report.comparison.added[0]["current_ordinal"], 2)
        self.assertEqual(report.comparison.added[0]["value"], "robert")


if __name__ == "__main__":
    unittest.main(verbosity=2)
