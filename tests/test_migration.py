import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

import cvss
from cvss.migration import (
    LEVEL_CHANGED,
    MISSING_EVIDENCE,
    RULE_CHANGED,
    RULE_NOT_APPLICABLE,
    SCORE_DATA_CHANGED,
    audit_migration,
)

OLD_VECTOR_8 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"
NEW_VECTOR_8 = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/"
    "SC:N/SI:N/SA:N/MAV:A/MAC:L/MAT:N/MPR:H/MUI:N/"
    "MVC:L/MVI:L/MVA:L/MSC:H/MSI:H/MSA:S"
)
NEW_VECTOR_69 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/" "SC:N/SI:L/SA:N"


def score_rule(rule_id, threshold, queue):
    return {
        "id": rule_id,
        "caliber": "base_score",
        "operator": ">=",
        "value": threshold,
        "queue": queue,
    }


class MigrationAuditTest(unittest.TestCase):
    def test_equal_scores_can_enter_different_queues(self):
        report = audit_migration(
            risk_id="RISK-EQUAL-8",
            old_vector=OLD_VECTOR_8,
            new_vector=NEW_VECTOR_8,
            old_rule=score_rule("expedited", 8.0, "legacy-expedited"),
            new_rule={
                "id": "expedited",
                "caliber": "base_severity",
                "operator": "==",
                "value": "Critical",
                "queue": "modern-expedited",
            },
        )

        self.assertEqual(8.0, report.old_score)
        self.assertEqual(8.0, report.new_score)
        self.assertEqual("High", report.old_severity)
        self.assertEqual("High", report.new_severity)
        self.assertTrue(report.old_matched)
        self.assertFalse(report.new_matched)
        self.assertEqual("legacy-expedited", report.old_queue)
        self.assertIsNone(report.new_queue)
        self.assertTrue(report.decision_changed)
        self.assertFalse(report.attribution.score_data_changed)
        self.assertTrue(report.attribution.rule_changed)
        self.assertFalse(report.attribution.level_changed)
        self.assertEqual(RULE_CHANGED, report.attribution.status)
        self.assertEqual([RULE_CHANGED], report.explanations)
        self.assertEqual(0, report.summary.old_rule_not_applicable)

        serialized = report.to_json()
        self.assertIn('"old_score": 8.0', serialized)
        self.assertIn('"new_score": 8.0', serialized)

    def test_threshold_rule_change_with_equal_scores(self):
        report = audit_migration(
            old_vector=OLD_VECTOR_8,
            new_vector=NEW_VECTOR_8,
            old_rules=[score_rule("gate", 8.0, "audit")],
            new_rules=[score_rule("gate", 9.0, "audit")],
        )

        self.assertTrue(report.old_matched)
        self.assertFalse(report.new_matched)
        self.assertTrue(report.decision_changed)
        self.assertFalse(report.attribution.score_data_changed)
        self.assertTrue(report.attribution.rule_changed)
        self.assertEqual(RULE_CHANGED, report.attribution.status)

    def test_equal_eight_score_boundary_operator_changes_queue(self):
        report = audit_migration(
            old_vector=OLD_VECTOR_8,
            new_vector=NEW_VECTOR_8,
            old_rule={
                "id": "boundary",
                "caliber": "base_score",
                "operator": ">=",
                "value": 8.0,
                "queue": "at-or-above-eight",
            },
            new_rule={
                "id": "boundary",
                "caliber": "base_score",
                "operator": ">",
                "value": 8.0,
                "queue": "strictly-above-eight",
            },
        )

        self.assertEqual((8.0, 8.0), (report.old_score, report.new_score))
        self.assertTrue(report.old_matched)
        self.assertFalse(report.new_matched)
        self.assertEqual("at-or-above-eight", report.old_queue)
        self.assertIsNone(report.new_queue)
        self.assertTrue(report.decision_changed)
        self.assertFalse(report.attribution.score_data_changed)
        self.assertTrue(report.attribution.rule_changed)

    def test_missing_old_vector_is_not_backfilled(self):
        report = audit_migration(
            old_vector=None,
            new_vector=NEW_VECTOR_8,
            old_rule=score_rule("gate", 8.0, "audit"),
            new_rule=score_rule("gate", 9.0, "audit"),
        )

        self.assertIsNone(report.old_vector)
        self.assertIsNone(report.old_score)
        self.assertIsNone(report.old_severity)
        self.assertEqual({}, report.old.metrics)
        self.assertEqual(MISSING_EVIDENCE, report.old.status)
        self.assertEqual(8.0, report.new_score)
        self.assertIsNone(report.old_matched)
        self.assertIsNone(report.decision_changed)
        self.assertIsNone(report.attribution.score_data_changed)
        self.assertTrue(report.attribution.rule_changed)
        self.assertFalse(report.attribution.determined)
        self.assertIn(SCORE_DATA_CHANGED, report.possible_explanations)
        self.assertIn(RULE_CHANGED, report.possible_explanations)
        self.assertIn(SCORE_DATA_CHANGED, report.explanations)
        self.assertIn(RULE_CHANGED, report.explanations)
        self.assertTrue(
            any(item.kind == MISSING_EVIDENCE and item.side == "old" for item in report.findings)
        )

        plain = report.to_dict()
        self.assertIsNone(plain["old"]["score"])
        self.assertIsNone(plain["old"]["cvss_version"])

    def test_same_rules_different_score_is_data_change(self):
        rule = score_rule("gate", 8.0, "audit")
        report = audit_migration(
            old_vector=OLD_VECTOR_8,
            new_vector=NEW_VECTOR_69,
            old_rule=rule,
            new_rule=dict(rule),
        )

        self.assertEqual(8.0, report.old_score)
        self.assertEqual(6.9, report.new_score)
        self.assertTrue(report.old_matched)
        self.assertFalse(report.new_matched)
        self.assertTrue(report.decision_changed)
        self.assertTrue(report.attribution.score_data_changed)
        self.assertFalse(report.attribution.rule_changed)
        self.assertEqual(SCORE_DATA_CHANGED, report.attribution.status)

    def test_old_rule_caliber_can_be_not_applicable_to_cvss4(self):
        old_rule = {
            "id": "temporal-gate",
            "caliber": "temporal_score",
            "operator": ">=",
            "value": 8.0,
            "queue": "temporal-audit",
        }
        report = audit_migration(
            old_vector=OLD_VECTOR_8,
            new_vector=NEW_VECTOR_8,
            old_rule=old_rule,
            new_rule=score_rule("base-gate", 8.0, "base-audit"),
        )
        config = report.configs[0]

        self.assertEqual("computed", config.old.status)
        self.assertTrue(config.old.matched)
        self.assertEqual(RULE_NOT_APPLICABLE, config.counterfactuals.old_rule_on_new.status)
        self.assertEqual(
            RULE_NOT_APPLICABLE,
            next(item for item in config.observations if item.caliber == "temporal_score").status,
        )
        self.assertTrue(
            any(
                item.kind == "old_rule_not_applicable"
                and item.interaction == "cross_old_rule_on_new"
                for item in report.findings
            )
        )

    def test_actual_severity_level_change_is_separate_finding(self):
        critical_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        report = audit_migration(
            old_vector=critical_31,
            new_vector=NEW_VECTOR_69,
            old_rule=score_rule("gate", 9.0, "critical-queue"),
            new_rule=score_rule("gate", 9.0, "critical-queue"),
        )

        self.assertEqual("Critical", report.old_severity)
        self.assertEqual("Medium", report.new_severity)
        self.assertTrue(report.level_change.changed)
        self.assertEqual(LEVEL_CHANGED, report.level_change.status)
        self.assertTrue(any(item.kind == LEVEL_CHANGED for item in report.findings))

    def test_package_exports_migration_entrypoint(self):
        self.assertTrue(hasattr(cvss, "audit_migration"))
        self.assertIs(cvss.migration_report, cvss.audit_migration)


if __name__ == "__main__":
    unittest.main()
