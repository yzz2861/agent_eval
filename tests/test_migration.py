import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.migration import (
    CHANGED,
    MISSING_EVIDENCE,
    NOT_COMPARABLE,
    OLD_RULE_NOT_APPLICABLE,
    POSSIBLE,
    REJECTED,
    RULE_CHANGED,
    SCORING_DATA_CHANGED,
    SUPPORTED,
    UNCHANGED,
    QueueRule,
    QueueRuleError,
    QueueRuleSet,
    migrate_queues,
)


OLD_80 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"
OLD_75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
NEW_80 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/E:U"


def score_rules(version, threshold=8.0, inclusive=True, name=None):
    return QueueRuleSet(
        version,
        ["score"],
        [
            {
                "queue": "priority",
                "min_score": threshold,
                "min_inclusive": inclusive,
            },
            {"queue": "standard"},
        ],
        name=name,
    )


class TestQueueMigration(unittest.TestCase):
    def test_equal_scores_can_use_different_queue_rules(self):
        """
        Both vectors are 8.0 / High, but the old rule includes 8.0 and the new
        rule excludes it.  Equal scores alone therefore do not prove equal rules.
        """
        result = migrate_queues(
            OLD_80,
            NEW_80,
            score_rules("3.1", 8.0, True, name="old"),
            score_rules("4.0", 8.0, False, name="new"),
        )

        self.assertEqual(8.0, result.old.score)
        self.assertEqual(8.0, result.new.score)
        self.assertEqual("High", result.old.severity)
        self.assertEqual("High", result.new.severity)
        self.assertEqual("priority", result.old.queue)
        self.assertEqual("standard", result.new.queue)
        self.assertEqual(CHANGED, result.status)
        self.assertTrue(result.changed)

        explanations = dict((item["hypothesis"], item["status"]) for item in result.explanations)
        self.assertEqual(REJECTED, explanations[SCORING_DATA_CHANGED])
        self.assertEqual(SUPPORTED, explanations[RULE_CHANGED])
        self.assertEqual(RULE_CHANGED, result.attribution)
        self.assertEqual(RULE_CHANGED, result.primary_explanation)
        self.assertFalse(result.coexisting)

        report = result.report()
        self.assertIn("score: 8.0 -> 8.0 (unchanged)", report)
        self.assertIn("scoring_data_changed: rejected", report)
        self.assertIn("rule_changed: supported", report)
        self.assertIn("attribution: rule_changed", report)

    def test_missing_old_vector_is_not_inferred(self):
        result = migrate_queues(
            None,
            NEW_80,
            score_rules("3.1"),
            score_rules("4.0"),
        )

        self.assertEqual(NOT_COMPARABLE, result.status)
        self.assertIsNone(result.changed)
        self.assertEqual("missing_evidence", result.old.status)
        self.assertIsNone(result.old.score)
        self.assertIsNone(result.old.severity)
        self.assertIsNone(result.old.queue)
        self.assertIsNone(result.old.base_score)
        self.assertIsNone(result.old.vector)
        self.assertEqual(8.0, result.new.score)
        self.assertEqual("priority", result.new.queue)

        self.assertEqual([MISSING_EVIDENCE], [item["code"] for item in result.blockers])
        self.assertNotIn(OLD_RULE_NOT_APPLICABLE, [item["code"] for item in result.blockers])
        self.assertFalse(result.cross_computation["performed"])
        self.assertEqual("undetermined", result.attribution)
        self.assertEqual([SCORING_DATA_CHANGED, RULE_CHANGED], result.possible_explanations)
        self.assertTrue(result.coexisting)
        self.assertIn("no score or severity was inferred", result.report())

    def test_missing_new_vector_is_not_inferred(self):
        result = migrate_queues(
            OLD_80,
            None,
            score_rules("3.1"),
            score_rules("4.0"),
        )

        self.assertEqual(NOT_COMPARABLE, result.status)
        self.assertEqual(8.0, result.old.score)
        self.assertEqual("priority", result.old.queue)
        self.assertEqual("missing_evidence", result.new.status)
        self.assertIsNone(result.new.score)
        self.assertIsNone(result.new.severity)
        self.assertIsNone(result.new.queue)
        self.assertEqual([MISSING_EVIDENCE], [item["code"] for item in result.blockers])

    def test_old_rule_inapplicable_is_distinct_from_missing_evidence(self):
        result = migrate_queues(
            NEW_80,
            NEW_80,
            score_rules("3.1"),
            score_rules("4.0"),
        )

        self.assertEqual(NOT_COMPARABLE, result.status)
        self.assertEqual("not_applicable", result.old.status)
        self.assertEqual(OLD_RULE_NOT_APPLICABLE, result.old.reason_code)
        self.assertEqual(8.0, result.old.score)
        self.assertIsNone(result.old.queue)
        self.assertEqual([OLD_RULE_NOT_APPLICABLE], [item["code"] for item in result.blockers])
        self.assertNotIn(MISSING_EVIDENCE, [item["code"] for item in result.blockers])
        self.assertIn("not applicable", result.report())

    def test_scoring_data_change_is_attributed_when_rules_are_equal(self):
        result = migrate_queues(
            OLD_75,
            NEW_80,
            score_rules("3.1", 8.0, True, name="old"),
            score_rules("4.0", 8.0, True, name="new"),
        )

        self.assertEqual(7.5, result.old.score)
        self.assertEqual(8.0, result.new.score)
        self.assertEqual("standard", result.old.queue)
        self.assertEqual("priority", result.new.queue)
        self.assertEqual(CHANGED, result.status)
        explanations = dict((item["hypothesis"], item["status"]) for item in result.explanations)
        self.assertEqual(SUPPORTED, explanations[SCORING_DATA_CHANGED])
        self.assertEqual(REJECTED, explanations[RULE_CHANGED])
        self.assertEqual(SCORING_DATA_CHANGED, result.attribution)

    def test_both_explanations_can_coexist(self):
        result = migrate_queues(
            OLD_75,
            NEW_80,
            score_rules("3.1", 8.0, True, name="old"),
            score_rules("4.0", 7.0, True, name="new"),
        )

        self.assertEqual(CHANGED, result.status)
        self.assertEqual("standard", result.old.queue)
        self.assertEqual("priority", result.new.queue)
        explanations = dict((item["hypothesis"], item["status"]) for item in result.explanations)
        self.assertEqual(SUPPORTED, explanations[SCORING_DATA_CHANGED])
        self.assertEqual(SUPPORTED, explanations[RULE_CHANGED])
        self.assertTrue(result.coexisting)
        self.assertEqual("both", result.attribution)
        self.assertIsNone(result.primary_explanation)

    def test_cross_computation_requires_a_common_declared_basis(self):
        old_rules = QueueRuleSet(
            "3.1",
            ["score"],
            [{"queue": "priority", "min_score": 8.0}, {"queue": "standard"}],
        )
        new_rules = QueueRuleSet(
            "4.0",
            ["severity"],
            [
                {"queue": "priority", "severities": ["Critical"]},
                {"queue": "standard"},
            ],
        )
        result = migrate_queues(OLD_80, NEW_80, old_rules, new_rules)

        self.assertEqual(CHANGED, result.status)
        self.assertEqual((), result.common_basis)
        self.assertFalse(result.cross_computation["performed"])
        self.assertIn(
            "no dimension was explicitly declared",
            result.cross_computation["not_performed_reason"],
        )
        explanations = dict((item["hypothesis"], item["status"]) for item in result.explanations)
        self.assertEqual(POSSIBLE, explanations[SCORING_DATA_CHANGED])
        self.assertEqual(POSSIBLE, explanations[RULE_CHANGED])
        self.assertTrue(result.coexisting)
        self.assertEqual("undetermined", result.attribution)

    def test_identical_decisions_are_unchanged(self):
        result = migrate_queues(
            OLD_80,
            NEW_80,
            score_rules("3.1", 8.0, True, name="old"),
            score_rules("4.0", 8.0, True, name="new"),
        )
        self.assertEqual(UNCHANGED, result.status)
        self.assertFalse(result.changed)
        self.assertEqual("no_change", result.attribution)

    def test_invalid_vector_is_reported_separately(self):
        result = migrate_queues(
            "not-a-vector",
            NEW_80,
            score_rules("3.1"),
            score_rules("4.0"),
        )
        self.assertEqual(NOT_COMPARABLE, result.status)
        self.assertEqual("invalid_vector", result.old.status)
        self.assertEqual(["invalid_vector"], [item["code"] for item in result.blockers])

    def test_red_hat_notation_is_recomputed(self):
        result = migrate_queues(
            "0.1/" + OLD_80,
            NEW_80,
            score_rules("3.1", 8.0, True),
            score_rules("4.0", 8.0, True),
        )
        self.assertEqual(8.0, result.old.score)
        self.assertEqual("priority", result.old.queue)

    def test_rule_conditions_must_use_the_declared_basis(self):
        with self.assertRaises(QueueRuleError):
            QueueRuleSet(
                "3.1",
                ["score"],
                [{"queue": "priority", "severities": ["High"]}],
            )

    def test_catch_all_rule_must_be_last(self):
        with self.assertRaises(QueueRuleError):
            QueueRuleSet(
                "3.1",
                ["score"],
                [
                    {"queue": "standard"},
                    {"queue": "priority", "min_score": 8.0},
                ],
            )

    def test_cvss4_does_not_declare_temporal_score(self):
        with self.assertRaises(QueueRuleError):
            QueueRuleSet(
                "4.0",
                ["score"],
                [{"queue": "priority", "min_score": 8.0}],
                score_metric="temporal",
            )

    def test_rule_objects_and_dict_rule_sets_are_accepted(self):
        old_rules = {
            "version": "3.1",
            "basis": ["score"],
            "rules": [
                QueueRule("priority", min_score=8.0),
                QueueRule("standard"),
            ],
        }
        new_rules = score_rules("4.0", 8.0, True)
        result = migrate_queues(OLD_80, NEW_80, old_rules, new_rules)
        self.assertEqual(UNCHANGED, result.status)
        self.assertEqual("priority", result.old.queue)
        self.assertEqual("priority", result.new.queue)


if __name__ == "__main__":
    unittest.main()
