import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import CVSS4
from cvss.approval4 import explain_approval
from cvss.exceptions import CVSS4ApprovalError, CVSS4MalformedError


class TestApproval4(unittest.TestCase):
    # Errata 1: a tiny correction where only the combined two changes cross the gate.
    ORIGINAL_ONE_COMBO = (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/"
        "E:A/CR:H/IR:H/AR:L"
    )
    REVIEWED_ONE_COMBO = (
        "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/"
        "E:U/CR:H/IR:H/AR:L"
    )

    # Errata 2: two mutually non-containing reasons cross the same gate.
    ORIGINAL_TWO_REASONS = (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:H/SA:L/"
        "E:P/CR:H/IR:M/AR:H"
    )
    REVIEWED_TWO_REASONS = (
        "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:L/SI:H/SA:L/"
        "E:U/CR:H/IR:M/AR:H"
    )

    def test_erratum_only_combination_crosses(self):
        result = CVSS4(self.ORIGINAL_ONE_COMBO).explain_approval(
            self.REVIEWED_ONE_COMBO, 6.9
        )
        self.assertEqual(result.original_score, 9.9)
        self.assertEqual(result.reviewed_score, 5.4)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.minimal_groups), 1)
        group = result.minimal_groups[0]
        # Neither change alone crosses, only the pair does.
        self.assertEqual(group.metrics, ("AV", "E"))
        self.assertEqual(group.score, 5.4)
        change_metrics = {change.metric: change for change in result.changes}
        self.assertEqual(change_metrics["AV"].old_value, "N")
        self.assertEqual(change_metrics["AV"].new_value, "P")
        self.assertEqual(change_metrics["E"].old_value, "A")
        self.assertEqual(change_metrics["E"].new_value, "U")
        # The full vector is preserved and re-computes to the reported score.
        self.assertEqual(CVSS4(group.vector).base_score, group.score)
        self.assertIn("AV:P", group.vector)
        self.assertIn("E:U", group.vector)
        # No single metric change crosses the gate.
        only_av = self.ORIGINAL_ONE_COMBO.replace("AV:N", "AV:P")
        only_e = self.ORIGINAL_ONE_COMBO.replace("E:A", "E:U")
        self.assertGreater(CVSS4(only_av).base_score, 6.9)
        self.assertGreater(CVSS4(only_e).base_score, 6.9)
        self.assertEqual(
            len(CVSS4(self.ORIGINAL_ONE_COMBO).explain_approval(only_av, 6.9).minimal_groups), 0
        )
        self.assertEqual(
            len(CVSS4(self.ORIGINAL_ONE_COMBO).explain_approval(only_e, 6.9).minimal_groups), 0
        )

    def test_erratum_two_incomparable_reasons(self):
        result = explain_approval(
            self.ORIGINAL_TWO_REASONS, self.REVIEWED_TWO_REASONS, 6.9
        )
        self.assertEqual(result.original_score, 9.2)
        self.assertTrue(result.complete)
        self.assertGreaterEqual(len(result.minimal_groups), 2)
        metric_sets = [set(group.metrics) for group in result.minimal_groups]
        # Every reason is minimal: none contains another.
        for i, left in enumerate(metric_sets):
            for j, right in enumerate(metric_sets):
                if i != j:
                    self.assertFalse(left.issubset(right))
        # Two specific, incomparable reasons, both traceable to original metrics.
        as_pairs = {tuple(sorted(group.metrics)): group for group in result.minimal_groups}
        self.assertIn(("AV", "VC"), as_pairs)
        self.assertIn(("AC", "VC"), as_pairs)
        for group in result.minimal_groups:
            self.assertLessEqual(group.score, 6.9)
            self.assertEqual(CVSS4(group.vector).base_score, group.score)
            for change in group.changes:
                original_cvss = CVSS4(result.original_vector)
                self.assertEqual(change.old_effective, original_cvss.m(change.metric))

    def test_coupled_groups_move_together(self):
        result = CVSS4(self.ORIGINAL_TWO_REASONS).explain_approval(
            self.REVIEWED_TWO_REASONS, 6.9, coupled_groups=[("AV", "E")]
        )
        self.assertTrue(result.complete)
        for group in result.minimal_groups:
            metrics = set(group.metrics)
            if "AV" in metrics or "E" in metrics:
                self.assertIn("AV", metrics)
                self.assertIn("E", metrics)
        joined = {tuple(sorted(group.metrics)) for group in result.minimal_groups}
        self.assertIn(("AV", "E"), joined)
        self.assertIn(("AC", "VC"), joined)

    def test_unknown_coupled_metric_rejected(self):
        with self.assertRaises(CVSS4ApprovalError):
            explain_approval(
                self.ORIGINAL_TWO_REASONS,
                self.REVIEWED_TWO_REASONS,
                6.9,
                coupled_groups=[("AV", "ZZ")],
            )

    def test_invalid_direction_and_budget(self):
        with self.assertRaises(CVSS4ApprovalError):
            explain_approval(
                self.ORIGINAL_TWO_REASONS, self.REVIEWED_TWO_REASONS, 6.9, direction="sideways"
            )
        with self.assertRaises(CVSS4ApprovalError):
            explain_approval(
                self.ORIGINAL_TWO_REASONS, self.REVIEWED_TWO_REASONS, 6.9, max_evaluations=0
            )

    def test_budget_limits_provenance(self):
        result = explain_approval(
            self.ORIGINAL_TWO_REASONS,
            self.REVIEWED_TWO_REASONS,
            6.9,
            max_evaluations=2,
        )
        self.assertFalse(result.complete)
        self.assertFalse(result.proven)
        self.assertLessEqual(result.evaluations, 2)
        for group in result.minimal_groups:
            self.assertEqual(CVSS4(group.vector).base_score, group.score)

    def test_modified_metric_inheritance_preserved(self):
        # MAV absent inherits AV; changing only the modified metric still scores via CVSS4.
        original = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        reviewed = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:P"
        )
        result = explain_approval(original, reviewed, 9.0)
        change = result.changes[0]
        self.assertEqual(change.metric, "MAV")
        self.assertIsNone(change.old_value)
        self.assertEqual(change.new_value, "P")
        # Inherited effective value of MAV before the change is the base AV value.
        self.assertEqual(change.old_effective, "N")
        self.assertEqual(change.new_effective, "P")
        for group in result.minimal_groups:
            self.assertEqual(CVSS4(group.vector).base_score, group.score)

    def test_supplemental_metrics_ignored(self):
        original = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        reviewed = original + "/U:Red"
        result = explain_approval(original, reviewed, 9.0)
        self.assertEqual(result.changes, ())
        self.assertIn("U", result.ignored_supplemental)
        self.assertEqual(result.minimal_groups, ())

    def test_already_below_gate_has_no_groups(self):
        original = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        result = explain_approval(original, original, 6.9)
        self.assertEqual(result.minimal_groups, ())
        self.assertTrue(result.complete)

    def test_above_direction_upgrade_gate(self):
        original = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        reviewed = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        result = explain_approval(original, reviewed, 9.0, direction="above")
        self.assertEqual(result.direction, "above")
        for group in result.minimal_groups:
            self.assertGreaterEqual(group.score, 9.0)
            self.assertEqual(CVSS4(group.vector).base_score, group.score)

    def test_malformed_vector_propagates(self):
        good = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        with self.assertRaises(CVSS4MalformedError):
            explain_approval(good, "CVSS:4.0/AV:ZZ", 6.9)


if __name__ == "__main__":
    unittest.main()
