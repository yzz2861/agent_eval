import sys
import unittest
from datetime import date
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from review.engine import (
    CONSISTENT,
    INCOMPARABLE,
    INVERTED,
    TIE_OK,
    evaluate_case,
    resolve_active,
)
from review.model import load_case

WD = path.dirname(path.abspath(__file__))
CASE = path.join(WD, "..", "examples", "four_tickets.json")


def verdicts_by_id(result):
    return {v.statement.id: v for v in result["verdicts"]}


class TestReviewExample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tickets, cls.statements = load_case(CASE)

    def test_scores_computed_per_scale(self):
        result = evaluate_case(self.tickets, self.statements, date(2026, 3, 1))
        self.assertEqual(result["scores"]["WO-甲"]["cvss3"], 5.3)
        self.assertEqual(result["scores"]["WO-乙"]["cvss3"], 9.3)
        self.assertEqual(result["scores"]["WO-丙"]["cvss3"], 9.3)
        self.assertNotIn("cvss3", result["scores"]["WO-丁"])

    def test_verdicts_before_update(self):
        result = evaluate_case(self.tickets, self.statements, date(2026, 3, 1))
        verdicts = verdicts_by_id(result)
        self.assertEqual(verdicts["S1"].status, INVERTED)
        self.assertEqual(verdicts["S2"].status, TIE_OK)
        self.assertEqual(verdicts["S3"].status, CONSISTENT)
        self.assertEqual(verdicts["S4"].status, INCOMPARABLE)
        self.assertIn("WO-甲", verdicts["S4"].detail)
        self.assertNotIn("S5", verdicts)

    def test_conflict_combination_before_update(self):
        result = evaluate_case(self.tickets, self.statements, date(2026, 3, 1))
        combos = [c.statement_ids for c in result["conflicts"]]
        self.assertEqual(combos, [("S1", "S2", "S3")])

    def test_update_shadows_only_covered_objects(self):
        result = evaluate_case(self.tickets, self.statements, date(2026, 8, 1))
        active_ids = [s.id for s in result["active"]]
        shadowed_ids = [s.id for s in result["shadowed"]]
        self.assertIn("S5", active_ids)
        self.assertEqual(shadowed_ids, ["S3"])
        # 未覆盖的陈述不受更新影响
        self.assertIn("S1", active_ids)
        self.assertIn("S2", active_ids)
        self.assertIn("S4", active_ids)

    def test_conflict_combination_after_update(self):
        result = evaluate_case(self.tickets, self.statements, date(2026, 8, 1))
        combos = [c.statement_ids for c in result["conflicts"]]
        self.assertEqual(combos, [("S1", "S2", "S5")])

    def test_old_statement_still_governs_earlier_window(self):
        result = evaluate_case(self.tickets, self.statements, date(2026, 6, 30))
        active_ids = [s.id for s in result["active"]]
        self.assertIn("S3", active_ids)
        self.assertNotIn("S5", active_ids)

    def test_tolerance_allows_tie(self):
        result = evaluate_case(
            self.tickets, self.statements, date(2026, 8, 1), tolerance=4.0
        )
        verdicts = verdicts_by_id(result)
        self.assertEqual(verdicts["S5"].status, TIE_OK)
        self.assertEqual(verdicts["S1"].status, TIE_OK)


class TestResolveActive(unittest.TestCase):
    def test_latest_valid_from_wins_per_coverage(self):
        _, statements = load_case(CASE)
        active, shadowed = resolve_active(statements, date(2026, 7, 1))
        by_id = {s.id: s for s in active}
        self.assertIn("S5", by_id)
        self.assertEqual([s.id for s in shadowed], ["S3"])


if __name__ == "__main__":
    unittest.main()
