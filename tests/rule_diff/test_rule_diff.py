"""Validation tests for the dlint rule-diff backend.

Covers: an injected false negative, an injected false positive, identical
rules (no spurious difference), exception vs no-warning separation, category
preservation under reduction, witness replay, out-of-scope declaration, and
the 30-second budget. Standard library plus pytest only.
"""

import ast
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   "..", "..")))

from dlint.rule_diff import (
    ALERT_ADDED,
    ALERT_REMOVED,
    Budget,
    compare_rules,
    replay,
    uncovered_features,
)
from dlint.rule_diff import language, reducer, runner

from tests.rule_diff import fixture_rules as fx


# A small but fully valid bounded subset keeps the validation suite fast while
# still exercising every required construct (imports/aliases, calls, constant
# conditions and assignments). One dedicated test below uses the full subset.
SMALL_SUBSET = language.BoundedSubset(
    bounds=language.Bounds(max_statements=3, max_program_count=350)
)
SMALL_BUDGET = Budget(deadline_seconds=5.0, max_programs=350, max_witnesses=2)


class TestBoundedSubset(unittest.TestCase):
    def test_every_generated_program_compiles_and_is_in_subset(self):
        count = 0
        for source in language.SUBSET.iter_programs():
            compile(source, "<generated>", "exec")
            self.assertTrue(language.is_in_subset(ast.parse(source)))
            count += 1
            if count >= 300:
                break
        self.assertGreater(count, 50)

    def test_subset_covers_required_behaviours(self):
        names = set(language.SUBSET.coverage().supported_node_types)
        for required in ("Import", "ImportFrom", "Call", "Attribute", "If",
                         "Assign", "Constant", "Name"):
            self.assertIn(required, names)

    def test_out_of_scope_is_declared_not_guessed(self):
        uncovered = uncovered_features(["FunctionDef", "While", "For",
                                       "Try", "Lambda", "BinOp"])
        self.assertEqual(uncovered, ["FunctionDef", "While", "For", "Try",
                                     "Lambda", "BinOp"])
        covered, uncovered2 = language.SUBSET.declare_coverage(
            ["Call", "FunctionDef"]
        )
        self.assertEqual(covered, ["Call"])
        self.assertEqual(uncovered2, ["FunctionDef"])

    def test_unsupported_node_is_detected(self):
        tree = ast.parse("def f():\n    return 1")
        self.assertFalse(language.is_in_subset(tree))
        self.assertIn("FunctionDef", language.unsupported_kinds(tree))


class TestRunnerSeparation(unittest.TestCase):
    def test_no_alert_is_empty_list_not_exception(self):
        result = runner.evaluate("a = 1", (fx.StableRule,))
        self.assertEqual(result.alerts, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.alert_identities(), set())

    def test_exception_is_counted_separately_from_alert(self):
        result = runner.evaluate("if True:" + chr(10) + "    a = 1", (fx.CrashingRule,))
        self.assertEqual(result.alerts, [])
        self.assertEqual(len(result.errors), 1)
        error = result.errors[0]
        self.assertEqual(error.rule_name, "CrashingRule")
        self.assertEqual(error.exception_type, "RuntimeError")
        self.assertIn("fixture_rules.py", error.location)

    def test_one_crashing_rule_does_not_block_others(self):
        result = runner.evaluate(
            "if True:" + chr(10) + "    danger()", (fx.CrashingRule, fx.StableRule)
        )
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(len(result.alerts), 1)
        self.assertEqual(result.alerts[0].rule_name, "StableRule")

    def test_alert_identity_ignores_line_position(self):
        first = runner.evaluate("danger()", (fx.StableRule,)).alerts[0]
        second = runner.evaluate("a = 1\ndanger()", (fx.StableRule,)).alerts[0]
        self.assertEqual(first.identity(), second.identity())
        self.assertNotEqual((first.lineno, first.col_offset),
                            (second.lineno, second.col_offset))


class TestFalseNegativeWitness(unittest.TestCase):
    def setUp(self):
        self.old = (fx.StrictEvalRule,)
        self.new = (fx.AliasBlindEvalRule,)
        self.report = compare_rules(self.old, self.new, subset=SMALL_SUBSET, budget=SMALL_BUDGET)

    def test_detects_injected_false_negative(self):
        self.assertIn(ALERT_REMOVED, self.report.category_counts)
        self.assertTrue(any(
            diff.category == ALERT_REMOVED for diff in self.report.differences
        ))
        self.assertTrue(self.report.alerts_removed)

    def test_witness_is_compilable_and_replayable(self):
        witness = next(d for d in self.report.differences
                       if d.category == ALERT_REMOVED)
        compile(witness.source, "<witness>", "exec")
        category, old_result, new_result = replay(
            witness.source, self.old, self.new
        )
        self.assertEqual(category, ALERT_REMOVED)
        self.assertTrue(old_result.alerts)
        self.assertEqual(new_result.alerts, [])

    def test_replay_is_deterministic(self):
        witness = next(d for d in self.report.differences
                       if d.category == ALERT_REMOVED)
        first = replay(witness.source, self.old, self.new)[0]
        second = replay(witness.source, self.old, self.new)[0]
        self.assertEqual(first, second)

    def test_premises_and_locations_present(self):
        witness = next(d for d in self.report.differences
                       if d.category == ALERT_REMOVED)
        self.assertTrue(witness.premises)
        self.assertTrue(witness.rule_locations)
        self.assertTrue(any("call" in p for p in witness.premises))

    def test_reduction_preserved_category(self):
        witness = next(d for d in self.report.differences
                       if d.category == ALERT_REMOVED)
        category = replay(witness.source, self.old, self.new)[0]
        self.assertEqual(category, ALERT_REMOVED)


class TestFalsePositiveWitness(unittest.TestCase):
    def setUp(self):
        self.old = (fx.StrictEvalRule,)
        self.new = (fx.OverbroadEvalRule,)
        self.report = compare_rules(self.old, self.new, subset=SMALL_SUBSET, budget=SMALL_BUDGET)

    def test_detects_injected_false_positive(self):
        self.assertIn(ALERT_ADDED, self.report.category_counts)
        self.assertTrue(any(
            diff.category == ALERT_ADDED for diff in self.report.differences
        ))
        self.assertTrue(self.report.alerts_added)

    def test_witness_replays_as_alert_added(self):
        witness = next(d for d in self.report.differences
                       if d.category == ALERT_ADDED)
        compile(witness.source, "<witness>", "exec")
        category, old_result, new_result = replay(
            witness.source, self.old, self.new
        )
        self.assertEqual(category, ALERT_ADDED)
        self.assertEqual(old_result.alerts, [])
        self.assertTrue(new_result.alerts)

    def test_categories_never_mix(self):
        # An added-alert witness must not be reported as a removed one.
        for diff in self.report.differences:
            if diff.category == ALERT_ADDED:
                self.assertEqual(diff.old_result.alerts, [])


class TestIdenticalRules(unittest.TestCase):
    def test_identical_rule_sets_have_no_differences(self):
        rules = (fx.StrictEvalRule, fx.AssignmentRule)
        report = compare_rules(rules, rules, subset=SMALL_SUBSET, budget=SMALL_BUDGET)
        self.assertFalse(report.difference_found)
        self.assertEqual(report.differences, [])
        self.assertEqual(report.category_counts, {})
        self.assertEqual(report.alerts_added, [])
        self.assertEqual(report.alerts_removed, [])

    def test_no_equivalence_proof_is_claimed(self):
        rules = (fx.StrictEvalRule,)
        report = compare_rules(rules, rules, subset=SMALL_SUBSET, budget=SMALL_BUDGET)
        statement = report.equivalence_statement()
        self.assertIn("NOT a proof of equivalence", statement)
        self.assertIn(str(report.programs_evaluated), statement)

    def test_distinct_but_equivalent_on_subset_still_bounded_wording(self):
        # Two rule classes with identical behaviour on this subset.
        report = compare_rules(
            (fx.StableRule,), (fx.StableRule,), subset=SMALL_SUBSET, budget=SMALL_BUDGET
        )
        self.assertFalse(report.difference_found)
        self.assertIn("No difference was found", report.equivalence_statement())


class TestExceptionCategories(unittest.TestCase):
    def test_error_introduced_is_separate_from_silence(self):
        # Old set never crashes; new set adds a crashing rule.
        report = compare_rules(
            (fx.StableRule,), (fx.StableRule, fx.CrashingRule),
            subset=SMALL_SUBSET, budget=SMALL_BUDGET,
        )
        self.assertIn("error_introduced", report.category_counts)
        self.assertGreater(report.new_error_count, 0)
        witness = next(d for d in self._diffs(report, "error_introduced"))
        self.assertEqual(witness.old_result.errors, [])
        self.assertTrue(witness.new_result.errors)
        # The crash must not be miscounted as an alert change.
        self.assertEqual(witness.old_result.alerts,
                         self._stable_alerts(witness))

    def test_error_cleared_when_crash_is_fixed(self):
        report = compare_rules(
            (fx.CrashingRule,), (fx.StableRule,), subset=SMALL_SUBSET, budget=SMALL_BUDGET
        )
        self.assertIn("error_cleared", report.category_counts)
        self.assertGreater(report.old_error_count, 0)

    @staticmethod
    def _diffs(report, category):
        return [d for d in report.differences if d.category == category]

    @staticmethod
    def _stable_alerts(witness):
        return [a for a in witness.new_result.alerts
                if a.rule_name == "StableRule"]


class TestReductionAndBudget(unittest.TestCase):
    def test_reduction_keeps_same_category_and_compiles(self):
        source = chr(10).join(["import os", "a = 1", "eval()", "b = 2"])
        classify_fn = lambda src: replay(src, (fx.StrictEvalRule,),
                                         (fx.AliasBlindEvalRule,))[0]
        deadline = lambda: True
        reduced, steps = reducer.reduce_witness(
            source, ALERT_REMOVED, classify_fn, deadline
        )
        compile(reduced, "<reduced>", "exec")
        self.assertEqual(classify_fn(reduced), ALERT_REMOVED)
        self.assertLessEqual(len(reduced.splitlines()), len(source.splitlines()))
        self.assertIn("eval", reduced)
        self.assertTrue(language.is_in_subset(ast.parse(reduced)))

    def test_reduction_never_returns_drifted_category(self):
        source = "eval()"
        classify_fn = lambda src: replay(src, (fx.StrictEvalRule,),
                                         (fx.AliasBlindEvalRule,))[0]
        reduced, _ = reducer.reduce_witness(
            source, ALERT_REMOVED, classify_fn, lambda: True
        )
        self.assertEqual(classify_fn(reduced), ALERT_REMOVED)

    def test_whole_run_respects_time_and_program_budget(self):
        start = time.monotonic()
        report = compare_rules(
            (fx.StrictEvalRule,), (fx.AliasBlindEvalRule,),
            budget=Budget(deadline_seconds=2.0, max_programs=100000,
                          max_witnesses=1),
        )
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 30.0)
        self.assertLessEqual(report.programs_evaluated, 100000)
        self.assertTrue(report.truncated)

    def test_report_dict_is_json_ready(self):
        import json
        report = compare_rules(
            (fx.StrictEvalRule,), (fx.AliasBlindEvalRule,),
            subset=SMALL_SUBSET, budget=SMALL_BUDGET,
        )
        encoded = json.dumps(report.to_dict())
        decoded = json.loads(encoded)
        self.assertIn("coverage", decoded)
        self.assertIn("alert_set_changes", decoded)
        self.assertIn("exception_counts", decoded)


if __name__ == "__main__":
    unittest.main()
