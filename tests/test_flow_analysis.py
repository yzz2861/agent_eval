#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import textwrap

import dlint
from dlint.flow import (
    FlowVerdict,
    RuleSpec,
    ValidatorContract,
    analyze_function,
)


RAISES_SPEC = RuleSpec(
    name="test-raises",
    sources=("user_supplied_path",),
    validators=("validate_path",),
    sinks=("open", "read_file"),
    validator_contract=ValidatorContract.RAISES,
)

BOOL_SPEC = RuleSpec(
    name="test-bool",
    sources=("user_supplied_path",),
    validators=("is_path_ok",),
    sinks=("open",),
    validator_contract=ValidatorContract.BOOL,
)


def _result(source, spec):
    function = ast.parse(textwrap.dedent(source)).body[0]
    return analyze_function(function, spec)


class TestRaisesContract(dlint.test.base.BaseTest):

    def test_dominating_validator_is_clean(self):
        result = _result(
            """
            def f(p):
                validate_path(p)
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.SAFE, result.verdict)

    def test_swallowed_exception_is_flagged(self):
        result = _result(
            """
            def f(p):
                try:
                    validate_path(p)
                except ValueError:
                    pass
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)
        self.assertEqual(7, result.sink_lineno)
        self.assertIn("except", " ".join(result.evidence))

    def test_plain_if_is_not_a_sanitizer(self):
        result = _result(
            """
            def f(p):
                if p:
                    open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)

    def test_early_return_after_validation_is_clean(self):
        result = _result(
            """
            def f(p):
                validate_path(p)
                if not p:
                    return
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.SAFE, result.verdict)

    def test_raise_after_validation_is_clean(self):
        result = _result(
            """
            def f(p):
                validate_path(p)
                if not p:
                    raise ValueError()
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.SAFE, result.verdict)

    def test_finally_reassign_reopens_the_path(self):
        result = _result(
            """
            def f(p):
                try:
                    validate_path(p)
                finally:
                    p = user_supplied_path()
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)
        self.assertIn("finally", " ".join(result.evidence))

    def test_taint_propagates_through_assignment(self):
        result = _result(
            """
            def f():
                p = user_supplied_path()
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)

    def test_reassignment_to_clean_value_clears_taint(self):
        result = _result(
            """
            def f():
                p = user_supplied_path()
                p = "/tmp/constant"
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.SAFE, result.verdict)

    def test_loop_validator_each_iteration_is_clean(self):
        result = _result(
            """
            def f(items):
                for name in items:
                    validate_path(name)
                    open(name)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.SAFE, result.verdict)

    def test_swallowed_exception_inside_loop_is_flagged(self):
        result = _result(
            """
            def f(items):
                for name in items:
                    try:
                        validate_path(name)
                    except OSError:
                        pass
                    open(name)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)
        self.assertIn("except", " ".join(result.evidence))

    def test_break_continue_and_loop_else(self):
        result = _result(
            """
            def f(items):
                for item in items:
                    if item:
                        break
                    validate_path(item)
                    open(item)
                else:
                    open(items)
            """,
            RAISES_SPEC,
        )
        # The loop-else sink receives the unvalidated parameter.
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)


class TestBoolContract(dlint.test.base.BaseTest):

    def test_accepting_branch_is_clean(self):
        result = _result(
            """
            def f(p):
                if is_path_ok(p):
                    open(p)
            """,
            BOOL_SPEC,
        )
        self.assertEqual(FlowVerdict.SAFE, result.verdict)

    def test_bare_call_without_branch_is_flagged(self):
        result = _result(
            """
            def f(p):
                is_path_ok(p)
                open(p)
            """,
            BOOL_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)

    def test_rejecting_branch_is_flagged(self):
        result = _result(
            """
            def f(p):
                if is_path_ok(p):
                    log("ok")
                else:
                    open(p)
            """,
            BOOL_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)
        self.assertIn("branch:False", " ".join(result.evidence))

    def test_unrelated_if_test_is_not_validation(self):
        result = _result(
            """
            def f(p):
                if p.startswith("/"):
                    open(p)
            """,
            BOOL_SPEC,
        )
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)


class TestEvidenceAndBudget(dlint.test.base.BaseTest):

    def test_evidence_is_the_shortest_branch_sequence(self):
        first = _result(
            """
            def f(p):
                try:
                    validate_path(p)
                except ValueError:
                    pass
                open(p)
            """,
            RAISES_SPEC,
        )
        second = _result(
            """
            def f(p):
                try:
                    validate_path(p)
                except ValueError:
                    pass
                open(p)
            """,
            RAISES_SPEC,
        )
        self.assertEqual(first.evidence, second.evidence)
        self.assertTrue(first.evidence)

    def test_exhausted_budget_is_unknown_not_clean(self):
        source = ["def f(p):"]
        for index in range(20):
            source.append("    if p == %d:" % index)
            source.append("        q%d = p" % index)
        source.append("    open(p)")
        function = ast.parse(textwrap.dedent("\n".join(source))).body[0]
        spec = RuleSpec(
            name="bounded",
            sources=(),
            validators=("validate_path",),
            sinks=("open",),
            max_states=10,
        )
        result = analyze_function(function, spec)
        self.assertEqual(FlowVerdict.UNKNOWN, result.verdict)

    def test_free_variable_from_enclosing_scope_is_tainted(self):
        tree = ast.parse(
            textwrap.dedent(
                """
                def outer(p):
                    def inner():
                        open(p)
                """
            )
        )
        inner = tree.body[0].body[0]
        result = analyze_function(inner, RAISES_SPEC)
        self.assertEqual(FlowVerdict.UNSAFE, result.verdict)

    def test_same_input_has_fixed_output_order(self):
        source = textwrap.dedent(
            """
            def a(p):
                open(p)
            def b(p):
                open(p)
            def c(p):
                open(p)
            """
        )
        tree = ast.parse(source)
        runs = []
        for _ in range(5):
            linter = dlint.linters.UnverifiedFilepathReadLinter()
            linter.visit(tree)
            runs.append([
                (r.lineno, r.col_offset, r.message)
                for r in linter.get_results()
            ])
        self.assertTrue(all(run == runs[0] for run in runs))
        self.assertEqual(3, len(runs[0]))


if __name__ == "__main__":
    import unittest
    unittest.main()
