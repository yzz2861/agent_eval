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
from dlint.linters import base
from dlint.linters.unverified_filepath_read import (
    UnverifiedFilepathReadLinter,
)


def _lint(source):
    tree = ast.parse(textwrap.dedent(source))
    linter = UnverifiedFilepathReadLinter()
    linter.visit(tree)
    return linter.get_results()


class TestUnverifiedFilepathRead(dlint.test.base.BaseTest):

    def test_dominating_validator_produces_no_warning(self):
        results = _lint(
            """
            def read(name):
                validate_path(name)
                with open(name) as handle:
                    return handle.read()
            """
        )
        self.assertEqual([], results)

    def test_validator_in_every_branch_is_clean(self):
        results = _lint(
            """
            def read(name):
                if name:
                    validate_path(name)
                else:
                    validate_path(name)
                open(name)
            """
        )
        self.assertEqual([], results)

    def test_swallowed_exception_warns(self):
        results = _lint(
            """
            def read(name):
                try:
                    validate_path(name)
                except ValueError:
                    pass
                open(name)
            """
        )
        self.assertEqual(1, len(results))
        self.assertEqual(7, results[0].lineno)
        self.assertIn("DUO139", results[0].message)
        self.assertIn("except", results[0].message)

    def test_plain_if_is_not_treated_as_sanitizer(self):
        results = _lint(
            """
            def read(name):
                if name:
                    open(name)
            """
        )
        self.assertEqual(1, len(results))
        self.assertIn("branch:True", results[0].message)

    def test_finally_reassignment_warns(self):
        results = _lint(
            """
            def read(name):
                try:
                    validate_path(name)
                finally:
                    name = user_supplied_path()
                open(name)
            """
        )
        self.assertEqual(1, len(results))
        self.assertIn("finally", results[0].message)

    def test_request_parameter_source_is_tracked(self):
        results = _lint(
            """
            def read():
                name = request.args.get("path")
                open(name)
            """
        )
        self.assertEqual(1, len(results))
        self.assertEqual(4, results[0].lineno)

    def test_result_objects_use_flake8_shape(self):
        results = _lint(
            """
            def read(name):
                open(name)
            """
        )
        self.assertEqual(1, len(results))
        self.assertIsInstance(results[0], base.Flake8Result)

    def test_output_order_is_deterministic(self):
        source = textwrap.dedent(
            """
            def z(p):
                open(p)
            def a(p):
                open(p)
            def m(p):
                open(p)
            """
        )
        runs = []
        for _ in range(5):
            tree = ast.parse(source)
            linter = UnverifiedFilepathReadLinter()
            linter.visit(tree)
            runs.append(
                [(r.lineno, r.col_offset, r.message)
                 for r in linter.get_results()]
            )
        self.assertTrue(all(run == runs[0] for run in runs))
        # Sorted by line number regardless of definition ordering.
        self.assertEqual([3, 5, 7], [r[0] for r in runs[0]])

    def test_clean_module_has_no_findings(self):
        results = _lint(
            """
            def read(name):
                validate_path(name)
                return open(name)
            """
        )
        self.assertEqual([], results)


if __name__ == "__main__":
    import unittest
    unittest.main()
