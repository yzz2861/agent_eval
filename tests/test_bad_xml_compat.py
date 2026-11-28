#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import unittest

import dlint
import dlint.compat


def warning_tuple(warning):
    return (warning["lineno"], warning["col_offset"], warning["message"])


class BrokenXMLUseLinter(dlint.linters.BadXMLUseLinter):
    """Simulates a rule that silently stopped reporting warnings."""

    @property
    def illegal_modules(self):
        return []


class TestBadXMLCompatibility(dlint.test.base.BaseTest):

    def setUp(self):
        self.report = dlint.compat.probe()

    def test_fixture_warning_positions(self):
        for fixture in dlint.compat.FIXTURES:
            entry = self.report["fixtures"][fixture["name"]]
            self.assertTrue(entry["parse"]["ok"], fixture["name"])

            actual = [tuple(warning) for warning in entry["warnings"]]
            expected = [warning_tuple(w) for w in fixture["expected_warnings"]]

            self.assertEqual(actual, expected, fixture["name"])

    def test_preset_ast_paths(self):
        for fixture in dlint.compat.FIXTURES:
            tree = ast.parse(dlint.compat._source(fixture))

            for path, expected in fixture["node_paths"].items():
                node = dlint.compat.resolve_node_path(tree, path)
                self.assertEqual(type(node).__name__, expected, path)

    def test_plugin_record_format(self):
        self.assertEqual(
            list(dlint.linters.base.Flake8Result._fields),
            dlint.compat.RESULT_FIELDS,
        )

        for fixture in dlint.compat.FIXTURES:
            entry = self.report["fixtures"][fixture["name"]]

            for record in entry["plugin"]:
                self.assertEqual(len(record), 4)
                self.assertIsInstance(record[0], int)
                self.assertIsInstance(record[1], int)
                self.assertIsInstance(record[2], dlint.compat.string_types)
                self.assertEqual(record[3], "BadXMLUseLinter")

            self.assertEqual(
                [list(record[:3]) for record in entry["plugin"]],
                entry["warnings"],
            )

    def test_parse_failure_is_not_a_coverage_gap(self):
        fixture = {
            "name": "broken_syntax",
            "source": "from xml import\n",
            "expected_warnings": [
                {
                    "lineno": 1,
                    "col_offset": 0,
                    "message": dlint.compat.XML_MESSAGE,
                },
            ],
            "node_paths": {},
        }
        baseline = dlint.compat.probe(fixtures=(fixture,))
        candidate = dlint.compat.probe(fixtures=(fixture,))
        findings = dlint.compat.compare_reports(
            baseline,
            candidate,
            fixtures=(fixture,),
        )

        categories = [finding["category"] for finding in findings]

        self.assertIn(dlint.compat.PARSE_ERROR, categories)
        self.assertNotIn(dlint.compat.COVERAGE_GAP, categories)

    def test_missing_rule_warning_is_a_coverage_gap(self):
        baseline = dlint.compat.probe()
        candidate = dlint.compat.probe(linter_class=BrokenXMLUseLinter)
        findings = dlint.compat.compare_reports(baseline, candidate)

        categories = [finding["category"] for finding in findings]

        self.assertIn(dlint.compat.COVERAGE_GAP, categories)
        self.assertNotIn(dlint.compat.PARSE_ERROR, categories)

    def test_failure_categories_have_distinct_exit_codes(self):
        self.assertEqual(
            dlint.compat._finding_exit_code(
                [{"category": dlint.compat.PARSE_ERROR}]
            ),
            dlint.compat.PARSE_FAILURE_EXIT,
        )
        self.assertEqual(
            dlint.compat._finding_exit_code(
                [{"category": dlint.compat.COVERAGE_GAP}]
            ),
            dlint.compat.HARD_FAILURE_EXIT,
        )
        self.assertEqual(
            dlint.compat._finding_exit_code(
                [{"category": dlint.compat.MANUAL_REVIEW}]
            ),
            0,
        )

    def test_available_interpreters_keep_duo107_coverage(self):
        interpreters = dlint.compat.discover_interpreters()
        versions = set(tuple(item["version"]) for item in interpreters)
        if len(versions) < 2:
            self.skipTest("need at least two Python versions")

        report = dlint.compat.run_probe()
        categories = set(
            finding["category"] for finding in report["findings"]
        )

        self.assertNotIn(dlint.compat.PARSE_ERROR, categories)
        self.assertNotIn(dlint.compat.COVERAGE_GAP, categories)
        self.assertNotIn(dlint.compat.RESULT_DRIFT, categories)
        self.assertNotIn(dlint.compat.SHAPE_DRIFT, categories)
        self.assertNotIn(dlint.compat.PLUGIN_FORMAT, categories)
        self.assertNotIn(dlint.compat.WORKER_ERROR, categories)


if __name__ == "__main__":
    unittest.main()
