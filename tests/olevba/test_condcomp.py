"""
Tests for the static conditional-compilation view (oletools.condcomp).

These tests never launch Office or execute a macro: they only feed VBA source
text to the static analyzer.
"""

import json
import os
import time
import unittest
from os.path import join

from oletools import condcomp, olevba
from tests.test_utils import DATA_BASE_DIR, call_and_capture


SAMPLE = join(DATA_BASE_DIR, "olevba", "condcomp",
              "conditional_sample.bas")


def _sample_code():
    with open(SAMPLE, "r") as handle:
        return handle.read()


def _chain_targets(report):
    targets = {}
    for scenario in report.scenarios:
        lines = sorted(chain.target.line_no
                       for chain in scenario.chains)
        targets[scenario.scenario_id] = lines
    return targets


class TestExpressionParser(unittest.TestCase):
    def test_literals_and_symbols(self):
        self.assertEqual(condcomp.parse_expression("1").value, 1)
        self.assertEqual(condcomp.parse_expression("VBA7").name, "VBA7")
        self.assertTrue(condcomp.parse_expression("True").value)
        self.assertFalse(condcomp.parse_expression("False").value)

    def test_boolean_precedence(self):
        context = condcomp.EvalContext(env={"A": 1, "B": 0})
        tri, _ = condcomp.evaluate_condition(
            condcomp.parse_expression("A Or B And False"), context)
        self.assertEqual(tri, condcomp.TRUE)
        tri, _ = condcomp.evaluate_condition(
            condcomp.parse_expression("Not A And B"), context)
        self.assertEqual(tri, condcomp.FALSE)

    def test_arithmetic_and_comparison(self):
        context = condcomp.EvalContext(env={})
        tri, _ = condcomp.evaluate_condition(
            condcomp.parse_expression("2 + 2 = 4"), context)
        self.assertEqual(tri, condcomp.TRUE)
        tri, _ = condcomp.evaluate_condition(
            condcomp.parse_expression("3 > 10"), context)
        self.assertEqual(tri, condcomp.FALSE)

    def test_unknown_is_three_valued(self):
        context = condcomp.EvalContext(env={})
        tri, atom = condcomp.evaluate_condition(
            condcomp.parse_expression("Win64"), context)
        self.assertEqual(tri, condcomp.UNKNOWN)
        self.assertIsNotNone(atom)

    def test_broken_expression_raises(self):
        with self.assertRaises(condcomp.CCParseError):
            condcomp.parse_expression("VBA7 @@@ 1")


class TestConstAndNesting(unittest.TestCase):
    def test_module_const_is_resolved(self):
        code = ("#Const D = 1\nSub AutoOpen()\n#If D Then\nShell \"a\"\n"
                "#End If\nEnd Sub\n")
        report = condcomp.analyze_module(code, "M")
        self.assertEqual(report.unknown_constants, [])
        self.assertEqual(len(report.scenarios), 1)
        self.assertEqual(report.scenarios[0].chains[0].target.line_no, 4)

    def test_nested_branches_are_exclusive(self):
        code = _sample_code()
        report = condcomp.analyze_module(code, "M")
        for scenario in report.scenarios:
            target_lines = [c.target.line_no for c in scenario.chains]
            # Shell x64 (5), Shell x86 (7) and Kill (10) are mutually
            # exclusive: a single scenario can never contain two of them.
            self.assertLessEqual(len(set(target_lines)), 1)


class TestEnvironmentDrivenChains(unittest.TestCase):
    def test_win64_environment_reaches_x64_payload(self):
        report = condcomp.analyze_module(
            _sample_code(), "M", env={"VBA7": 1, "Win64": 1})
        # a fully specified conditional set gives one deterministic answer
        self.assertNotIn('VBA7', report.unknown_constants)
        self.assertNotIn('WIN64', report.unknown_constants)
        all_targets = [c.target.line_no for c in report.chains]
        self.assertIn(5, all_targets)
        self.assertNotIn(7, all_targets)
        self.assertNotIn(10, all_targets)

    def test_legacy_environment_reaches_kill(self):
        report = condcomp.analyze_module(
            _sample_code(), "M", env={"VBA7": 0})
        # VBA7 false always lands in the #Else branch, regardless of Win64
        for scenario in report.scenarios:
            for chain in scenario.chains:
                self.assertEqual(chain.target.line_no, 10)

    def test_same_sample_two_environments_diverge(self):
        win64 = condcomp.analyze_module(
            _sample_code(), "M", env={"VBA7": 1, "Win64": 1})
        legacy = condcomp.analyze_module(
            _sample_code(), "M", env={"VBA7": 0})
        win64_lines = sorted(set(c.target.line_no for c in win64.chains))
        legacy_lines = sorted(set(c.target.line_no for c in legacy.chains))
        self.assertEqual(win64_lines, [5])
        self.assertEqual(legacy_lines, [10])
        self.assertNotEqual(win64_lines, legacy_lines)

    def test_unknown_environment_does_not_fabricate_one_chain(self):
        report = condcomp.analyze_module(_sample_code(), "M")
        # unknown constants must be enumerated, not guessed
        self.assertIn("VBA7", report.unknown_constants)
        self.assertIn("WIN64", report.unknown_constants)
        self.assertGreater(len(report.scenarios), 1)
        possible = set()
        for scenario in report.scenarios:
            for chain in scenario.chains:
                possible.add(chain.target.line_no)
        # every mutually exclusive payload stays a separate possibility
        self.assertEqual(possible, {5, 7, 10})

    def test_chain_keeps_module_and_original_lines(self):
        report = condcomp.analyze_module(
            _sample_code(), "NamedModule", env={"VBA7": 1, "Win64": 1})
        chain = report.chains[0]
        self.assertEqual(chain.module_name, "NamedModule")
        self.assertEqual(chain.entry.line_no, 2)
        self.assertEqual(chain.target.line_no, 5)
        # line numbers point back at the raw source text
        self.assertEqual(_sample_code().splitlines()[4].strip(),
                         "Shell \"payload_x64.exe\"")


class TestIncompatibleBranches(unittest.TestCase):
    def test_mutually_exclusive_calls_never_join_one_chain(self):
        code = (
            "Sub AutoOpen()\n"
            "#If VBA7 Then\n"
            "    Shell \\\"a.exe\\\"\n"
            "#Else\n"
            "    Kill \\\"b.txt\\\"\n"
            "#End If\n"
            "End Sub\n")
        report = condcomp.analyze_module(code, "M")
        for scenario in report.scenarios:
            for chain in scenario.chains:
                # each chain ends in exactly one suspicious call, never both
                terminal = set(c.target.keyword for c in scenario.chains)
                self.assertEqual(len(terminal), 1)
        all_terminal = set()
        for scenario in report.scenarios:
            for chain in scenario.chains:
                all_terminal.add(chain.target.keyword)
        # across scenarios both possibilities remain on the table
        self.assertEqual(all_terminal, {"Shell", "Kill"})

    def test_cross_procedure_chain_respects_conditions(self):
        code = (
            "Sub AutoOpen()\n"
            "#If VBA7 Then\n"
            "    Call Payload\n"
            "#End If\n"
            "End Sub\n"
            "Sub Payload()\n"
            "    CreateObject(\\\"WScript.Shell\\\")\n"
            "End Sub\n")
        on = condcomp.analyze_module(code, "M", env={"VBA7": 1})
        off = condcomp.analyze_module(code, "M", env={"VBA7": 0})
        self.assertTrue(any(
            "Payload" in name for c in on.chains for name, _ in c.path))
        self.assertEqual(off.chains, [])


class TestSyntaxDamage(unittest.TestCase):
    def test_broken_directive_only_uncertain_in_region(self):
        code = (
            "Sub AutoOpen()\n"
            "#If VBA7 @@@ Then\n"
            "    Shell \\\"a.exe\\\"\n"
            "#End If\n"
            "    Kill \\\"b.txt\\\"\n"
            "End Sub\n")
        report = condcomp.analyze_module(code, "M")
        # the parse error is recorded but analysis still completes
        self.assertTrue(report.damage)
        self.assertEqual(report.damage[0][0], 2)
        # the line outside the broken frame is analysed normally
        outside = [h for h in report.keyword_hits
                   if h.line_no == 5 and h.keyword == "Kill"]
        self.assertEqual(len(outside), 1)
        # and the broken frame is flagged uncertain, not silently guessed
        self.assertTrue(any(getattr(s, "uncertain", False)
                            for s in report.scenarios))

    def test_unclosed_region_is_damaged_not_fatal(self):
        code = ("Sub AutoOpen()\n#If VBA7 Then\nShell \"a\"\nEnd Sub\n")
        report = condcomp.analyze_module(code, "M", env={'VBA7': 1})
        self.assertEqual(len(report.scenarios), 1)
        self.assertTrue(any(getattr(s, 'uncertain', False) for s in report.scenarios))

class TestPerformanceAndInterface(unittest.TestCase):
    def test_analysis_runs_in_under_two_seconds(self):
        start = time.time()
        condcomp.analyze_module(_sample_code(), "M")
        self.assertLess(time.time() - start, 2.0)

    def test_keyword_interface_still_available(self):
        # the classic flat keyword scan must keep working unchanged
        hits = olevba.scan_vba(_sample_code(), False)
        keywords = set(keyword for _type, keyword, _desc in hits)
        self.assertIn("AutoOpen", keywords)
        self.assertIn("Shell", keywords)

    def test_report_is_json_serializable(self):
        report = condcomp.analyze_vba_modules([("M", _sample_code())])
        encoded = json.dumps(report.to_dict())
        decoded = json.loads(encoded)
        self.assertEqual(decoded["modules"][0]["module"], "M")
        self.assertGreater(
            len(decoded["modules"][0]["scenarios"]), 1)

    def test_vba_parser_text_api(self):
        with open(SAMPLE, "rb") as handle:
            parser = olevba.VBA_Parser(SAMPLE, data=handle.read())
        try:
            report = parser.conditional_compilation_analysis(
                env={"VBA7": 1, "Win64": 1})
        finally:
            parser.close()
        targets = set(chain.target.line_no for chain in report.chains)
        self.assertEqual(targets, {5})


class TestCommandLine(unittest.TestCase):
    def test_cli_unknown_environment_is_explicit(self):
        output, ret_code = call_and_capture(
            "olevba", ("--cond-comp", "-a", SAMPLE))
        self.assertEqual(ret_code, 0)
        self.assertIn("Provided environment", output)
        self.assertIn("Scenario", output)
        # no single fabricated conclusion: several scenarios are listed
        self.assertGreaterEqual(output.count("Scenario "), 2)

    def test_cli_define_drives_the_chain(self):
        output, ret_code = call_and_capture(
            "olevba", ("--cond-comp", "-a", "--define", "VBA7=1",
                       "--define", "Win64=1", SAMPLE))
        self.assertEqual(ret_code, 0)
        self.assertIn("Shell", output)
        self.assertNotIn("Kill", output)

    def test_cli_json_mode(self):
        output, ret_code = call_and_capture(
            "olevba", ("--cond-comp", "-j", "--define", "VBA7=1",
                       "--define", "Win64=1", SAMPLE))
        self.assertEqual(ret_code, 0)
        decoded = json.loads(output)
        cc = [item["conditional_compilation"] for item in decoded
              if "conditional_compilation" in item][0]
        self.assertEqual(cc["env"]["WIN64"], 1)


if __name__ == "__main__":
    unittest.main()
