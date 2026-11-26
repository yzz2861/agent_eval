# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for offline cross-platform path contract checks."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from securesystemslib.exceptions import FormatError

from in_toto.contract_check import (
    ContractError,
    check_contract,
    load_contract,
    parse_contract,
    render_markdown,
)
from in_toto.in_toto_contract_check import main


def _contract(  # noqa: PLR0913
    products=None,
    materials=None,
    rules_before=None,
    rules_after=None,
    normalization_before=None,
    normalization_after=None,
    mapping=None,
    match_names_before="original",
    match_names_after="original",
):
    """Build a compact two-platform contract for tests."""
    products = products or [{"name": "src/App.py", "content": "app"}]
    rules = rules_after or rules_before or [["ALLOW", "*"], ["DISALLOW", "*"]]
    rules_before = rules_before or rules
    rules_after = rules_after or rules
    mapping = mapping or {}

    return {
        "schema_version": 1,
        "name": "test-contract",
        "platforms": [
            {
                "name": "linux",
                "path_style": "posix",
                "mapping": mapping.get("linux", {}),
            },
            {
                "name": "windows",
                "path_style": "windows",
                "mapping": mapping.get("windows", {}),
            },
        ],
        "cases": [
            {
                "name": "case",
                "steps": [
                    {
                        "name": "build",
                        "materials": materials or [],
                        "products": products,
                    }
                ],
                "target": {"step": "build", "type": "products"},
                "policies": {
                    "before": {
                        "match_names": match_names_before,
                        "normalization": normalization_before or {},
                        "rules": rules_before,
                    },
                    "after": {
                        "match_names": match_names_after,
                        "normalization": normalization_after or {},
                        "rules": rules_after,
                    },
                },
            }
        ],
    }


class TestParseContract(unittest.TestCase):
    """Test contract validation and default handling."""

    def test_minimal_contract_defaults(self):
        contract = parse_contract(_contract())
        self.assertEqual(contract["name"], "test-contract")
        self.assertEqual(contract["platforms"][0]["export_style"], "relative")
        self.assertTrue(contract["platforms"][0]["case_sensitive"])
        self.assertFalse(contract["platforms"][1]["case_sensitive"])
        self.assertEqual(
            contract["cases"][0]["policies"]["before"]["normalization"],
            {
                "unicode": "none",
                "case": "preserve",
                "separator": "native",
                "strip_prefixes": [],
            },
        )

    def test_bad_schema_version(self):
        data = _contract()
        data["schema_version"] = 2
        with self.assertRaises(ContractError):
            parse_contract(data)

    def test_duplicate_platform_names(self):
        data = _contract()
        data["platforms"][1]["name"] = "linux"
        with self.assertRaises(ContractError):
            parse_contract(data)

    def test_duplicate_case_names(self):
        data = _contract()
        data["cases"].append(data["cases"][0])
        with self.assertRaises(ContractError):
            parse_contract(data)

    def test_invalid_target_step(self):
        data = _contract()
        data["cases"][0]["target"]["step"] = "missing"
        with self.assertRaises(ContractError):
            parse_contract(data)

    def test_invalid_rule(self):
        data = _contract(rules_after=[["NOT_A_RULE", "*"]])
        with self.assertRaises(FormatError):
            parse_contract(data)

    def test_rule_string_is_split(self):
        data = _contract(rules_after=["ALLOW src/*.py"])
        contract = parse_contract(data)
        self.assertEqual(
            contract["cases"][0]["policies"]["after"]["rules"],
            [["ALLOW", "src/*.py"]],
        )

    def test_invalid_normalization(self):
        data = _contract(normalization_after={"unicode": "BAD"})
        with self.assertRaises(ContractError):
            parse_contract(data)

    def test_invalid_mapping(self):
        data = _contract()
        data["platforms"][0]["mapping"] = []
        with self.assertRaises(ContractError):
            parse_contract(data)


class TestCaseMatching(unittest.TestCase):
    """Test case, Unicode, root, and ambiguity vectors."""

    def test_case_insensitive_windows_diverges_then_normalizes(self):
        data = _contract(
            products=[{"name": "src/App.py", "content": "app"}],
            rules_before=[["ALLOW", "src/app.py"], ["DISALLOW", "*"]],
            rules_after=[["ALLOW", "src/app.py"], ["DISALLOW", "*"]],
            match_names_after="normalized",
            normalization_after={
                "case": "casefold",
                "separator": "slash",
            },
        )
        result = check_contract(parse_contract(data))
        case = result["cases"][0]
        self.assertEqual(
            case["cross_platform"]["before"]["status"], "DIVERGENT"
        )
        self.assertEqual(
            case["cross_platform"]["after"]["status"], "EQUIVALENT_PASS"
        )
        self.assertFalse(
            case["cross_platform"]["before"]["platforms"]["linux"]["passed"]
        )
        self.assertTrue(
            case["cross_platform"]["before"]["platforms"]["windows"]["passed"]
        )
        expanded = case["policy_change"]["expanded_rules"]
        self.assertEqual(expanded[0]["rule_index"], 0)
        self.assertEqual(expanded[0]["added"], ["src/App.py"])
        self.assertEqual(
            expanded[0]["platforms"]["linux"]["added"], ["src/App.py"]
        )
        self.assertEqual(expanded[0]["platforms"]["windows"]["added"], [])

    def test_unicode_nfc_nfd_diverges_then_normalizes(self):
        data = _contract(
            products=[{"name": "docs/caf\u00e9.txt", "content": "cafe"}],
            rules_before=[
                ["ALLOW", "docs/caf\u00e9.txt"],
                ["DISALLOW", "*"],
            ],
            rules_after=[
                ["ALLOW", "docs/caf\u00e9.txt"],
                ["DISALLOW", "*"],
            ],
            mapping={
                "linux": {"docs/caf\u00e9.txt": "docs/cafe\u0301.txt"},
                "windows": {"docs/caf\u00e9.txt": "docs\\caf\u00e9.txt"},
            },
            match_names_after="normalized",
            normalization_after={"unicode": "NFC", "separator": "slash"},
        )
        result = check_contract(parse_contract(data))
        case = result["cases"][0]
        self.assertEqual(
            case["cross_platform"]["before"]["status"], "DIVERGENT"
        )
        self.assertEqual(
            case["cross_platform"]["after"]["status"], "EQUIVALENT_PASS"
        )
        self.assertEqual(
            case["policy_change"]["expanded_rules"][0]["platforms"]["linux"][
                "added"
            ],
            ["docs/caf\u00e9.txt"],
        )

    def test_root_convention_diverges_then_strips_prefix(self):
        data = _contract(
            products=[{"name": "src/main.py", "content": "main"}],
            rules_before=[["ALLOW", "src/main.py"], ["DISALLOW", "*"]],
            rules_after=[["ALLOW", "src/main.py"], ["DISALLOW", "*"]],
            mapping={
                "linux": {"src/main.py": "./src/main.py"},
                "windows": {"src/main.py": "C:\\work\\src\\main.py"},
            },
            match_names_after="normalized",
            normalization_after={
                "separator": "slash",
                "strip_prefixes": ["C:/work/"],
            },
        )
        result = check_contract(parse_contract(data))
        case = result["cases"][0]
        self.assertEqual(
            case["cross_platform"]["before"]["status"], "DIVERGENT"
        )
        self.assertEqual(
            case["cross_platform"]["after"]["status"], "EQUIVALENT_PASS"
        )
        self.assertEqual(
            case["policy_change"]["expanded_rules"][0]["platforms"]["windows"][
                "added"
            ],
            ["src/main.py"],
        )

    def test_mapping_ambiguity_lists_candidates(self):
        data = _contract(
            products=[
                {"name": "src/README.md", "content": "upper"},
                {"name": "src/readme.md", "content": "lower"},
            ],
            rules_before=[["ALLOW", "src/README.md"], ["DISALLOW", "*"]],
            rules_after=[["ALLOW", "src/README.md"], ["DISALLOW", "*"]],
            mapping={
                "windows": {
                    "src/README.md": "src\\README.md",
                    "src/readme.md": "src\\readme.md",
                }
            },
        )
        result = check_contract(parse_contract(data))
        case = result["cases"][0]
        self.assertEqual(case["cross_platform"]["after"]["status"], "AMBIGUOUS")
        ambiguities = case["cross_platform"]["after"]["platforms"]["windows"][
            "ambiguities"
        ]
        collision = next(
            item
            for item in ambiguities
            if item["kind"] == "case-fold-collision"
        )
        self.assertTrue(collision["blocking"])
        self.assertEqual(
            [candidate["artifact"] for candidate in collision["candidates"]],
            ["src/README.md", "src/readme.md"],
        )

    def test_match_rule_with_prefixes(self):
        data = {
            "schema_version": 1,
            "name": "match-rule",
            "platforms": [
                {"name": "linux", "path_style": "posix"},
                {"name": "windows", "path_style": "windows"},
            ],
            "cases": [
                {
                    "name": "match",
                    "steps": [
                        {
                            "name": "build",
                            "materials": [],
                            "products": [
                                {"name": "src/lib/a.py", "content": "a"}
                            ],
                        },
                        {
                            "name": "package",
                            "materials": [
                                {"name": "src/lib/a.py", "content": "a"}
                            ],
                            "products": [],
                        },
                    ],
                    "target": {"step": "package", "type": "materials"},
                    "policies": {
                        "after": {
                            "match_names": "original",
                            "rules": [
                                [
                                    "MATCH",
                                    "*.py",
                                    "IN",
                                    "src/lib",
                                    "WITH",
                                    "PRODUCTS",
                                    "IN",
                                    "src/lib",
                                    "FROM",
                                    "build",
                                ],
                                ["DISALLOW", "*"],
                            ],
                        }
                    },
                }
            ],
        }
        result = check_contract(parse_contract(data))
        cross = result["cases"][0]["cross_platform"]["after"]
        self.assertEqual(cross["status"], "EQUIVALENT_PASS")
        record = cross["platforms"]["linux"]["rules"][0]
        self.assertEqual(record["matched"], ["src/lib/a.py"])
        self.assertEqual(record["consumed_canonical"], ["src/lib/a.py"])

    def test_match_rule_normalized_with_native_separator(self):
        data = {
            "schema_version": 1,
            "name": "match-rule-normalized",
            "platforms": [
                {"name": "linux", "path_style": "posix"},
                {"name": "windows", "path_style": "windows"},
            ],
            "cases": [
                {
                    "name": "match",
                    "steps": [
                        {
                            "name": "build",
                            "materials": [],
                            "products": [{"name": "lib/a.py", "content": "a"}],
                        },
                        {
                            "name": "package",
                            "materials": [{"name": "lib/a.py", "content": "a"}],
                            "products": [],
                        },
                    ],
                    "target": {"step": "package", "type": "materials"},
                    "policies": {
                        "after": {
                            "match_names": "normalized",
                            "rules": [
                                [
                                    "MATCH",
                                    "*.py",
                                    "IN",
                                    "lib",
                                    "WITH",
                                    "PRODUCTS",
                                    "IN",
                                    "lib",
                                    "FROM",
                                    "build",
                                ],
                                ["DISALLOW", "*"],
                            ],
                        }
                    },
                }
            ],
        }
        result = check_contract(parse_contract(data))
        cross = result["cases"][0]["cross_platform"]["after"]
        self.assertEqual(cross["status"], "EQUIVALENT_PASS")


class TestPolicyChange(unittest.TestCase):
    """Test expansion reporting."""

    def test_expansion_reports_added_and_removed(self):
        data = _contract(
            products=[
                {"name": "src/App.py", "content": "app"},
                {"name": "src/data.json", "content": "data"},
            ],
            rules_before=[["ALLOW", "src/*.py"], ["DISALLOW", "*"]],
            rules_after=[["ALLOW", "*"], ["DISALLOW", "*"]],
        )
        case = check_contract(parse_contract(data))["cases"][0]
        expansion = case["policy_change"]["expanded_rules"][0]
        self.assertEqual(expansion["rule_index"], 0)
        self.assertTrue(expansion["expanded"])
        self.assertEqual(expansion["added"], ["src/data.json"])

    def test_new_rule_expands_from_empty(self):
        data = _contract(
            products=[
                {"name": "src/App.py", "content": "app"},
                {"name": "src/data.json", "content": "data"},
            ],
            rules_before=[["ALLOW", "src/*.py"], ["DISALLOW", "*"]],
            rules_after=[
                ["ALLOW", "src/*.py"],
                ["ALLOW", "*.json"],
                ["DISALLOW", "*"],
            ],
        )
        case = check_contract(parse_contract(data))["cases"][0]
        expansions = {
            expansion["rule_index"]: expansion
            for expansion in case["policy_change"]["expanded_rules"]
        }
        self.assertEqual(expansions[1]["added"], ["src/data.json"])


class TestRenderReport(unittest.TestCase):
    """Test Markdown acceptance report rendering."""

    def test_report_contains_required_sections_and_unicode(self):
        data = _contract(
            products=[{"name": "docs/caf\u00e9.txt", "content": "cafe"}],
            rules_before=[
                ["ALLOW", "docs/caf\u00e9.txt"],
                ["DISALLOW", "*"],
            ],
            rules_after=[
                ["ALLOW", "docs/caf\u00e9.txt"],
                ["DISALLOW", "*"],
            ],
            mapping={"linux": {"docs/caf\u00e9.txt": "docs/cafe\u0301.txt"}},
            match_names_after="normalized",
            normalization_after={"unicode": "NFC"},
        )
        report = render_markdown(check_contract(parse_contract(data)))
        for text in [
            "## Verdict",
            "## Rule applicability",
            "## Mapping ambiguities",
            "## Policy change: expanded applicability",
            "Before policy",
            "After policy",
            "U+0301",
            "Expanded rules",
        ]:
            self.assertIn(text, report)


class TestExampleContract(unittest.TestCase):
    """Test the checked-in acceptance example end to end."""

    def test_example_verdicts(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "examples",
            "contract-check",
            "windows-linux-contract.json",
        )
        result = check_contract(load_contract(path))
        statuses = {
            case["name"]: {
                policy: case["cross_platform"][policy]["status"]
                for policy in case["cross_platform"]
            }
            for case in result["cases"]
        }
        self.assertEqual(
            statuses["case-variant"],
            {"before": "DIVERGENT", "after": "EQUIVALENT_PASS"},
        )
        self.assertEqual(
            statuses["unicode-equivalence"],
            {"before": "DIVERGENT", "after": "EQUIVALENT_PASS"},
        )
        self.assertEqual(
            statuses["root-convention"],
            {"before": "DIVERGENT", "after": "EQUIVALENT_PASS"},
        )
        self.assertEqual(
            statuses["material-product-match"],
            {"before": "EQUIVALENT_PASS", "after": "EQUIVALENT_PASS"},
        )
        self.assertEqual(
            statuses["mapping-ambiguity"],
            {"before": "AMBIGUOUS", "after": "AMBIGUOUS"},
        )


class TestCLI(unittest.TestCase):
    """Test the contract-check CLI."""

    def test_load_contract_and_report_only(self):
        data = _contract()
        with tempfile.TemporaryDirectory() as tmpdir:
            contract_path = os.path.join(tmpdir, "contract.json")
            output_path = os.path.join(tmpdir, "report.md")
            with open(contract_path, "w", encoding="utf-8") as fileobj:
                json.dump(data, fileobj)

            argv = [
                "in-toto-contract-check",
                contract_path,
                "--report-only",
                "-o",
                output_path,
            ]
            with patch.object(sys, "argv", argv):
                self.assertEqual(main(), 0)

            with open(output_path, encoding="utf-8") as fileobj:
                self.assertIn("Offline path contract", fileobj.read())

    def test_json_stdout_and_divergence_exit(self):
        data = _contract(
            rules_before=[["ALLOW", "src/app.py"], ["DISALLOW", "*"]],
            rules_after=[["ALLOW", "src/app.py"], ["DISALLOW", "*"]],
        )
        data["cases"][0]["policies"]["after"] = data["cases"][0]["policies"][
            "before"
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            contract_path = os.path.join(tmpdir, "contract.json")
            with open(contract_path, "w", encoding="utf-8") as fileobj:
                json.dump(data, fileobj)

            argv = [
                "in-toto-contract-check",
                contract_path,
                "--format",
                "json",
            ]
            stdout = io.StringIO()
            with patch.object(sys, "argv", argv), redirect_stdout(stdout):
                self.assertEqual(main(), 1)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["policy"], "after")


if __name__ == "__main__":
    unittest.main()
