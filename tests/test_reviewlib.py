# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the optional artifact-usage review."""

import unittest
from pathlib import Path

from in_toto import reviewlib
from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.rulelib import (
    pack_review_rule,
    unpack_rule,
)
from in_toto.verifylib import verify_item_rules


CONFIG_HASH = {"sha256": "a" * 64}
RELEASE_HASH = {"sha256": "b" * 64}
TEST_HASH = {"sha256": "c" * 64}


def make_layout():
    """Return the sample layout with one copy and two downstream builds."""
    copy_step = Step(name="copy-config")
    copy_step.expected_materials = [
        ["MATCH", "base.toml", "WITH", "MATERIALS", "FROM", "copy-config"],
        ["DISALLOW", "*"],
    ]
    copy_step.expected_products = [
        ["ALLOW", "dist/*"],
        ["DISALLOW", "*"],
    ]

    release_step = Step(name="build-release")
    release_step.expected_materials = [
        [
            "MATCH",
            "base.toml",
            "IN",
            "dist/release",
            "WITH",
            "PRODUCTS",
            "IN",
            "dist/release",
            "FROM",
            "copy-config",
        ],
        ["DISALLOW", "*"],
    ]
    release_step.expected_products = [
        ["ALLOW", "release/*"],
        ["DISALLOW", "*"],
    ]

    test_step = Step(name="build-test")
    # This path uses the same content, but only an ALLOW rule. Approval does
    # not travel through this path.
    test_step.expected_materials = [
        ["ALLOW", "dist/test/base.toml"],
        ["DISALLOW", "*"],
    ]
    test_step.expected_products = [
        ["ALLOW", "test/*"],
        ["DISALLOW", "*"],
    ]

    return Layout(steps=[copy_step, release_step, test_step])


def make_links(include_test=True):
    """Return links with two identical downstream configuration files."""
    links = {
        "copy-config": Link(
            name="copy-config",
            materials={"reviewed/base.toml": CONFIG_HASH},
            products={
                "dist/release/base.toml": CONFIG_HASH,
                "dist/test/base.toml": CONFIG_HASH,
            },
        ),
        "build-release": Link(
            name="build-release",
            materials={"dist/release/base.toml": CONFIG_HASH},
            products={"release/app.bin": RELEASE_HASH},
        ),
    }
    if include_test:
        links["build-test"] = Link(
            name="build-test",
            materials={"dist/test/base.toml": CONFIG_HASH},
            products={"test/app.bin": TEST_HASH},
        )
    return links


def make_declarations():
    """Return declarations that approve release uses only."""
    return {
        "origin": "reviewed/base.toml",
        "approved_purposes": ["release"],
        "uses": {
            "build-release": "release",
            "build-test": "test",
        },
    }


class TestReviewMaterialUsage(unittest.TestCase):
    """Test the path-aware material usage review."""

    def setUp(self):
        self.layout = make_layout()
        self.links = make_links()
        self.declarations = make_declarations()

    def test_identical_downstream_files_trace_only_one_path(self):
        """Approval follows the release path, not the identical test path."""
        result = reviewlib.review_material_usage(
            self.layout, self.links, self.declarations
        )

        self.assertEqual(result.status, reviewlib.OUT_OF_SCOPE)
        self.assertEqual(result.uses["build-release"], reviewlib.IN_SCOPE)
        self.assertEqual(result.uses["build-test"], reviewlib.OUT_OF_SCOPE)

        # Both downstream copies exist and have the same content.
        self.assertEqual(
            self.links["copy-config"].products["dist/release/base.toml"],
            self.links["copy-config"].products["dist/test/base.toml"],
        )

        approve_edges = [
            edge
            for trace in result.traces
            for edge in trace["edges"]
            if edge["kind"] == "consume"
        ]
        self.assertEqual(len(approve_edges), 1)
        self.assertEqual(
            approve_edges[0]["to"]["path"], "dist/release/base.toml"
        )

    def test_out_of_scope_copy_retains_evidence(self):
        """The unapproved use is retained with path and rule evidence."""
        result = reviewlib.review_material_usage(
            self.layout, self.links, self.declarations
        )

        findings = [
            finding
            for finding in result.out_of_scope
            if finding.path == "dist/test/base.toml"
        ]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, "out_of_scope_use")
        self.assertEqual(
            finding.evidence["artifact"]["hashes"], CONFIG_HASH
        )
        rules = [
            entry["rule"] for entry in finding.evidence["matching_rules"]
        ]
        self.assertIn(["ALLOW", "dist/test/base.toml"], rules)

    def test_missing_step_input_is_unknown(self):
        """A missing link yields unknown, not an out-of-scope conclusion."""
        declarations = {
            "origin": "reviewed/base.toml",
            "approved_purposes": ["release"],
            "uses": {"build-test": "release"},
        }
        result = reviewlib.review_material_usage(
            self.layout,
            make_links(include_test=False),
            declarations,
        )

        self.assertEqual(result.status, reviewlib.UNKNOWN)
        self.assertEqual(result.uses["build-test"], reviewlib.UNKNOWN)
        self.assertIn("build-test", result.missing_steps)
        self.assertFalse(
            any(
                finding.path == "dist/test/base.toml"
                and finding.status == reviewlib.OUT_OF_SCOPE
                for finding in result.findings
            )
        )

    def test_review_rule_can_declare_purpose(self):
        """A REVIEW ... AS rule contributes a declared build use."""
        layout = make_layout()
        layout.steps[1].expected_materials.insert(
            0,
            [
                "REVIEW",
                "base.toml",
                "IN",
                "dist/release",
                "AS",
                "release",
            ],
        )
        layout.steps[2].expected_materials.insert(
            0,
            ["REVIEW", "base.toml", "IN", "dist/test", "AS", "test"],
        )

        result = reviewlib.review_material_usage(
            layout,
            self.links,
            {"origin": "reviewed/base.toml", "approved_purposes": ["release"]},
        )
        self.assertEqual(
            result.uses["build-release:dist/release/base.toml"],
            reviewlib.IN_SCOPE,
        )
        self.assertEqual(
            result.uses["build-test:dist/test/base.toml"],
            reviewlib.OUT_OF_SCOPE,
        )

    def test_missing_predecessor_product_is_unknown(self):
        """A MATCH rule whose input product is absent yields unknown."""
        layout = Layout(
            steps=[
                Step(name="copy-config"),
                Step(
                    name="build-test",
                    expected_materials=[
                        [
                            "MATCH",
                            "base.toml",
                            "IN",
                            "dist/test",
                            "WITH",
                            "PRODUCTS",
                            "IN",
                            "dist/test",
                            "FROM",
                            "copy-config",
                        ],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        links = {
            "copy-config": Link(
                name="copy-config",
                materials={"reviewed/base.toml": CONFIG_HASH},
                products={"dist/release/base.toml": CONFIG_HASH},
            ),
            "build-test": Link(
                name="build-test",
                materials={"dist/test/base.toml": CONFIG_HASH},
                products={},
            ),
        }
        declarations = {
            "origin": "reviewed/base.toml",
            "approved_purposes": ["release"],
            "uses": {"build-test": "release"},
        }
        result = reviewlib.review_material_usage(layout, links, declarations)
        self.assertEqual(result.status, reviewlib.UNKNOWN)
        self.assertEqual(result.uses["build-test"], reviewlib.UNKNOWN)
        self.assertTrue(
            any(
                finding.kind == "missing_step_input"
                and finding.path == "dist/test/base.toml"
                for finding in result.unknown
            )
        )

    def test_purpose_outside_approved_scope(self):
        """An otherwise approved path fails when its purpose is not approved."""
        declarations = dict(self.declarations)
        declarations["uses"] = {"build-release": "experiment"}

        result = reviewlib.review_material_usage(
            self.layout, self.links, declarations
        )
        self.assertEqual(result.status, reviewlib.OUT_OF_SCOPE)
        self.assertEqual(result.uses["build-release"], reviewlib.OUT_OF_SCOPE)

    def test_unknown_origin(self):
        """An origin that is absent from all links yields unknown."""
        declarations = {"origin": "missing/base.toml", "uses": {}}
        result = reviewlib.review_material_usage(
            self.layout, self.links, declarations
        )
        self.assertEqual(result.status, reviewlib.UNKNOWN)
        self.assertTrue(
            any(f.kind == "missing_origin" for f in result.unknown)
        )

    def test_result_dictionary_and_aliases(self):
        """Result is dictionary-like and aliases point to the same review."""
        result = reviewlib.review_material_usage(
            self.layout, self.links, self.declarations
        )
        self.assertEqual(result["status"], "out_of_scope")
        self.assertEqual(result["verdict"], reviewlib.OUT_OF_SCOPE)
        self.assertIn("findings", result)
        self.assertTrue(result)  # out of scope is still a valid review

        alias_result = reviewlib.review_artifact_scope(
            self.layout, self.links, self.declarations
        )
        self.assertEqual(alias_result.status, result.status)

    def test_nested_links_and_path_based_uses(self):
        """Nested functionary links and artifact-path uses are accepted."""
        links = {
            name: {"keyid": link} for name, link in self.links.items()
        }
        declarations = {
            "origin": "reviewed/base.toml",
            "approved_purposes": ["release"],
            "uses": {
                "dist/release/base.toml": "release",
                "dist/test/base.toml": "test",
            },
        }
        result = reviewlib.review_material_usage(
            self.layout, links, declarations
        )
        self.assertEqual(
            result.uses["dist/release/base.toml"], reviewlib.IN_SCOPE
        )
        self.assertEqual(
            result.uses["dist/test/base.toml"], reviewlib.OUT_OF_SCOPE
        )


class TestDemoReviewFiles(unittest.TestCase):
    """Exercise the checked-in sample that contains identical copies."""

    def test_sample_links_and_declarations(self):
        base = Path(__file__).parent / "demo_review_files"
        result = reviewlib.review_material_usage(
            base / "root.layout",
            base,
            base / "usage.json",
        )

        self.assertEqual(result.status, reviewlib.OUT_OF_SCOPE)
        self.assertEqual(result.uses["build-release"], reviewlib.IN_SCOPE)
        self.assertEqual(result.uses["build-test"], reviewlib.OUT_OF_SCOPE)
        self.assertEqual(
            (base / "dist/release/base.toml").read_bytes(),
            (base / "dist/test/base.toml").read_bytes(),
        )


class TestOptionalReviewRule(unittest.TestCase):
    """Test the optional, non-consuming REVIEW/AUDIT rule hints."""

    def setUp(self):
        self.links = {
            "item": Link(
                name="item",
                materials={"foo": CONFIG_HASH},
                products={"bar": RELEASE_HASH},
            )
        }

    def test_pack_and_unpack_review_rule(self):
        rule = ["REVIEW", "foo"]
        self.assertEqual(unpack_rule(rule)["rule_type"], "review")
        self.assertEqual(pack_review_rule("foo"), rule)

    def test_review_rule_does_not_change_verification(self):
        verify_item_rules(
            "item",
            "materials",
            [["REVIEW", "foo"], ["ALLOW", "foo"]],
            self.links,
        )


if __name__ == "__main__":
    unittest.main()
