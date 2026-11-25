import copy
import unittest
import json
import os

from cpe.cpelang2_3 import CPELanguage2_3
from cpe.applicability import (
    AssetInventory,
    Verdict,
)


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")

SOLARIS_58 = "cpe:2.3:o:sun:solaris:5.8:*:*:*:*:*:*:*"
SOLARIS_59 = "cpe:2.3:o:sun:solaris:5.9:*:*:*:*:*:*:*"
WEBLOGIC = "cpe:2.3:a:bea:weblogic:8.1:*:*:*:*:*:*:*"
WEBLOGIC_OTHER = "cpe:2.3:a:bea:weblogic:9.0:*:*:*:*:*:*:*"


def _expression(body):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cpe:platform-specification '
        'xmlns:cpe="http://cpe.mitre.org/language/2.0">'
        '<cpe:platform id="p1"><cpe:logical-test operator="AND" '
        'negate="FALSE">{0}</cpe:logical-test>'
        "</cpe:platform></cpe:platform-specification>"
    ).format(body)


def _fact(name, negate=False):
    return (
        '<cpe:logical-test operator="OR" negate="{0}">'
        '<cpe:fact-ref name="{1}" />'
        "</cpe:logical-test>"
    ).format("TRUE" if negate else "FALSE", name)


def _load_dual_deployment():
    path = os.path.join(FIXTURE_DIR,
                        "applicability_dual_deployment.json")
    with open(path) as handle:
        return json.load(handle)


def _inventories(payload):
    return [
        AssetInventory(
            item["asset_id"],
            item["components"],
            item["covered_parts"],
        )
        for item in payload["inventories"]
    ]


class TestDualDeployment(unittest.TestCase):
    def setUp(self):
        self.payload = _load_dual_deployment()
        self.expression = CPELanguage2_3(
            os.path.join(FIXTURE_DIR, "advisory_solaris_weblogic.xml"),
            isFile=True,
        )

    def test_production_matches_disaster_recovery_unknown(self):
        assessment = self.expression.assess_applicability(
            _inventories(self.payload))

        self.assertIs(assessment.verdict, Verdict.MATCH)
        self.assertTrue(assessment.is_applicable)
        self.assertEqual(assessment.matched_assets, ["P-1001"])
        self.assertEqual(assessment.unknown_assets, ["D-2002"])
        self.assertIs(assessment.assets["P-1001"].verdict, Verdict.MATCH)
        self.assertIs(assessment.assets["D-2002"].verdict,
                      Verdict.INSUFFICIENT_EVIDENCE)

    def test_disaster_recovery_gap_is_coverage_evidence(self):
        assessment = self.expression.assess_applicability(
            _inventories(self.payload))
        dr_root = assessment.assets["D-2002"]
        os_branch = dr_root.children[0]

        self.assertIs(os_branch.verdict, Verdict.INSUFFICIENT_EVIDENCE)
        kinds = {
            evidence.kind
            for child in os_branch.children
            for evidence in child.evidence
        }
        self.assertEqual(kinds, {"coverage"})
        for child in os_branch.children:
            self.assertEqual(
                child.evidence[0].asset_id, "D-2002")

    def test_moving_environment_evidence_changes_verdict_and_asset(self):
        moved = copy.deepcopy(self.payload)
        inventories = moved["inventories"]

        for inventory in inventories:
            inventory["components"] = [
                component for component in inventory["components"]
                if component != SOLARIS_59
            ]

        inventories[0]["covered_parts"] = ["a", "o"]
        inventories[1]["components"].append(SOLARIS_59)
        inventories[1]["covered_parts"] = ["a", "o"]

        assessment = self.expression.assess_applicability(
            _inventories(moved))

        self.assertIs(assessment.verdict, Verdict.MATCH)
        self.assertEqual(assessment.matched_assets, ["D-2002"])
        self.assertEqual(assessment.unknown_assets, [])
        self.assertIs(assessment.assets["P-1001"].verdict,
                      Verdict.EXCLUDED)

