import unittest

from cpe.cpe2_3_fs import CPE2_3_FS
from cpe.cpelang2_3 import CPELanguage2_3
from cpe.cpeset2_3 import CPESet2_3
from cpe.applicability import (
    ApplicabilityEvaluator,
    AssetInventory,
    Verdict,
)


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



class TestSameDeploymentRequirement(unittest.TestCase):
    """The app and the runtime must coexist in one deployment."""

    def _and_expression(self):
        return CPELanguage2_3(_expression(_fact(SOLARIS_59) + _fact(WEBLOGIC)))

    def test_components_split_across_deployments_are_not_applicable(self):
        production = AssetInventory("P-1001", [SOLARIS_59], ["a", "o"])
        disaster_recovery = AssetInventory("D-2002", [WEBLOGIC], ["a", "o"])

        assessment = self._and_expression().assess_applicability(
            [production, disaster_recovery])

        self.assertIs(assessment.verdict, Verdict.EXCLUDED)
        self.assertEqual(assessment.matched_assets, [])
        self.assertIs(
            assessment.assets["P-1001"].verdict, Verdict.EXCLUDED)
        self.assertIs(
            assessment.assets["D-2002"].verdict, Verdict.EXCLUDED)

    def test_products_coexisting_in_one_deployment_match(self):
        production = AssetInventory(
            "P-1001", [SOLARIS_59, WEBLOGIC], ["a", "o"])
        disaster_recovery = AssetInventory("D-2002", [WEBLOGIC], ["a", "o"])

        assessment = self._and_expression().assess_applicability(
            [production, disaster_recovery])

        self.assertIs(assessment.verdict, Verdict.MATCH)
        self.assertEqual(assessment.matched_assets, ["P-1001"])

    def test_same_named_product_instances_stay_scoped_to_asset(self):
        production = AssetInventory(
            "P-1001", [SOLARIS_59, WEBLOGIC], ["a", "o"])
        disaster_recovery = AssetInventory(
            "D-2002", [WEBLOGIC, WEBLOGIC_OTHER], ["a", "o"])

        assessment = self._and_expression().assess_applicability(
            [production, disaster_recovery])

        weblogic_branch = assessment.assets["D-2002"].children[1]
        self.assertIs(weblogic_branch.verdict, Verdict.MATCH)
        for evidence in weblogic_branch.evidence:
            self.assertEqual(evidence.asset_id, "D-2002")
        self.assertIs(
            assessment.assets["D-2002"].verdict, Verdict.EXCLUDED)


class TestNegation(unittest.TestCase):
    """Negation and nested negation use the three-valued semantics."""

    def test_negated_present_fact_is_excluded(self):
        expression = CPELanguage2_3(_expression(_fact(WEBLOGIC, negate=True)))
        inventory = AssetInventory("A-1", [WEBLOGIC], ["a"])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(assessment.verdict, Verdict.EXCLUDED)
        branch = assessment.assets["A-1"].children[0]
        self.assertTrue(branch.negated)
        self.assertTrue(branch.children[0].evidence[0].negated)

    def test_negated_absent_fact_on_covered_part_matches(self):
        expression = CPELanguage2_3(_expression(_fact(WEBLOGIC, negate=True)))
        inventory = AssetInventory("A-1", [WEBLOGIC_OTHER], ["a"])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(assessment.verdict, Verdict.MATCH)

    def test_negated_fact_on_uncovered_part_stays_unknown(self):
        expression = CPELanguage2_3(_expression(_fact(WEBLOGIC, negate=True)))
        inventory = AssetInventory("A-1", [])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(
            assessment.verdict, Verdict.INSUFFICIENT_EVIDENCE)

    def test_double_negation_recovers_original_verdict(self):
        inner = _fact(WEBLOGIC, negate=True)
        double_negation = (
            '<cpe:logical-test operator="OR" negate="TRUE">'
            + inner +
            "</cpe:logical-test>"
        )
        expression = CPELanguage2_3(_expression(double_negation))
        present = AssetInventory("A-1", [WEBLOGIC], ["a"])
        missing = AssetInventory("A-2", [WEBLOGIC_OTHER], ["a"])

        self.assertIs(
            expression.assess_applicability(present).verdict,
            Verdict.MATCH)
        self.assertIs(
            expression.assess_applicability(missing).verdict,
            Verdict.EXCLUDED)


class TestPartialInventory(unittest.TestCase):
    """Only fully inventoried parts can produce a hard exclusion."""

    def test_uncovered_missing_part_is_insufficient_evidence(self):
        expression = CPELanguage2_3(
            _expression(_fact(SOLARIS_59) + _fact(WEBLOGIC)))
        inventory = AssetInventory("A-1", [WEBLOGIC])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(
            assessment.verdict, Verdict.INSUFFICIENT_EVIDENCE)
        os_branch = assessment.assets["A-1"].children[0]
        self.assertEqual(
            os_branch.children[0].evidence[0].kind, "coverage")

    def test_covered_missing_part_is_excluded(self):
        expression = CPELanguage2_3(
            _expression(_fact(SOLARIS_59) + _fact(WEBLOGIC)))
        inventory = AssetInventory("A-1", [WEBLOGIC], ["a", "o"])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(assessment.verdict, Verdict.EXCLUDED)
        os_branch = assessment.assets["A-1"].children[0]
        self.assertEqual(
            os_branch.children[0].evidence[0].kind, "absence")

    def test_or_branch_with_one_unknown_stays_unknown(self):
        expression = CPELanguage2_3(
            _expression(_fact(SOLARIS_58) + _fact(SOLARIS_59)))
        inventory = AssetInventory("A-1", [])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(
            assessment.verdict, Verdict.INSUFFICIENT_EVIDENCE)

    def test_or_branch_excluded_when_whole_part_covered(self):
        expression = CPELanguage2_3(
            _expression(_fact(SOLARIS_58) + _fact(SOLARIS_59)))
        inventory = AssetInventory(
            "A-1", ["cpe:2.3:o:sun:sunos:5.11:*:*:*:*:*:*:*"], ["o"])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(assessment.verdict, Verdict.EXCLUDED)

    def test_single_inventory_input_is_accepted(self):
        expression = CPELanguage2_3(_expression(_fact(WEBLOGIC)))
        inventory = AssetInventory("A-1", [WEBLOGIC], ["a"])

        assessment = expression.assess_applicability(inventory)

        self.assertIs(assessment.verdict, Verdict.MATCH)
        self.assertEqual(assessment.matched_assets, ["A-1"])


class TestBooleanInterfaceUnchanged(unittest.TestCase):
    """The legacy boolean matcher keeps its original contract."""

    def _set(self, names):
        cpeset = CPESet2_3()
        for name in names:
            cpeset.append(CPE2_3_FS(name))
        return cpeset

    def test_language_match_still_returns_boolean(self):
        expression = CPELanguage2_3(
            _expression(_fact(SOLARIS_59) + _fact(WEBLOGIC)))

        matched = self._set([SOLARIS_59, WEBLOGIC])
        self.assertIs(expression.language_match(matched), True)

        unmatched = self._set([WEBLOGIC])
        self.assertIs(expression.language_match(unmatched), False)

    def test_assessment_and_boolean_agree_on_positive_case(self):
        expression = CPELanguage2_3(_expression(_fact(WEBLOGIC)))
        cpeset = self._set([WEBLOGIC])
        inventory = AssetInventory("A-1", [WEBLOGIC], ["a"])

        self.assertIs(expression.language_match(cpeset), True)
        self.assertIs(
            expression.assess_applicability(inventory).is_applicable, True)


class TestEvaluatorAndSerialization(unittest.TestCase):
    """Direct evaluator use and plain dictionary export."""

    def test_evaluator_reports_three_verdicts_in_one_run(self):
        expression = CPELanguage2_3(
            _expression(_fact(SOLARIS_59) + _fact(WEBLOGIC)))
        inventories = [
            AssetInventory("ok", [SOLARIS_59, WEBLOGIC], ["a", "o"]),
            AssetInventory("gap", [WEBLOGIC]),
            AssetInventory("no", [WEBLOGIC_OTHER], ["a", "o"]),
        ]

        assessment = ApplicabilityEvaluator(expression).assess(inventories)

        self.assertIs(assessment.verdict, Verdict.MATCH)
        self.assertIs(assessment.assets["ok"].verdict, Verdict.MATCH)
        self.assertIs(
            assessment.assets["gap"].verdict,
            Verdict.INSUFFICIENT_EVIDENCE)
        self.assertIs(assessment.assets["no"].verdict, Verdict.EXCLUDED)
        self.assertEqual(assessment.matched_assets, ["ok"])
        self.assertEqual(assessment.unknown_assets, ["gap"])

    def test_as_dict_is_json_friendly(self):
        import json

        expression = CPELanguage2_3(_expression(_fact(WEBLOGIC)))
        inventory = AssetInventory("A-1", [WEBLOGIC], ["a"])

        payload = expression.assess_applicability(inventory).as_dict()
        encoded = json.dumps(payload)

        self.assertIn("match", encoded)
        self.assertEqual(payload["matched_assets"], ["A-1"])
        root = payload["assets"]["A-1"]
        fact = root["children"][0]["children"][0]
        self.assertIn("evidence", fact)


if __name__ == "__main__":
    unittest.main()
