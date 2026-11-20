import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import (
    Assessment,
    CallableRule,
    CVSSCaseInvalid,
    CVSSCaseNotFound,
    ProductEvaluation,
    ThresholdRule,
    VulnerabilityCase,
)

V3_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_LOWER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H"
V3_ENV = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"
V4_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
V2_VECTOR = "AV:N/AC:L/Au:N/C:P/I:P/A:P"


class TestAssessment(unittest.TestCase):
    def test_content_identity_distinct_versions_same_score_shape(self):
        # Equal numeric scores from different CVSS versions must stay distinct.
        a3 = Assessment(V3_HIGH, basis={"env": "three"})
        a4 = Assessment(V4_HIGH, basis={"env": "four"})
        self.assertNotEqual(a3.assessment_id, a4.assessment_id)
        self.assertEqual(a3.cvss_version, "3.1")
        self.assertEqual(a4.cvss_version, "4.0")
        self.assertNotEqual(a3, a4)

    def test_same_inputs_resolve_to_same_id(self):
        a1 = Assessment(V3_HIGH, basis={"env": "x", "id": 1})
        a2 = Assessment(V3_HIGH, basis={"id": 1, "env": "x"})
        self.assertEqual(a1.assessment_id, a2.assessment_id)
        self.assertEqual(a1, a2)
        self.assertEqual(hash(a1), hash(a2))

    def test_different_vector_or_basis_breaks_identity(self):
        base = Assessment(V3_HIGH, basis={"env": "x"})
        other_vector = Assessment(V3_LOWER, basis={"env": "x"})
        other_basis = Assessment(V3_HIGH, basis={"env": "y"})
        self.assertNotEqual(base.assessment_id, other_vector.assessment_id)
        self.assertNotEqual(base.assessment_id, other_basis.assessment_id)

    def test_assessment_is_immutable(self):
        assessment = Assessment(V3_HIGH)
        with self.assertRaises(AttributeError):
            assessment.vector = "tampered"
        with self.assertRaises(AttributeError):
            assessment.scores = (1.0,)

    def test_basis_is_defensively_copied(self):
        basis = {"env": "original"}
        assessment = Assessment(V3_HIGH, basis=basis)
        basis["env"] = "mutated-after"
        self.assertEqual(assessment.basis["env"], "original")

    def test_score_kinds_and_unsupported(self):
        a3 = Assessment(V3_ENV)
        self.assertEqual(a3.score("base"), a3.scores[0])
        self.assertEqual(a3.score("environmental"), a3.scores[2])
        a4 = Assessment(V4_HIGH)
        with self.assertRaises(CVSSCaseInvalid):
            a4.score("environmental")
        with self.assertRaises(CVSSCaseInvalid):
            a3.score("not-a-kind")

    def test_invalid_vector_and_basis(self):
        with self.assertRaises(CVSSCaseInvalid):
            Assessment("not-a-vector")
        with self.assertRaises(CVSSCaseInvalid):
            Assessment(V3_HIGH, basis=["not", "a", "dict"])
        with self.assertRaises(CVSSCaseInvalid):
            Assessment("  ")

    def test_cvss2_support(self):
        assessment = Assessment(V2_VECTOR)
        self.assertEqual(assessment.cvss_version, "2.0")
        self.assertEqual(assessment.score("base"), assessment.scores[0])

    def test_explicit_version_mismatch_rejected(self):
        with self.assertRaises(CVSSCaseInvalid):
            Assessment(V3_HIGH, cvss_version="4.0")


def build_case():
    case = VulnerabilityCase("CVE-X-1", title="three product lines")
    case.add_product("product-a", vector=V3_HIGH, basis={"env": "a", "ticket": "TA"})
    case.add_product("product-b", vector=V4_HIGH, basis={"env": "b", "ticket": "TB"})
    case.share_assessment("product-b", "product-c", note="shared base image")
    return case


class TestVulnerabilityCaseProducts(unittest.TestCase):
    def test_independent_product_assessments(self):
        case = build_case()
        ids = {name: case.get_product(name).assessment_id for name in case.products()}
        self.assertNotEqual(ids["product-a"], ids["product-b"])
        self.assertEqual(sorted(ids), ["product-a", "product-b", "product-c"])

    def test_shared_reference_uses_same_assessment_id(self):
        case = build_case()
        self.assertEqual(
            case.get_product("product-b").assessment_id,
            case.get_product("product-c").assessment_id,
        )
        refs = case.shared_references()
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["source_product"], "product-b")
        self.assertEqual(refs[0]["target_product"], "product-c")

    def test_duplicate_product_rejected_and_missing_lookup(self):
        case = build_case()
        with self.assertRaises(CVSSCaseInvalid):
            case.add_product("product-a", vector=V3_HIGH)
        with self.assertRaises(CVSSCaseNotFound):
            case.get_product("ghost")
        with self.assertRaises(CVSSCaseNotFound):
            case.share_assessment("ghost", "product-d")

    def test_identical_assessment_deduplicated_in_registry(self):
        case = VulnerabilityCase("CVE-X-2")
        first = case.add_assessment(V3_HIGH, basis={"env": "same"})
        second = case.add_assessment(V3_HIGH, basis={"env": "same"})
        self.assertIs(first, second)
        self.assertEqual(len(case._assessments), 1)

    def test_get_assessment_across_products(self):
        case = build_case()
        shared_id = case.get_product("product-c").assessment_id
        assessment = case.get_assessment(shared_id)
        self.assertEqual(assessment.assessment_id, shared_id)
        self.assertEqual(assessment.basis["env"], "b")
        with self.assertRaises(CVSSCaseNotFound):
            case.get_assessment("deadbeef")

    def test_add_product_with_explicit_assessment_object(self):
        case = VulnerabilityCase("CVE-X-3")
        assessment = Assessment(V3_HIGH, basis={"env": "explicit"})
        case.add_product("product-a", assessment=assessment)
        self.assertEqual(case.get_product("product-a").assessment_id, assessment.assessment_id)
        with self.assertRaises(CVSSCaseInvalid):
            case.add_product("product-b", assessment=assessment, vector=V3_HIGH)


class TestRemediation(unittest.TestCase):
    def test_remediate_one_environment_keeps_history(self):
        case = build_case()
        original_id = case.get_product("product-a").assessment_id
        new = case.remediate_environment(
            "product-a", V3_LOWER, basis={"env": "a-fixed"}, reason="rebuild"
        )
        evaluation = case.get_product("product-a")
        self.assertEqual(len(evaluation.revisions), 2)
        self.assertEqual(evaluation.assessment_id, new.assessment_id)
        # The previous independent assessment is still retrievable and reviewable.
        historical = evaluation.get_revision(original_id)
        self.assertEqual(historical.vector, V3_HIGH)
        reasons = [entry["reason"] for entry in evaluation.remediation_history]
        self.assertEqual(reasons, ["initial assessment", "rebuild"])

    def test_other_products_unaffected_by_remediation(self):
        case = build_case()
        before_b = case.get_product("product-b").assessment_id
        before_c = case.get_product("product-c").assessment_id
        case.remediate_environment("product-a", V3_LOWER, basis={"env": "a-fixed"})
        self.assertEqual(case.get_product("product-b").assessment_id, before_b)
        self.assertEqual(case.get_product("product-c").assessment_id, before_c)

    def test_revision_of_one_shared_product_does_not_touch_other(self):
        case = build_case()
        case.remediate_environment("product-c", V3_LOWER, basis={"env": "c-fixed"})
        self.assertNotEqual(
            case.get_product("product-c").assessment_id,
            case.get_product("product-b").assessment_id,
        )
        # product-b still points at the original shared assessment
        self.assertEqual(
            case.get_product("product-b").assessment_id,
            case.get_product("product-b").revisions[0].assessment_id,
        )

    def test_identical_revision_is_noop(self):
        case = build_case()
        evaluation = case.get_product("product-a")
        count = len(evaluation.revisions)
        evaluation.add_revision(evaluation.assessment, "no change")
        self.assertEqual(len(evaluation.revisions), count)

    def test_remediate_unknown_product(self):
        case = build_case()
        with self.assertRaises(CVSSCaseNotFound):
            case.remediate_environment("ghost", V3_LOWER)


class TestDisposition(unittest.TestCase):
    def test_threshold_rule_selects_only_qualifying_products(self):
        case = build_case()
        # product-a base is 9.8; product-b/c base is 10.0
        tickets = case.apply_disposition(ThresholdRule(9.9, name="critical-only"))
        queued_products = sorted(
            case._tickets[t].as_dict()["decision"]["product"] for t in case.tickets()
        )
        self.assertEqual(queued_products, ["product-b", "product-c"])
        self.assertEqual(len(tickets), 2)

    def test_ticket_explains_vector_basis_and_condition(self):
        case = build_case()
        tickets = case.apply_disposition(ThresholdRule(9.0, score_kind="base"))
        ticket = tickets[0]
        explanation = case.explain_ticket(ticket.ticket_id)
        self.assertEqual(explanation["case_id"], "CVE-X-1")
        self.assertEqual(explanation["cited_assessment"]["basis"]["ticket"], "TA")
        self.assertTrue(explanation["cited_assessment"]["vector"].startswith("CVSS:3.1"))
        self.assertEqual(explanation["disposition"]["rule_name"], "threshold-base-9.0")
        self.assertTrue(explanation["disposition"]["queued"])
        self.assertEqual(explanation["disposition"]["threshold"], 9.0)

    def test_ticket_still_explainable_after_later_remediation(self):
        case = build_case()
        tickets = case.apply_disposition(ThresholdRule(9.0))
        a_ticket = next(
            t for t in tickets
            if t.as_dict()["decision"]["product"] == "product-a"
        )
        cited_before = a_ticket.as_dict()["assessment"]["vector"]
        case.remediate_environment("product-a", V3_LOWER, basis={"env": "a-fixed"})
        explanation = case.explain_ticket(a_ticket.ticket_id)
        # Snapshot preserves the assessment that actually caused the queue entry.
        self.assertEqual(explanation["cited_assessment"]["vector"], cited_before)
        self.assertNotEqual(
            explanation["cited_assessment"]["vector"],
            explanation["current_assessment"]["vector"],
        )
        self.assertEqual(len(explanation["remediation_history"]), 2)

    def test_callable_rule_boolean_and_reason(self):
        case = VulnerabilityCase("CVE-X-4")
        case.add_product("p1", V3_HIGH, {"flag": True})
        case.add_product("p2", V3_LOWER, {"flag": False})

        rule = CallableRule(
            lambda product, assessment: assessment.basis.get("flag", False),
            name="flag-rule",
        )
        tickets = case.apply_disposition(rule)
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0].as_dict()["decision"]["product"], "p1")

    def test_callable_rule_tuple_reason(self):
        case = VulnerabilityCase("CVE-X-5")
        case.add_product("p1", V3_HIGH, {})

        def predicate(product, assessment):
            return True, "manual triage override"

        tickets = case.apply_disposition(CallableRule(predicate, name="manual"))
        self.assertEqual(
            tickets[0].as_dict()["decision"]["reason"], "manual triage override"
        )

    def test_non_queued_products_have_decisions_in_audit(self):
        case = build_case()
        case.apply_disposition(ThresholdRule(9.9))
        decisions = [e for e in case.audit_log() if e["action"] == "disposition_decision"]
        self.assertEqual(len(decisions), 3)
        queued = {e["product"]: e["queued"] for e in decisions}
        self.assertFalse(queued["product-a"])
        self.assertTrue(queued["product-b"])

    def test_invalid_rule_and_ticket_lookup(self):
        case = build_case()
        with self.assertRaises(CVSSCaseInvalid):
            case.apply_disposition("not-a-rule")
        with self.assertRaises(CVSSCaseInvalid):
            ThresholdRule(5.0, score_kind="bogus")
        with self.assertRaises(CVSSCaseNotFound):
            case.explain_ticket("CVE-X-1-T9999")

    def test_ticket_ids_are_stable_and_incrementing(self):
        case = build_case()
        first = case.apply_disposition(ThresholdRule(9.0))
        ids = [t.ticket_id for t in first]
        self.assertEqual(ids[0], "CVE-X-1-T0001")
        self.assertEqual(ids[-1], "CVE-X-1-T0003")

    def test_full_case_serialization_is_json_safe(self):
        import json
        case = build_case()
        case.apply_disposition(ThresholdRule(9.0))
        case.remediate_environment("product-a", V3_LOWER, basis={"env": "a-fixed"})
        payload = json.dumps(case.as_dict())
        restored = json.loads(payload)
        self.assertEqual(restored["case_id"], "CVE-X-1")
        self.assertTrue(restored["tickets"])
        self.assertTrue(restored["audit_log"])


if __name__ == "__main__":
    unittest.main()
