"""Tests for offline approval independence checks."""

from __future__ import annotations

import copy
import json
import unittest

from securesystemslib.independence_check import (
    attach_independence_check,
    audit_independence,
    canonical_json,
    recompute_independence,
    verify_offline_attestation,
)
from securesystemslib.independence_sample import create_shared_substitute_sample


class SharedSubstituteIndependenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sample = create_shared_substitute_sample()
        self.bundle = self.sample.bundle

    def test_naive_signature_counts_pass_but_independence_is_absent(self) -> None:
        result = audit_independence(self.bundle)

        self.assertEqual(4, len(result.verification_results))
        self.assertTrue(all(item["valid"] for item in result.verification_results))
        self.assertEqual([2, 2], [group["threshold"] for group in result.group_reports])
        self.assertEqual(
            [2, 2],
            [group["candidate_signature_count"] for group in result.group_reports],
        )

        self.assertFalse(result.feasible)
        self.assertFalse(result.ok)
        self.assertEqual(1, result.shortfall)
        self.assertEqual("independent_signoff_absent", result.absence)
        self.assertEqual(1, len(result.absences))
        self.assertIn(
            "person.chen", result.absences[0]["blocking_shared_principal_ids"]
        )

        chen = next(
            person
            for person in result.shared_principals
            if person["principal_id"] == "person.chen"
        )
        self.assertEqual({"data", "compliance"}, set(chen["group_ids"]))
        self.assertTrue(chen["would_violate_independence_if_counted_for_both"])
        self.assertFalse(chen["assignment_conflict"])

        assigned_principals = [
            item["principal_id"]
            for items in result.assignment.values()
            for item in items
        ]
        self.assertEqual(len(assigned_principals), len(set(assigned_principals)))
        self.assertEqual(3, result.assigned_seats)

        chen_candidates = [
            candidate
            for candidate in result.candidates
            if candidate["principal_id"] == "person.chen"
        ]
        self.assertEqual(2, len(chen_candidates))
        self.assertTrue(
            any(
                alias.get("normalized") == "chen.che"
                for candidate in chen_candidates
                for alias in candidate["alias_evidence"]
            )
        )
        self.assertTrue(
            any(
                shift["kind"] == "substitute"
                and shift["substitute_for"] == "person.wang"
                for candidate in chen_candidates
                for shift in candidate["shift_evidence"]
            )
        )

        overlap = chen["cross_group_time_overlaps"][0]
        self.assertEqual({"data", "compliance"}, set(overlap["group_ids"]))
        self.assertIn("SRC-DATA-SUBSTITUTE", overlap["source_refs"])
        self.assertIn("SRC-SHARED-ONCALL", overlap["source_refs"])
        self.assertIn("SRC-TIME-OVERLAP-REVIEW", overlap["source_refs"])
        self.assertTrue(result.provenance["complete"], result.provenance)

        attached = attach_independence_check(self.bundle)
        self.assertFalse(attached.feasible)
        self.assertEqual(result.report_digest, attached.report_digest)

    def test_independent_signoff_makes_same_sample_reachable(self) -> None:
        self.sample.add_independent_signoff()
        result = audit_independence(self.bundle)

        self.assertTrue(result.feasible)
        self.assertTrue(result.satisfiable)
        self.assertTrue(result.threshold_reachable)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(0, result.shortfall)
        self.assertEqual("none", result.absence)
        self.assertEqual([], result.absences)
        self.assertEqual(4, result.assigned_seats)

        for group_report in result.group_reports:
            self.assertEqual(2, group_report["assigned_count"])
            self.assertTrue(group_report["threshold_met"])

        data_people = {item["principal_id"] for item in result.assignment["data"]}
        compliance_people = {
            item["principal_id"] for item in result.assignment["compliance"]
        }
        self.assertEqual({"person.chen", "person.lin"}, data_people)
        self.assertEqual({"person.zhao", "person.zhou"}, compliance_people)
        self.assertTrue(data_people.isdisjoint(compliance_people))
        self.assertFalse(
            any(person["assignment_conflict"] for person in result.shared_principals)
        )

        recomputed = recompute_independence(copy.deepcopy(self.bundle))
        self.assertEqual(result.report_digest, recomputed.report_digest)
        attestation = verify_offline_attestation(self.bundle, result)
        self.assertTrue(attestation["valid"], attestation)

        json_bundle = json.loads(canonical_json(self.bundle))
        json_result = audit_independence(json_bundle)
        self.assertEqual(result.inputs_digest, json_result.inputs_digest)
        self.assertEqual(result.report_digest, json_result.report_digest)

    def test_tampered_signature_breaks_offline_attestation(self) -> None:
        original = audit_independence(self.bundle)
        tampered = copy.deepcopy(self.bundle)
        tampered["approval_groups"][0]["signatures"][0]["sig"] = "00" * 64

        result = audit_independence(tampered)
        self.assertFalse(result.ok)
        self.assertGreaterEqual(
            sum(1 for item in result.verification_results if not item["valid"]), 1
        )
        verification = verify_offline_attestation(tampered, original)
        self.assertFalse(verification["valid"])


if __name__ == "__main__":
    unittest.main()
