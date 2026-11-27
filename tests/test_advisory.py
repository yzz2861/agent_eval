import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import (
    AdvisoryScoring,
    AdvisoryScoringError,
    ReceiptConflictError,
    ReceiptValidationError,
    RevisionReceipt,
    StaleReceiptError,
)
from cvss.cvss3 import CVSS3

BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


class TestAdvisoryScoring(unittest.TestCase):
    def setUp(self):
        self.ledger = AdvisoryScoring("RHSA-TEST", BASE_VECTOR)

    def test_initial_state_uses_cvss_recalculation_entry(self):
        result = self.ledger.current_result()
        expected = CVSS3(BASE_VECTOR)
        self.assertEqual(0, self.ledger.vector_version)
        self.assertEqual(expected.clean_vector(), result["vector"])
        self.assertEqual(expected.scores()[0], result["base_score"])
        self.assertEqual(expected.severities()[0], result["severity"])
        self.assertEqual("High", result["severity"])
        self.assertEqual(7.5, result["base_score"])

    def test_interleaved_compatible_revisions_coexist_and_recalculate(self):
        impact = RevisionReceipt("R1", "responder-a", {"I": "L"}, 0, 1)
        premise = RevisionReceipt("R2", "responder-b", {"AV": "A"}, 0, 2)

        first = self.ledger.submit(impact)
        second = self.ledger.submit(premise)

        self.assertEqual("accepted", first["kind"])
        self.assertEqual("accepted", second["kind"])
        self.assertEqual(2, self.ledger.vector_version)
        self.assertEqual(0, first["payload"]["base_version"])
        self.assertEqual(0, second["payload"]["base_version"])

        merged = self.ledger.current_result()
        self.assertEqual("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", merged["vector"])
        self.assertEqual(8.2, first["payload"]["base_score"])
        self.assertEqual(7.1, second["payload"]["base_score"])
        self.assertEqual("High", second["payload"]["severity"])

    def test_each_accepted_receipt_records_base_vector_version(self):
        first = self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        second = self.ledger.submit(RevisionReceipt("R2", "b", {"AV": "A"}, 0, 2))

        self.assertEqual(0, first["payload"]["base_version"])
        self.assertEqual(0, second["payload"]["base_version"])
        self.assertEqual(1, first["payload"]["vector_version"])
        self.assertEqual(2, second["payload"]["vector_version"])
        kinds = [event["kind"] for event in self.ledger.journal()]
        self.assertEqual(["initialized", "accepted", "accepted"], kinds)

    def test_duplicate_delivery_is_idempotent(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        redelivered = RevisionReceipt("R1", "a", {"I": "L"}, 0, 2)

        duplicate = self.ledger.submit(redelivered)

        self.assertEqual("duplicate", duplicate["kind"])
        self.assertEqual(1, duplicate["payload"]["original_seq"])
        self.assertEqual(1, self.ledger.vector_version)
        accepted = [e for e in self.ledger.journal() if e["kind"] == "accepted"]
        self.assertEqual(1, len(accepted))
        self.assertEqual(8.2, self.ledger.current_result()["base_score"])

    def test_deliver_processes_receipts_in_transport_seq_order(self):
        impact = RevisionReceipt("R1", "a", {"I": "L"}, 0, 1)
        premise = RevisionReceipt("R2", "b", {"AV": "A"}, 0, 2)
        redelivery = RevisionReceipt("R1", "a", {"I": "L"}, 0, 3)

        results = self.ledger.deliver(redelivery, premise, impact)

        self.assertEqual(["accepted", "accepted", "duplicate"], [e["kind"] for e in results])
        self.assertEqual(2, self.ledger.vector_version)
        self.assertEqual(7.1, self.ledger.current_result()["base_score"])

    def test_conflicting_same_field_revision_is_rejected(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        conflicting = RevisionReceipt("R2", "c", {"I": "H"}, 1, 2)

        with self.assertRaises(ReceiptConflictError):
            self.ledger.submit(conflicting)

        rejected = [e for e in self.ledger.journal() if e["kind"] == "rejected"]
        self.assertEqual(1, len(rejected))
        detail = rejected[0]["payload"]["conflicts"][0]
        self.assertEqual("I", detail["metric"])
        self.assertEqual("H", detail["submitted_value"])
        self.assertEqual("L", detail["current_value"])
        self.assertEqual("R1", detail["owner_receipt"])
        self.assertEqual(1, self.ledger.vector_version)
        self.assertEqual(8.2, self.ledger.current_result()["base_score"])

    def test_same_value_resubmission_on_owned_field_is_allowed(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        repeated = self.ledger.submit(RevisionReceipt("R2", "a", {"I": "L"}, 1, 2))

        self.assertEqual("accepted", repeated["kind"])
        self.assertEqual({}, dict(repeated["payload"]["changed"]))
        self.assertEqual(8.2, self.ledger.current_result()["base_score"])

    def test_future_base_version_is_rejected_as_stale(self):
        future = RevisionReceipt("R9", "a", {"I": "L"}, 99, 1)
        with self.assertRaises(StaleReceiptError):
            self.ledger.submit(future)
        self.assertEqual(0, self.ledger.vector_version)

    def test_old_base_version_on_changed_metric_is_stale(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        # Same displayed value, so there is no value conflict, but the responder never saw R1.
        stale = RevisionReceipt("R2", "b", {"I": "L", "AC": "H"}, 0, 2)
        with self.assertRaises(StaleReceiptError):
            self.ledger.submit(stale)
        rejected = [e for e in self.ledger.journal() if e["kind"] == "rejected"][0]
        self.assertIn("stale", rejected["payload"]["reason"])
        self.assertEqual(1, self.ledger.vector_version)

    def test_old_base_version_on_untouched_metric_still_merges(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        late = RevisionReceipt("R2", "b", {"AV": "A"}, 0, 2)
        event = self.ledger.submit(late)
        self.assertEqual("accepted", event["kind"])
        self.assertEqual(7.1, self.ledger.current_result()["base_score"])

    def test_invalid_receipt_metrics_are_rejected_as_external_input(self):
        with self.assertRaises(ReceiptValidationError):
            RevisionReceipt("R1", "a", {"NOPE": "L"}, 0, 1)
        with self.assertRaises(ReceiptValidationError):
            RevisionReceipt("R2", "a", {"I": "ZZ"}, 0, 2)
        with self.assertRaises(ReceiptValidationError):
            RevisionReceipt("R3", "a", {}, 0, 3)

    def test_withdrawal_keeps_public_values_traceable_and_restores_metric(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        self.ledger.publish("report-1")

        withdrawn = self.ledger.withdraw("R1", "a")

        self.assertEqual("withdrawn", withdrawn["kind"])
        self.assertEqual({"I": "N"}, dict(withdrawn["payload"]["rollback_values"]))
        self.assertEqual(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            self.ledger.current_result()["vector"],
        )
        historical = self.ledger.publication("report-1")
        self.assertEqual(8.2, historical["base_score"])
        self.assertIn("I:L", historical["vector"])
        kinds = [event["kind"] for event in self.ledger.journal()]
        self.assertIn("accepted", kinds)
        self.assertIn("withdrawn", kinds)

    def test_withdrawing_unknown_receipt_fails(self):
        with self.assertRaises(AdvisoryScoringError):
            self.ledger.withdraw("missing", "a")

    def test_historical_release_point_recomputes_displayed_score_and_severity(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        self.ledger.submit(RevisionReceipt("R2", "b", {"AV": "A"}, 0, 2))
        release = self.ledger.publish("report-2026-11-28")

        recomputed = self.ledger.recompute_at("report-2026-11-28")

        self.assertTrue(recomputed["matches_display"])
        self.assertEqual(7.1, recomputed["base_score"])
        self.assertEqual("High", recomputed["severity"])
        self.assertEqual(release["payload"]["base_score"], recomputed["displayed_score"])
        self.assertEqual(release["payload"]["severity"], recomputed["displayed_severity"])

    def test_recompute_after_withdrawal_still_matches_historical_report(self):
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        self.ledger.submit(RevisionReceipt("R2", "b", {"AV": "A"}, 0, 2))
        self.ledger.publish("report-2026-11-28")
        self.ledger.withdraw("R1", "a")

        recomputed = self.ledger.recompute_at("report-2026-11-28")

        self.assertTrue(recomputed["matches_display"])
        self.assertEqual(7.1, recomputed["base_score"])
        self.assertEqual("High", recomputed["severity"])
        self.assertNotEqual(recomputed["vector"], self.ledger.current_result()["vector"])

    def test_multiple_publication_points_remain_independently_recomputable(self):
        self.ledger.publish("initial-report")
        self.ledger.submit(RevisionReceipt("R1", "a", {"I": "L"}, 0, 1))
        self.ledger.publish("impact-report")
        self.ledger.submit(RevisionReceipt("R2", "b", {"AV": "A"}, 0, 2))
        self.ledger.publish("premise-report")

        self.assertEqual(7.5, self.ledger.recompute_at("initial-report")["base_score"])
        self.assertEqual(8.2, self.ledger.recompute_at("impact-report")["base_score"])
        self.assertEqual(7.1, self.ledger.recompute_at("premise-report")["base_score"])
        for result in ("initial-report", "impact-report", "premise-report"):
            self.assertTrue(self.ledger.recompute_at(result)["matches_display"])


if __name__ == "__main__":
    unittest.main()
