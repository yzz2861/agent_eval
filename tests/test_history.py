import sys
import unittest
from datetime import datetime
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import (
    ScoringHistory,
    CVSSHistoryReferenceError,
    CVSSHistoryRevocationError,
    CVSSHistoryValidationError,
)

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
BUSINESS_TIME = datetime(2025, 3, 9, 12, 0)


def build_history():
    history = ScoringHistory()
    history.add_advisory(
        "CVE-2025-9001",
        VECTOR,
        known_at=datetime(2025, 3, 1, 9, 0),
        effective_at=datetime(2025, 3, 1, 12, 0),
    )
    history.add_erratum(
        "CVE-2025-9001", "E", "P",
        known_at=datetime(2025, 3, 5, 10, 0),
        effective_at=datetime(2025, 3, 4, 12, 0),
    )
    second = history.add_erratum(
        "CVE-2025-9001", "E", "F",
        known_at=datetime(2025, 3, 12, 10, 0),
        effective_at=datetime(2025, 3, 8, 12, 0),
    )
    history.add_revocation(
        "CVE-2025-9001", second.event_id,
        known_at=datetime(2025, 3, 15, 9, 0),
        effective_at=datetime(2025, 3, 8, 12, 0),
    )
    return history, second.event_id


class TestScoringHistory(unittest.TestCase):
    def test_as_of_preserves_original_basis(self):
        history, _ = build_history()
        basis = history.as_of("CVE-2025-9001", datetime(2025, 3, 3, 12, 0), BUSINESS_TIME)
        self.assertEqual(basis.scores[1], 8.5)
        self.assertEqual(basis.vector, VECTOR)
        self.assertEqual(basis.applied_event_ids, ("CVE-2025-9001:advisory:1",))
        self.assertEqual(basis.revoked_event_ids, ())
        self.assertEqual(basis.metric_provenance["E"], "CVE-2025-9001:advisory:1")

    def test_hindsight_includes_late_errata(self):
        history, _ = build_history()
        basis = history.hindsight("CVE-2025-9001", BUSINESS_TIME)
        self.assertEqual(basis.scores[1], 8.8)
        self.assertIn("E:P", basis.vector)
        self.assertIn("CVE-2025-9001:erratum:1", basis.applied_event_ids)
        self.assertEqual(basis.metric_provenance["E"], "CVE-2025-9001:erratum:1")

    def test_same_business_time_two_distinct_bases(self):
        history, _ = build_history()
        as_of_basis = history.as_of("CVE-2025-9001", datetime(2025, 3, 3, 12, 0), BUSINESS_TIME)
        hindsight_basis = history.hindsight("CVE-2025-9001", BUSINESS_TIME)
        self.assertEqual(as_of_basis.effective_at, hindsight_basis.effective_at)
        self.assertNotEqual(as_of_basis.vector, hindsight_basis.vector)
        self.assertNotEqual(as_of_basis.scores, hindsight_basis.scores)

    def test_revocation_restores_previous_value(self):
        history, second_id = build_history()
        basis = history.hindsight("CVE-2025-9001", BUSINESS_TIME)
        self.assertEqual(basis.revoked_event_ids, (second_id,))
        self.assertNotIn(second_id, basis.applied_event_ids)
        self.assertIn("E:P", basis.vector)
        self.assertNotIn("E:F", basis.vector)

    def test_revocation_invisible_before_known_at(self):
        history, _ = build_history()
        basis = history.as_of("CVE-2025-9001", datetime(2025, 3, 13, 12, 0), BUSINESS_TIME)
        self.assertEqual(basis.scores[1], 9.1)
        self.assertIn("E:F", basis.vector)
        self.assertEqual(basis.revoked_event_ids, ())

    def test_base_metric_update_rejected(self):
        history, _ = build_history()
        with self.assertRaises(CVSSHistoryValidationError):
            history.add_erratum(
                "CVE-2025-9001", "AV", "L",
                known_at=datetime(2025, 3, 16, 9, 0),
                effective_at=datetime(2025, 3, 16, 9, 0),
            )

    def test_illegal_metric_value_rejected(self):
        history, _ = build_history()
        with self.assertRaises(CVSSHistoryValidationError):
            history.add_erratum(
                "CVE-2025-9001", "E", "ZZZ",
                known_at=datetime(2025, 3, 16, 9, 0),
                effective_at=datetime(2025, 3, 16, 9, 0),
            )

    def test_cross_version_reference_is_traceable(self):
        history, _ = build_history()
        with self.assertRaises(CVSSHistoryReferenceError) as context:
            history.add_erratum(
                "CVE-2025-9001", "E", "H",
                known_at=datetime(2025, 3, 16, 9, 0),
                effective_at=datetime(2025, 3, 16, 9, 0),
                reference_prefix="CVSS:3.0",
            )
        error = context.exception
        self.assertEqual(error.advisory_id, "CVE-2025-9001")
        self.assertEqual(error.referenced_prefix, "CVSS:3.0")
        self.assertIsNotNone(error.event_id)

    def test_unknown_advisory_is_traceable(self):
        history = ScoringHistory()
        with self.assertRaises(CVSSHistoryReferenceError) as context:
            history.add_erratum(
                "CVE-MISSING", "E", "H",
                known_at=datetime(2025, 3, 16, 9, 0),
                effective_at=datetime(2025, 3, 16, 9, 0),
            )
        self.assertEqual(context.exception.advisory_id, "CVE-MISSING")

    def test_revoking_unknown_event_rejected(self):
        history, _ = build_history()
        with self.assertRaises(CVSSHistoryRevocationError):
            history.add_revocation(
                "CVE-2025-9001", "no-such-event",
                known_at=datetime(2025, 3, 16, 9, 0),
                effective_at=datetime(2025, 3, 16, 9, 0),
            )

    def test_double_revocation_rejected(self):
        history, second_id = build_history()
        with self.assertRaises(CVSSHistoryRevocationError):
            history.add_revocation(
                "CVE-2025-9001", second_id,
                known_at=datetime(2025, 3, 16, 9, 0),
                effective_at=datetime(2025, 3, 16, 9, 0),
            )

    def test_malformed_advisory_rejected(self):
        history = ScoringHistory()
        with self.assertRaises(CVSSHistoryValidationError):
            history.add_advisory(
                "CVE-BAD", "not-a-vector",
                known_at=datetime(2025, 3, 1, 9, 0),
                effective_at=datetime(2025, 3, 1, 12, 0),
            )


if __name__ == "__main__":
    unittest.main()
