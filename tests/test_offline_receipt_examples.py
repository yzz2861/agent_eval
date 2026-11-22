from __future__ import annotations

import json
import unittest
from pathlib import Path

from offline_receipt_compare.comparator import ReceiptComparator
from offline_receipt_compare.models import (
    EvidenceStore,
    ReceiptSet,
    VerdictCode,
)
from offline_receipt_compare.verifier import MetadataBundle

STORE = Path(__file__).resolve().parent.parent / "examples_store"


class ExampleFixturesTestCase(unittest.TestCase):
    def _compare(self, scenario: str) -> object:
        root = STORE / scenario
        receipts = ReceiptSet.load(root / "receipts").receipts
        comparator = ReceiptComparator(
            old_bundle=MetadataBundle(root / "old_metadata"),
            candidate_bundle=MetadataBundle(root / "candidate_metadata"),
            receipts=receipts,
            evidence=EvidenceStore(root / "evidence"),
        )
        return comparator.run()

    def test_scenario_a_is_reverifiable(self) -> None:
        report = self._compare("scenario_a_reverifiable")
        self.assertEqual(len(report.outcomes), 1)
        self.assertEqual(report.outcomes[0].code, VerdictCode.REVERIFIABLE)
        self.assertEqual(report.targets_without_receipt_ignored, 1)
        payload = report.to_dict()
        json.dumps(payload)

    def test_scenario_b_requires_reissue(self) -> None:
        report = self._compare("scenario_b_reissue_required")
        self.assertEqual(report.blocked[0].code, VerdictCode.PATH_BROKEN)
        self.assertEqual(report.re_verifiable, [])


if __name__ == "__main__":
    unittest.main()
