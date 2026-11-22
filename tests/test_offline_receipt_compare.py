from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from offline_receipt_compare.comparator import ReceiptComparator
from offline_receipt_compare.fixture_io import write_evidence
from offline_receipt_compare.models import EvidenceStore, Receipt, VerdictCode
from offline_receipt_compare.repo_builder import (
    DelegationSpec,
    FixtureRepository,
)
from offline_receipt_compare.verifier import MetadataBundle, verify_chain

ISSUED = datetime(2026, 6, 1, tzinfo=UTC)


def make_receipt(target_path: str, content: bytes, path: list[str]) -> Receipt:
    return Receipt(
        receipt_id="R-1",
        target_path=target_path,
        hashes={"sha256": hashlib.sha256(content).hexdigest()},
        length=len(content),
        issued_at=ISSUED,
        delegation_path=path,
        evidence_relpath=f"artifacts/{Path(target_path).name}",
    )


def build(tmp: Path, content: bytes, include: bool) -> tuple[Path, Path]:
    old = FixtureRepository(expiry_base=ISSUED)
    old.add_delegation(
        "targets", DelegationSpec("legacy", ["hw/*"], terminating=True)
    )
    old.add_target("hw/part.bin", content, role="legacy")
    old_dir = tmp / "old"
    old.write(old_dir)

    candidate = FixtureRepository(expiry_base=ISSUED)
    candidate.add_delegation(
        "targets", DelegationSpec("current", ["hw/*"], terminating=True)
    )
    if include:
        candidate.add_target("hw/part.bin", content, role="current")
    new_dir = tmp / "candidate"
    candidate.write(new_dir)
    return old_dir, new_dir


class ComparatorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR") or None))

    def _run(self, receipt: Receipt) -> object:
        comparator = ReceiptComparator(
            old_bundle=MetadataBundle(self.tmp / "old"),
            candidate_bundle=MetadataBundle(self.tmp / "candidate"),
            receipts=[receipt],
            evidence=EvidenceStore(self.tmp / "evidence"),
        )
        return comparator.run()

    def test_reverifiable_when_path_and_evidence_hold(self) -> None:
        content = b"firmware body"
        build(self.tmp, content, include=True)
        receipt = make_receipt("hw/part.bin", content, ["targets", "legacy"])
        write_evidence(self.tmp / "evidence", receipt.evidence_relpath, content)

        report = self._run(receipt)
        self.assertEqual(report.receipts_evaluated, 1)
        outcome = report.outcomes[0]
        self.assertEqual(outcome.code, VerdictCode.REVERIFIABLE)
        self.assertEqual(
            [step.role for step in outcome.candidate_path],
            ["targets", "current"],
        )
        resolution = verify_chain(
            MetadataBundle(self.tmp / "candidate"),
            "hw/part.bin",
            reference_time=ISSUED,
        )
        self.assertTrue(resolution.found)

    def test_reissue_when_target_no_longer_resolved(self) -> None:
        content = b"firmware body"
        build(self.tmp, content, include=False)
        receipt = make_receipt("hw/part.bin", content, ["targets", "legacy"])
        write_evidence(self.tmp / "evidence", receipt.evidence_relpath, content)

        report = self._run(receipt)
        self.assertEqual(report.blocked[0].code, VerdictCode.PATH_BROKEN)
        self.assertEqual(report.re_verifiable, [])

    def test_content_drift_requires_reissue(self) -> None:
        old_content = b"original"
        new_content = b"changed-body"
        build(self.tmp, new_content, include=True)
        receipt = make_receipt(
            "hw/part.bin", old_content, ["targets", "legacy"]
        )
        write_evidence(
            self.tmp / "evidence", receipt.evidence_relpath, old_content
        )

        report = self._run(receipt)
        self.assertEqual(report.blocked[0].code, VerdictCode.CONTENT_DRIFTED)

    def test_missing_and_mismatched_evidence(self) -> None:
        content = b"firmware body"
        build(self.tmp, content, include=True)
        receipt = make_receipt("hw/part.bin", content, ["targets", "legacy"])

        missing = self._run(receipt)
        self.assertEqual(missing.blocked[0].code, VerdictCode.EVIDENCE_MISSING)

        write_evidence(
            self.tmp / "evidence", receipt.evidence_relpath, b"tampered"
        )
        mismatched = self._run(receipt)
        self.assertEqual(
            mismatched.blocked[0].code, VerdictCode.EVIDENCE_MISMATCH
        )

    def test_target_without_receipt_is_ignored_not_risk(self) -> None:
        content = b"firmware body"
        old = FixtureRepository(expiry_base=ISSUED)
        old.add_delegation(
            "targets", DelegationSpec("legacy", ["hw/*"], terminating=True)
        )
        old.add_target("hw/part.bin", content, role="legacy")
        old.add_target("hw/unreceipted.bin", b"no receipt", role="legacy")
        old.write(self.tmp / "old")

        candidate = FixtureRepository(expiry_base=ISSUED)
        candidate.add_delegation(
            "targets", DelegationSpec("current", ["hw/*"], terminating=True)
        )
        candidate.add_target("hw/part.bin", content, role="current")
        candidate.add_target(
            "hw/unreceipted.bin", b"no receipt", role="current"
        )
        candidate.write(self.tmp / "candidate")

        receipt = make_receipt("hw/part.bin", content, ["targets", "legacy"])
        write_evidence(self.tmp / "evidence", receipt.evidence_relpath, content)
        report = self._run(receipt)

        self.assertEqual(report.targets_without_receipt_ignored, 1)
        self.assertEqual(len(report.outcomes), 1)
        self.assertEqual(report.outcomes[0].code, VerdictCode.REVERIFIABLE)

    def test_historical_invalidation_is_flagged(self) -> None:
        content = b"firmware body"
        FixtureRepository(expiry_base=ISSUED).write(self.tmp / "old")
        FixtureRepository(expiry_base=ISSUED).write(self.tmp / "candidate")

        receipt = make_receipt("hw/never-existed.bin", content, ["targets"])
        write_evidence(self.tmp / "evidence", receipt.evidence_relpath, content)
        report = self._run(receipt)

        self.assertEqual(
            report.blocked[0].code,
            VerdictCode.NOT_HISTORICALLY_VALID,
        )


if __name__ == "__main__":
    unittest.main()
