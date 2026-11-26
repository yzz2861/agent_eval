"""Tests for signed approval attachment retirement."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from securesystemslib.retirement import (
    INDEX_PAYLOAD_TYPE,
    INDEX_SCHEMA_VERSION,
    ApprovalAttachment,
    ApprovalCase,
    ApprovalIndex,
    AuthorizationRecord,
    EvidenceStatus,
    InvalidRequestError,
    MissingEvidenceError,
    RetirementRequest,
    RetirementResult,
    RetirementService,
    RetirementStatus,
    VerificationStatus,
    write_signed_document,
)
from securesystemslib.signer import CryptoSigner


def _digest(data: bytes) -> dict[str, str]:
    return {"sha256": hashlib.sha256(data).hexdigest()}


class TestRetirement(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(dir=os.getcwd()))
        self.attachments_dir = self.temp_dir / "attachments"
        self.attachments_dir.mkdir()
        self.approver = CryptoSigner.generate_ed25519()
        self.archivist = CryptoSigner.generate_ed25519()
        self.service = RetirementService(
            [self.archivist.public_key],
            [self.approver.public_key],
            signer=self.archivist,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _write_attachment(self, attachment_id: str, data: bytes) -> ApprovalAttachment:
        relative_path = f"attachments/{attachment_id}.txt"
        (self.temp_dir / relative_path).write_bytes(data)
        return ApprovalAttachment(
            attachment_id=attachment_id,
            path=relative_path,
            digest=_digest(data),
            size=len(data),
        )

    def _authorization(
        self,
        case_id: str,
        attachments: dict[str, ApprovalAttachment],
        *,
        approved_at: str = "2021-02-03T04:05:06+00:00",
    ) -> AuthorizationRecord:
        return AuthorizationRecord.create(
            record_id=f"authz-{case_id}",
            case_id=case_id,
            attachment_ids=attachments,
            approved_at=approved_at,
            authorized_digests={
                attachment_id: dict(attachment.digest or {})
                for attachment_id, attachment in attachments.items()
            },
            approver=self.approver,
        )

    def _write_index(
        self,
        attachments: dict[str, ApprovalAttachment],
        cases: dict[str, tuple[str, ...]],
        *,
        path: Path | None = None,
    ) -> Path:
        index = ApprovalIndex(
            schema_version=INDEX_SCHEMA_VERSION,
            attachments=attachments,
            cases={
                case_id: ApprovalCase(
                    case_id=case_id,
                    attachment_ids=attachment_ids,
                    authorization=self._authorization(
                        case_id,
                        {
                            attachment_id: attachments[attachment_id]
                            for attachment_id in attachment_ids
                        },
                    ),
                )
                for case_id, attachment_ids in cases.items()
            },
        )
        index_path = path or self.temp_dir / "index.dsse.json"
        write_signed_document(
            index_path,
            index.to_dict(),
            INDEX_PAYLOAD_TYPE,
            self.archivist,
        )
        return index_path

    def test_successful_retirement_leaves_digest_and_authorization(self):
        attachment = self._write_attachment("att-old", b"old approval memo")
        other = self._write_attachment("att-new", b"new approval memo")
        index_path = self._write_index(
            {attachment.attachment_id: attachment, other.attachment_id: other},
            {"case-a": ("att-old",), "case-b": ("att-new",)},
        )

        result = self.service.retire(
            index_path,
            {"request_id": "req-ok", "case_id": "case-a", "attachment_id": "att-old"},
            evidence_dir=self.temp_dir / "evidence-success",
        )

        self.assertIsInstance(result, RetirementResult)
        self.assertTrue(result.retired)
        self.assertEqual(result.status, RetirementStatus.RETIRED)
        self.assertFalse((self.temp_dir / attachment.path).exists())
        self.assertTrue((self.temp_dir / other.path).exists())

        manifest_path = self.temp_dir / "retirement-manifest.dsse.json"
        manifest_result = self.service.load_manifest(manifest_path)
        self.assertEqual(manifest_result.status, EvidenceStatus.COMPLETE)
        self.assertEqual(len(manifest_result.manifest.entries), 1)
        entry = manifest_result.manifest.entries[0]
        self.assertEqual(entry.attachment_id, "att-old")
        self.assertEqual(entry.digest, attachment.digest)
        self.assertEqual(entry.authorization.record_id, "authz-case-a")
        self.assertIsNotNone(entry.authorization.signature)

        verification = self.service.verify_retirement(index_path, manifest_path)
        self.assertEqual(verification.status, VerificationStatus.VALID)
        self.assertTrue(verification.valid)

        evidence = self.temp_dir / "evidence-success"
        for filename in (
            "index.dsse.json",
            "request.json",
            "retirement-manifest.dsse.json",
            "retention-record.json",
            "receipt.json",
            "verification-report.json",
        ):
            self.assertTrue((evidence / filename).exists(), filename)

        retention = json.loads((evidence / "retention-record.json").read_text())
        self.assertEqual(retention["retained"]["digest"], attachment.digest)
        self.assertEqual(
            retention["retained"]["authorization"]["record_id"], "authz-case-a"
        )

    def test_shared_reference_rejects_without_deleting(self):
        attachment = self._write_attachment("att-shared", b"shared attached memo")
        index_path = self._write_index(
            {attachment.attachment_id: attachment},
            {"case-a": ("att-shared",), "case-b": ("att-shared",)},
        )

        result = self.service.retire(
            index_path,
            {
                "request_id": "req-shared",
                "case_id": "case-a",
                "attachment_id": "att-shared",
            },
            evidence_dir=self.temp_dir / "evidence-rejected",
        )

        self.assertFalse(result.retired)
        self.assertEqual(result.status, RetirementStatus.REJECTED)
        self.assertEqual(result.reason, "shared-reference")
        self.assertEqual(result.referencing_cases, ("case-a", "case-b"))
        self.assertTrue((self.temp_dir / attachment.path).exists())
        self.assertFalse((self.temp_dir / "retirement-manifest.dsse.json").exists())

        evidence = self.temp_dir / "evidence-rejected"
        rejection = json.loads((evidence / "rejection.json").read_text())
        self.assertEqual(rejection["status"], "rejected")
        self.assertEqual(rejection["reason"], "shared-reference")
        self.assertEqual(rejection["verification"]["status"], "valid")
        self.assertTrue(rejection["verification"]["attachment"]["digest_matches_index"])

        report = self.service.verify_rejection(
            index_path,
            {
                "request_id": "req-shared",
                "case_id": "case-a",
                "attachment_id": "att-shared",
            },
        )
        self.assertEqual(report.status, VerificationStatus.VALID)

    def test_request_must_name_exactly_one_attachment(self):
        first = self._write_attachment("att-one", b"one")
        second = self._write_attachment("att-two", b"two")
        index_path = self._write_index(
            {first.attachment_id: first, second.attachment_id: second},
            {"case-a": ("att-one", "att-two")},
        )

        result = self.service.retire(
            index_path,
            {
                "request_id": "req-many",
                "case_id": "case-a",
                "attachment_ids": ["att-one", "att-two"],
            },
            evidence_dir=self.temp_dir / "evidence-invalid",
        )

        self.assertFalse(result.retired)
        self.assertEqual(result.reason, "invalid-request")
        self.assertTrue((self.temp_dir / first.path).exists())
        self.assertTrue((self.temp_dir / second.path).exists())

        with self.assertRaises(InvalidRequestError):
            RetirementRequest.from_dict(
                {
                    "request_id": "req-many",
                    "case_id": "case-a",
                    "attachment_ids": ["att-one", "att-two"],
                }
            )

    def test_legacy_plain_index_reports_missing_evidence(self):
        attachment_path = self.temp_dir / "attachments/legacy.txt"
        attachment_path.write_bytes(b"legacy approval")
        legacy = {
            "schema_version": 1,
            "attachments": {"att-legacy": {"path": "attachments/legacy.txt"}},
            "cases": {"case-legacy": {"attachments": ["att-legacy"]}},
        }
        index_path = self.temp_dir / "legacy-index.json"
        index_path.write_text(json.dumps(legacy))

        read_result = self.service.load_index(index_path)
        self.assertEqual(read_result.status, EvidenceStatus.MISSING)
        self.assertFalse(read_result.signature_verified)
        self.assertIn("index.signature", read_result.evidence_report.missing)
        self.assertIn(
            "attachments.att-legacy.digest", read_result.evidence_report.missing
        )
        self.assertIn(
            "cases.case-legacy.authorization", read_result.evidence_report.missing
        )

        with self.assertRaises(MissingEvidenceError):
            read_result.require_complete()

        result = self.service.retire(
            index_path,
            {
                "request_id": "req-legacy",
                "case_id": "case-legacy",
                "attachment_id": "att-legacy",
            },
            evidence_dir=self.temp_dir / "evidence-legacy",
        )
        self.assertFalse(result.retired)
        self.assertEqual(result.reason, "missing-evidence")
        self.assertTrue(attachment_path.exists())
        self.assertTrue((self.temp_dir / "evidence-legacy/rejection.json").exists())

    def test_digest_mismatch_rejects_and_preserves_attachment(self):
        attachment = self._write_attachment("att-tampered", b"original")
        index_path = self._write_index(
            {attachment.attachment_id: attachment},
            {"case-a": ("att-tampered",)},
        )
        (self.temp_dir / attachment.path).write_bytes(b"changed after signing")

        result = self.service.retire(
            index_path,
            {
                "request_id": "req-tampered",
                "case_id": "case-a",
                "attachment_id": "att-tampered",
            },
            evidence_dir=self.temp_dir / "evidence-tampered",
        )

        self.assertFalse(result.retired)
        self.assertEqual(result.reason, "digest-mismatch")
        self.assertTrue((self.temp_dir / attachment.path).exists())

    def test_sequential_retirements_append_one_entry_each(self):
        first = self._write_attachment("att-first", b"first memo")
        second = self._write_attachment("att-second", b"second memo")
        index_path = self._write_index(
            {first.attachment_id: first, second.attachment_id: second},
            {"case-a": ("att-first",), "case-b": ("att-second",)},
        )
        manifest_path = self.temp_dir / "retirement-manifest.dsse.json"

        first_result = self.service.retire(
            index_path,
            {
                "request_id": "req-first",
                "case_id": "case-a",
                "attachment_id": "att-first",
            },
            manifest_path=manifest_path,
            evidence_dir=self.temp_dir / "evidence-first",
        )
        second_result = self.service.retire(
            index_path,
            {
                "request_id": "req-second",
                "case_id": "case-b",
                "attachment_id": "att-second",
            },
            manifest_path=manifest_path,
            evidence_dir=self.temp_dir / "evidence-second",
        )

        self.assertTrue(first_result.retired)
        self.assertTrue(second_result.retired)
        manifest = self.service.load_manifest(manifest_path).manifest
        self.assertEqual(len(manifest.entries), 2)
        self.assertEqual(
            {entry.attachment_id for entry in manifest.entries},
            {"att-first", "att-second"},
        )
        for entry in manifest.entries:
            self.assertEqual(entry.authorization.attachment_ids, (entry.attachment_id,))
        self.assertFalse((self.temp_dir / first.path).exists())
        self.assertFalse((self.temp_dir / second.path).exists())
        self.assertEqual(
            self.service.verify_retirement(index_path, manifest_path).status,
            VerificationStatus.VALID,
        )

    def test_legacy_manifest_reports_missing_evidence(self):
        manifest_path = self.temp_dir / "legacy-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "entries": [
                        {
                            "attachment_id": "att-legacy",
                            "case_id": "case-legacy",
                            "path": "attachments/legacy.txt",
                        }
                    ],
                }
            )
        )

        result = self.service.load_manifest(manifest_path)
        self.assertEqual(result.status, EvidenceStatus.MISSING)
        self.assertFalse(result.signature_verified)
        self.assertIn("manifest.signature", result.evidence_report.missing)
        self.assertIn(
            "manifest.retirements[0].retained.digest", result.evidence_report.missing
        )
        self.assertIn(
            "manifest.retirements[0].retained.authorization",
            result.evidence_report.missing,
        )

    def test_incomplete_existing_manifest_blocks_new_retirement(self):
        attachment = self._write_attachment("att-blocked", b"blocked memo")
        index_path = self._write_index(
            {attachment.attachment_id: attachment},
            {"case-a": ("att-blocked",)},
        )
        manifest_path = self.temp_dir / "retirement-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "entries": [
                        {
                            "attachment_id": "att-older",
                            "case_id": "case-older",
                            "path": "attachments/older.txt",
                        }
                    ],
                }
            )
        )

        result = self.service.retire(
            index_path,
            {
                "request_id": "req-blocked",
                "case_id": "case-a",
                "attachment_id": "att-blocked",
            },
            manifest_path=manifest_path,
            evidence_dir=self.temp_dir / "evidence-blocked",
        )

        self.assertFalse(result.retired)
        self.assertEqual(result.reason, "missing-evidence")
        self.assertTrue((self.temp_dir / attachment.path).exists())


if __name__ == "__main__":
    unittest.main()
