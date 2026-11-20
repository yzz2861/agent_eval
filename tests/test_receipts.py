"""Tests for offline approval receipt reconciliation."""

from __future__ import annotations

import copy
import unittest
from datetime import UTC, datetime, timedelta

from securesystemslib.receipts import (
    Approval,
    Artifact,
    OfflineReceiptVerifier,
    Receipt,
    ReceiptError,
    SeatRequirement,
    verifier_from_dict,
)
from securesystemslib.signer import CryptoSigner

ARTIFACT = Artifact("payments-api", "sha256:" + "a" * 64)
OTHER_ARTIFACT = Artifact("payments-api", "sha256:" + "b" * 64)
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
NOT_BEFORE = NOW - timedelta(hours=2)
NOT_AFTER = NOW + timedelta(hours=2)


class ReceiptTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.approval_signer = CryptoSigner.generate_ed25519("approval-key")
        cls.release_signer = CryptoSigner.generate_ed25519("release-key")
        cls.security_signer = CryptoSigner.generate_ed25519("security-key")
        cls.operations_signer = CryptoSigner.generate_ed25519("operations-key")
        cls.rogue_signer = CryptoSigner.generate_ed25519("rogue-key")

    def approval(  # noqa: PLR0913
        self,
        approval_id: str,
        *,
        purposes: set[str] | None = None,
        artifact: Artifact = ARTIFACT,
        signer: CryptoSigner | None = None,
        not_before: datetime = NOT_BEFORE,
        not_after: datetime = NOT_AFTER,
    ) -> Approval:
        approval = Approval(
            approval_id=approval_id,
            artifact=artifact,
            purposes=frozenset(purposes or {"deploy", "rollback"}),
            not_before=not_before,
            not_after=not_after,
            issuer="release-board",
        )
        approval.sign(signer or self.approval_signer)
        return approval

    def receipt(  # noqa: PLR0913
        self,
        receipt_id: str,
        approval_id: str,
        seat: str,
        signature_type: str,
        signer: CryptoSigner,
        *,
        purpose: str = "deploy",
        artifact: Artifact = ARTIFACT,
        issued_at: datetime = NOW,
    ) -> Receipt:
        receipt = Receipt(
            receipt_id=receipt_id,
            approval_id=approval_id,
            seat=seat,
            signature_type=signature_type,
            purpose=purpose,
            artifact=artifact,
            issued_at=issued_at,
        )
        receipt.sign(signer)
        return receipt

    def verifier(
        self, requirements: list[SeatRequirement], **kwargs: object
    ) -> OfflineReceiptVerifier:
        return OfflineReceiptVerifier(
            requirements,
            approval_keys={
                self.approval_signer.public_key.keyid: self.approval_signer.public_key
            },
            receipt_keys={
                "release_manager": {
                    self.release_signer.public_key.keyid: self.release_signer.public_key
                },
                "security": {
                    self.security_signer.public_key.keyid: (
                        self.security_signer.public_key
                    )
                },
                "operations": {
                    self.operations_signer.public_key.keyid: (
                        self.operations_signer.public_key
                    )
                },
            },
            **kwargs,
        )

    @staticmethod
    def requirements() -> list[SeatRequirement]:
        return [
            SeatRequirement("release", "release_manager", {"deploy"}, ARTIFACT),
            SeatRequirement("security", "security", {"deploy"}, ARTIFACT),
        ]


class TestOfflineReceiptVerifier(ReceiptTestBase):
    def test_global_matching_is_not_greedy(self) -> None:
        """A flexible seat yields its preferred approval to a constrained seat."""

        approvals = [self.approval("A1"), self.approval("A2")]
        receipts = [
            self.receipt(
                "release-a1",
                "A1",
                "release",
                "release_manager",
                self.release_signer,
            ),
            self.receipt(
                "release-a2",
                "A2",
                "release",
                "release_manager",
                self.release_signer,
            ),
            self.receipt(
                "security-a1",
                "A1",
                "security",
                "security",
                self.security_signer,
            ),
        ]

        verifier = self.verifier(self.requirements())
        verifier.add_approvals(approvals).add_receipts(receipts)
        result = verifier.reconcile(as_of=NOW)

        self.assertTrue(result.ok, result.summary())
        matched = {match.seat: match for match in result.matches}
        self.assertEqual(matched["release"].approval_id, "A2")
        self.assertEqual(matched["security"].approval_id, "A1")
        self.assertEqual(result.missing_signature_types, ())

    def test_one_approval_covers_multiple_purposes_at_one_seat(self) -> None:
        """Multiple receipts at one seat may share one multi-purpose approval."""

        approval = self.approval("A1", purposes={"deploy", "rollback"})
        receipts = [
            self.receipt(
                "release-deploy",
                "A1",
                "release",
                "release_manager",
                self.release_signer,
                purpose="deploy",
            ),
            self.receipt(
                "release-rollback",
                "A1",
                "release",
                "release_manager",
                self.release_signer,
                purpose="rollback",
            ),
        ]
        requirements = [
            SeatRequirement(
                "release",
                "release_manager",
                {"deploy", "rollback"},
                ARTIFACT,
            )
        ]

        verifier = self.verifier(requirements)
        verifier.add_approvals([approval]).add_receipts(receipts)
        result = verifier.reconcile(as_of=NOW)

        self.assertTrue(result.ok, result.summary())
        self.assertEqual(
            result.matches[0].receipt_ids,
            ("release-deploy", "release-rollback"),
        )
        self.assertEqual(result.matches[0].purposes, ("deploy", "rollback"))

    def test_approval_cannot_be_reused_by_another_seat(self) -> None:
        """The same approval is consumed by at most one independent seat."""

        receipts = [
            self.receipt(
                "release-a1",
                "A1",
                "release",
                "release_manager",
                self.release_signer,
            ),
            self.receipt(
                "security-a1",
                "A1",
                "security",
                "security",
                self.security_signer,
            ),
        ]

        verifier = self.verifier(self.requirements())
        verifier.add_approvals([self.approval("A1")]).add_receipts(receipts)
        result = verifier.reconcile(as_of=NOW)

        self.assertFalse(result.ok)
        self.assertEqual(result.missing_signature_types, ("security",))
        self.assertEqual(result.missing[0].reason, "approval_already_used")
        self.assertIn("security", result.summary())

    def test_retransmission_is_idempotent(self) -> None:
        """The same receipt identity can be retransmitted without new capacity."""

        approval = self.approval("A1")
        second_approval = self.approval("A2")
        release_receipt = self.receipt(
            "release-a1",
            "A1",
            "release",
            "release_manager",
            self.release_signer,
        )
        security_receipt = self.receipt(
            "security-a2",
            "A2",
            "security",
            "security",
            self.security_signer,
        )
        verifier = self.verifier(self.requirements())
        verifier.add_approvals([approval, copy.deepcopy(approval), second_approval])
        verifier.add_receipts(
            [
                release_receipt,
                copy.deepcopy(release_receipt),
                security_receipt,
                copy.deepcopy(security_receipt),
            ]
        )
        verifier.add_manual_receipts([copy.deepcopy(security_receipt)])

        result = verifier.reconcile(as_of=NOW)

        self.assertTrue(result.ok, result.summary())
        self.assertEqual(result.manual_receipt_ids, ("security-a2",))
        self.assertEqual(result.conflicts, ())

    def test_conflicting_retransmission_invalidates_identity(self) -> None:
        """A changed body under an existing receipt id cannot inherit identity."""

        release_receipt = self.receipt(
            "release-a1",
            "A1",
            "release",
            "release_manager",
            self.release_signer,
        )
        conflicting = Receipt(
            receipt_id=release_receipt.receipt_id,
            approval_id=release_receipt.approval_id,
            seat=release_receipt.seat,
            signature_type=release_receipt.signature_type,
            purpose="rollback",
            artifact=release_receipt.artifact,
            issued_at=release_receipt.issued_at,
        )
        conflicting.sign(self.release_signer)

        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([self.approval("A1")])
        verifier.add_receipts([release_receipt, conflicting])
        result = verifier.reconcile(as_of=NOW)

        self.assertFalse(result.ok)
        self.assertEqual(result.conflicts[0].kind, "receipt")
        self.assertEqual(result.conflicts[0].evidence_id, "release-a1")
        self.assertEqual(result.missing_signature_types, ("release_manager",))

    def test_manual_supplement_completes_pending_seat(self) -> None:
        """A late human-supplied receipt is accepted while it is still valid."""

        verifier = self.verifier(self.requirements())
        verifier.add_approvals([self.approval("A1"), self.approval("A2")])
        verifier.add_receipts(
            [
                self.receipt(
                    "release-a1",
                    "A1",
                    "release",
                    "release_manager",
                    self.release_signer,
                )
            ]
        )

        first = verifier.reconcile(as_of=NOW)
        self.assertFalse(first.ok)
        self.assertEqual(first.missing_signature_types, ("security",))

        verifier.add_manual_receipts(
            [
                self.receipt(
                    "security-a2-manual",
                    "A2",
                    "security",
                    "security",
                    self.security_signer,
                )
            ]
        )
        second = verifier.reconcile(as_of=NOW)

        self.assertTrue(second.ok, second.summary())
        self.assertEqual(second.manual_receipt_ids, ("security-a2-manual",))

    def test_expired_manual_evidence_is_not_accepted(self) -> None:
        """Manual provenance never overrides the approval validity window."""

        approval = self.approval("A1")
        expired_receipt = self.receipt(
            "release-a1",
            "A1",
            "release",
            "release_manager",
            self.release_signer,
            issued_at=NOT_BEFORE - timedelta(seconds=1),
        )
        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([approval])
        verifier.add_manual_receipts([expired_receipt])
        result = verifier.reconcile(as_of=NOW)

        self.assertFalse(result.ok)
        self.assertEqual(result.missing[0].reason, "outside_validity")
        self.assertEqual(result.missing_signature_types, ("release_manager",))

    def test_missing_signature_type_is_reported(self) -> None:
        """A failing acceptance case names the absent signature category."""

        receipts = [
            self.receipt(
                "release-a1",
                "A1",
                "release",
                "release_manager",
                self.release_signer,
            ),
            self.receipt(
                "operations-a1",
                "A2",
                "operations",
                "operations",
                self.operations_signer,
                purpose="rollback",
            ),
        ]
        requirements = [
            *self.requirements(),
            SeatRequirement("operations", "operations", {"rollback"}, ARTIFACT),
        ]
        verifier = self.verifier(requirements)
        verifier.add_approvals([self.approval("A1"), self.approval("A2")])
        verifier.add_receipts(receipts)

        result = verifier.reconcile(as_of=NOW)

        self.assertFalse(result.ok)
        self.assertEqual(result.missing_signature_types, ("security",))
        self.assertEqual(result.missing[0].seat, "security")
        self.assertEqual(result.missing[0].reason, "missing_signature")
        self.assertIn("missing signature type(s): security", result.summary())

    def test_wrong_artifact_and_purpose_are_distinguished(self) -> None:
        """Scope violations produce reviewer-actionable reasons."""

        wrong_artifact = self.receipt(
            "release-artifact",
            "A1",
            "release",
            "release_manager",
            self.release_signer,
            artifact=OTHER_ARTIFACT,
        )
        wrong_purpose = self.receipt(
            "release-purpose",
            "A1",
            "release",
            "release_manager",
            self.release_signer,
            purpose="publish",
        )
        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([self.approval("A1", purposes={"deploy"})])
        verifier.add_receipts([wrong_artifact])
        result = verifier.reconcile(as_of=NOW)
        self.assertEqual(result.missing[0].reason, "artifact_mismatch")

        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([self.approval("A1", purposes={"deploy"})])
        verifier.add_receipts([wrong_purpose])
        result = verifier.reconcile(as_of=NOW)
        self.assertEqual(result.missing[0].reason, "purpose_not_allowed")

    def test_untrusted_receipt_signature_is_rejected(self) -> None:
        """A receipt signed by an unregistered key is not accepted."""

        forged = self.receipt(
            "release-forged",
            "A1",
            "release",
            "release_manager",
            self.rogue_signer,
        )
        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([self.approval("A1")])
        verifier.add_receipts([forged])
        result = verifier.reconcile(as_of=NOW)

        self.assertFalse(result.ok)
        self.assertEqual(result.missing[0].reason, "invalid_receipt")
        self.assertEqual(
            result.rejected_receipts[0].reasons,
            ("untrusted_or_invalid_receipt_signature",),
        )

    def test_approval_must_be_signed_and_current(self) -> None:
        """Approval authentication and expiry are checked independently."""

        unsigned = Approval(
            approval_id="unsigned",
            artifact=ARTIFACT,
            purposes=frozenset({"deploy"}),
            not_before=NOT_BEFORE,
            not_after=NOT_AFTER,
        )
        receipt = self.receipt(
            "release-unsigned",
            "unsigned",
            "release",
            "release_manager",
            self.release_signer,
        )
        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([unsigned]).add_receipts([receipt])
        result = verifier.reconcile(as_of=NOW)
        self.assertEqual(result.missing[0].reason, "invalid_approval")

        expired_approval = self.approval(
            "expired",
            not_before=NOT_BEFORE,
            not_after=NOW - timedelta(seconds=1),
        )
        receipt = self.receipt(
            "release-expired",
            "expired",
            "release",
            "release_manager",
            self.release_signer,
            issued_at=NOW - timedelta(minutes=1),
        )
        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([expired_approval]).add_receipts([receipt])
        result = verifier.reconcile(as_of=NOW)
        self.assertEqual(result.missing[0].reason, "invalid_approval")

    def test_roundtrip_preserves_payload_and_signatures(self) -> None:
        """Serialized evidence can be verified again without trusting new data."""

        approval = self.approval("A1")
        receipt = self.receipt(
            "release-a1",
            "A1",
            "release",
            "release_manager",
            self.release_signer,
        )
        approval_copy = Approval.from_dict(copy.deepcopy(approval.to_dict()))
        receipt_copy = Receipt.from_dict(copy.deepcopy(receipt.to_dict()))

        self.assertEqual(approval.payload(), approval_copy.payload())
        self.assertEqual(receipt.payload(), receipt_copy.payload())
        self.assertEqual(approval.signatures, approval_copy.signatures)
        self.assertEqual(receipt.signatures, receipt_copy.signatures)

        tampered = receipt.to_dict()
        artifact = tampered["artifact"]
        assert isinstance(artifact, dict)
        artifact["digest"] = OTHER_ARTIFACT.digest
        tampered_receipt = Receipt.from_dict(tampered)
        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([approval_copy]).add_receipts([tampered_receipt])
        result = verifier.reconcile(as_of=NOW)

        self.assertFalse(result.ok)
        self.assertEqual(
            result.rejected_receipts[0].reasons,
            ("untrusted_or_invalid_receipt_signature",),
        )

    def test_json_bundle_can_be_reconciled(self) -> None:
        """The CLI bundle uses the same public-key verification path."""

        approvals = [self.approval("A1"), self.approval("A2")]
        receipts = [
            self.receipt(
                "release-a1",
                "A1",
                "release",
                "release_manager",
                self.release_signer,
            ),
            self.receipt(
                "security-a2",
                "A2",
                "security",
                "security",
                self.security_signer,
            ),
        ]
        bundle = {
            "as_of": "2026-11-20T12:00:00Z",
            "requirements": [item.to_dict() for item in self.requirements()],
            "approvals": [item.to_dict() for item in approvals],
            "receipts": [item.to_dict() for item in receipts],
            "trusted_keys": {
                "approval": {
                    self.approval_signer.public_key.keyid: (
                        self.approval_signer.public_key.to_dict()
                    )
                },
                "receipt": {
                    "release_manager": {
                        self.release_signer.public_key.keyid: (
                            self.release_signer.public_key.to_dict()
                        )
                    },
                    "security": {
                        self.security_signer.public_key.keyid: (
                            self.security_signer.public_key.to_dict()
                        )
                    },
                },
            },
        }

        result = verifier_from_dict(bundle).reconcile(as_of=bundle["as_of"])

        self.assertTrue(result.ok, result.summary())
        self.assertEqual(
            {match.seat for match in result.matches},
            {"release", "security"},
        )

    def test_added_evidence_is_snapshotted(self) -> None:
        """Mutating a caller-owned object cannot change submitted evidence."""

        approval = self.approval("A1")
        receipt = self.receipt(
            "release-a1",
            "A1",
            "release",
            "release_manager",
            self.release_signer,
        )
        verifier = self.verifier(self.requirements()[:1])
        verifier.add_approvals([approval]).add_receipts([receipt])

        approval.purposes = frozenset({"publish"})
        receipt.purpose = "publish"

        result = verifier.reconcile(as_of=NOW)

        self.assertTrue(result.ok, result.summary())

    def test_input_validation(self) -> None:
        """Malformed identities and timestamp forms fail closed."""

        with self.assertRaises(ReceiptError):
            SeatRequirement("", "security")
        with self.assertRaises(ReceiptError):
            Artifact("", "sha256:abc")
        with self.assertRaises(ReceiptError):
            Approval(
                "A1",
                ARTIFACT,
                frozenset(),
                NOT_BEFORE,
                NOT_AFTER,
            )
        with self.assertRaises(ReceiptError):
            Artifact.from_dict({"name": "only-name"})
        with self.assertRaises(ReceiptError):
            self.approval(
                "A1",
                not_before=NOW + timedelta(hours=1),
                not_after=NOW,
            )


if __name__ == "__main__":
    unittest.main()
