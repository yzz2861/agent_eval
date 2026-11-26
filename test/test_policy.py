#!/usr/bin/env python

import os
import sys
import unittest
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from signxml import (
    ApprovalStage,
    DigestAlgorithm,
    InvalidInput,
    InvalidSignature,
    PolicyRegistry,
    PolicyStatus,
    PolicyVersion,
    SignatureConfiguration,
    SignatureMethod,
    StageEvidence,
    SuspensionReason,
    XMLSigner,
    XMLVerifier,
    evaluate_stages,
    methods,
)

UTC = timezone.utc

OLD_POLICY_EXPLANATION = "Approval policy v1: historical files are verified under the policy of their signing date."
NEW_POLICY_EXPLANATION = "Approval policy v2: archive uploads and re-reviews each carry their own approval version."


def make_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Offline Policy Test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return cert_pem, key_pem


def make_registry():
    return PolicyRegistry(
        [
            PolicyVersion(
                version="approval-v1",
                effective_from=datetime(2021, 1, 1, tzinfo=UTC),
                effective_to=datetime(2023, 1, 1, tzinfo=UTC),
                explanation=OLD_POLICY_EXPLANATION,
            ),
            PolicyVersion(
                version="approval-v2",
                effective_from=datetime(2023, 1, 1, tzinfo=UTC),
                explanation=NEW_POLICY_EXPLANATION,
            ),
        ]
    )


class TestOfflinePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_pem, cls.key_pem = make_self_signed_cert()
        cls.registry = make_registry()
        cls.verification_config = SignatureConfiguration(verification_time=datetime(2025, 1, 1, tzinfo=UTC))

    def sign_document(self):
        root = etree.fromstring(b"<approval><item>contract-1</item></approval>")
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
        )
        return signer.sign(root, key=self.key_pem, cert=self.cert_pem)

    def verify_document(self, signed):
        return XMLVerifier().verify(etree.tostring(signed), x509_cert=self.cert_pem, expect_config=self.verification_config)

    def full_evidence(self):
        return [
            StageEvidence(stage=ApprovalStage.SIGNING, stage_time=datetime(2022, 6, 15, tzinfo=UTC)),
            StageEvidence(
                stage=ApprovalStage.ARCHIVING,
                stage_time=datetime(2022, 7, 1, tzinfo=UTC),
                approval_version="approval-v1",
            ),
            StageEvidence(
                stage=ApprovalStage.REPUBLISHING,
                stage_time=datetime(2024, 2, 1, tzinfo=UTC),
                approval_version="approval-v2",
            ),
        ]

    def test_three_stages_conclusive_and_reproducible(self):
        verify_result = self.verify_document(self.sign_document())
        first = evaluate_stages(verify_result, evidence=self.full_evidence(), registry=self.registry)
        second = evaluate_stages(verify_result, evidence=self.full_evidence(), registry=self.registry)
        self.assertEqual(first, second)

        self.assertTrue(first.signature_valid)
        self.assertEqual(
            tuple(d.stage for d in first.decisions),
            (ApprovalStage.SIGNING, ApprovalStage.ARCHIVING, ApprovalStage.REPUBLISHING),
        )
        for decision in first.decisions:
            self.assertEqual(decision.status, PolicyStatus.CONCLUSIVE)
            self.assertTrue(decision.independent_evidence)
            self.assertEqual(decision.reasons, ())

        signing = first.decision_for(ApprovalStage.SIGNING)
        self.assertEqual(signing.policy_version, "approval-v1")
        self.assertEqual(signing.explanation, OLD_POLICY_EXPLANATION)
        archiving = first.decision_for(ApprovalStage.ARCHIVING)
        self.assertEqual(archiving.policy_version, "approval-v1")
        republishing = first.decision_for(ApprovalStage.REPUBLISHING)
        self.assertEqual(republishing.policy_version, "approval-v2")
        self.assertEqual(republishing.explanation, NEW_POLICY_EXPLANATION)

    def test_time_conflict_suspends_stage(self):
        verify_result = self.verify_document(self.sign_document())
        evidence = self.full_evidence()
        evidence[1] = StageEvidence(
            stage=ApprovalStage.ARCHIVING,
            stage_time=datetime(2022, 5, 1, tzinfo=UTC),
            approval_version="approval-v1",
        )
        determination = evaluate_stages(verify_result, evidence=evidence, registry=self.registry)
        archiving = determination.decision_for(ApprovalStage.ARCHIVING)
        self.assertEqual(archiving.status, PolicyStatus.SUSPENDED)
        self.assertIn(SuspensionReason.TIME_CONFLICT, archiving.reasons)
        self.assertEqual(determination.decision_for(ApprovalStage.SIGNING).status, PolicyStatus.CONCLUSIVE)
        self.assertEqual(determination.decision_for(ApprovalStage.REPUBLISHING).status, PolicyStatus.CONCLUSIVE)

    def test_unknown_versions_suspend(self):
        verify_result = self.verify_document(self.sign_document())
        evidence = [
            StageEvidence(stage=ApprovalStage.SIGNING, stage_time=datetime(2010, 1, 1, tzinfo=UTC)),
            StageEvidence(
                stage=ApprovalStage.ARCHIVING,
                stage_time=datetime(2022, 7, 1, tzinfo=UTC),
                approval_version="approval-v9",
            ),
            StageEvidence(
                stage=ApprovalStage.REPUBLISHING,
                stage_time=datetime(2024, 2, 1, tzinfo=UTC),
                approval_version="approval-v1",
            ),
        ]
        determination = evaluate_stages(verify_result, evidence=evidence, registry=self.registry)
        signing = determination.decision_for(ApprovalStage.SIGNING)
        self.assertEqual(signing.status, PolicyStatus.SUSPENDED)
        self.assertIn(SuspensionReason.UNKNOWN_POLICY_VERSION, signing.reasons)
        self.assertIsNone(signing.policy_version)
        archiving = determination.decision_for(ApprovalStage.ARCHIVING)
        self.assertEqual(archiving.status, PolicyStatus.SUSPENDED)
        self.assertIn(SuspensionReason.UNKNOWN_APPROVAL_VERSION, archiving.reasons)
        republishing = determination.decision_for(ApprovalStage.REPUBLISHING)
        self.assertEqual(republishing.status, PolicyStatus.SUSPENDED)
        self.assertIn(SuspensionReason.APPROVAL_VERSION_MISMATCH, republishing.reasons)

    def test_missing_evidence_suspends(self):
        verify_result = self.verify_document(self.sign_document())
        evidence = [
            StageEvidence(stage=ApprovalStage.SIGNING, stage_time=datetime(2022, 6, 15, tzinfo=UTC)),
            StageEvidence(stage=ApprovalStage.ARCHIVING, stage_time=datetime(2022, 7, 1, tzinfo=UTC)),
            StageEvidence(stage=ApprovalStage.REPUBLISHING, approval_version="approval-v2"),
        ]
        determination = evaluate_stages(verify_result, evidence=evidence, registry=self.registry)
        archiving = determination.decision_for(ApprovalStage.ARCHIVING)
        self.assertEqual(archiving.status, PolicyStatus.SUSPENDED)
        self.assertIn(SuspensionReason.MISSING_STAGE_APPROVAL_VERSION, archiving.reasons)
        self.assertFalse(archiving.independent_evidence)
        republishing = determination.decision_for(ApprovalStage.REPUBLISHING)
        self.assertEqual(republishing.status, PolicyStatus.SUSPENDED)
        self.assertIn(SuspensionReason.MISSING_STAGE_TIME, republishing.reasons)
        self.assertFalse(republishing.independent_evidence)

    def test_failed_signature_suspends_all_stages(self):
        signed = self.sign_document()
        signed.find("item").text = "tampered"
        with self.assertRaises(InvalidSignature):
            self.verify_document(signed)
        determination = evaluate_stages(None, evidence=self.full_evidence(), registry=self.registry)
        self.assertFalse(determination.signature_valid)
        for decision in determination.decisions:
            self.assertEqual(decision.status, PolicyStatus.SUSPENDED)
            self.assertIn(SuspensionReason.SIGNATURE_VERIFICATION_FAILED, decision.reasons)

    def test_restore_old_policy_explanation(self):
        self.assertEqual(self.registry.explain("approval-v1"), OLD_POLICY_EXPLANATION)
        self.assertEqual(self.registry.explain("approval-v2"), NEW_POLICY_EXPLANATION)
        self.assertIsNone(self.registry.explain("approval-v9"))
        verify_result = self.verify_document(self.sign_document())
        evidence = [StageEvidence(stage=ApprovalStage.SIGNING, stage_time=datetime(2022, 6, 15, tzinfo=UTC))]
        determination = evaluate_stages(verify_result, evidence=evidence, registry=self.registry)
        signing = determination.decision_for(ApprovalStage.SIGNING)
        self.assertEqual(signing.status, PolicyStatus.CONCLUSIVE)
        self.assertEqual(signing.policy_version, "approval-v1")
        self.assertEqual(signing.explanation, self.registry.explain("approval-v1"))

    def test_registry_rejects_invalid_versions(self):
        with self.assertRaises(InvalidInput):
            PolicyRegistry(
                [
                    PolicyVersion(version="v1", effective_from=datetime(2021, 1, 1, tzinfo=UTC)),
                    PolicyVersion(version="v1", effective_from=datetime(2022, 1, 1, tzinfo=UTC)),
                ]
            )
        with self.assertRaises(InvalidInput):
            PolicyRegistry(
                [
                    PolicyVersion(version="v1", effective_from=datetime(2021, 1, 1, tzinfo=UTC)),
                    PolicyVersion(version="v2", effective_from=datetime(2022, 1, 1, tzinfo=UTC)),
                ]
            )
        with self.assertRaises(InvalidInput):
            PolicyVersion(
                version="v1",
                effective_from=datetime(2022, 1, 1, tzinfo=UTC),
                effective_to=datetime(2021, 1, 1, tzinfo=UTC),
            )

    def test_duplicate_stage_evidence_rejected(self):
        verify_result = self.verify_document(self.sign_document())
        evidence = [
            StageEvidence(stage=ApprovalStage.SIGNING, stage_time=datetime(2022, 6, 15, tzinfo=UTC)),
            StageEvidence(stage=ApprovalStage.SIGNING, stage_time=datetime(2022, 6, 16, tzinfo=UTC)),
        ]
        with self.assertRaises(InvalidInput):
            evaluate_stages(verify_result, evidence=evidence, registry=self.registry)


if __name__ == "__main__":
    unittest.main()

