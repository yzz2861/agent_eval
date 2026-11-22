#!/usr/bin/env python

import os
import sys
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from signxml import SignatureConstructionMethod, SignatureConfiguration, XMLVerifier
from signxml.algorithms import DigestAlgorithm, SignatureMethod
from signxml.exceptions import InvalidInput
from signxml.legacy_review import (
    AdmissionPolicy,
    AdmissionPolicyTable,
    LegacyDocumentSigner,
    OfflineReviewer,
    ReviewError,
    ReviewOutcome,
    build_default_policy_table,
    document_fingerprint,
    issue_trusted_time_evidence,
    issue_upgrade,
    review_reissued_document,
    verify_upgrade_receipt,
)

LEGACY_TIME = datetime(2023, 6, 1, tzinfo=timezone.utc)
REVIEW_TIME = datetime(2025, 6, 1, tzinfo=timezone.utc)
UPGRADE_TIME = datetime(2025, 6, 2, tzinfo=timezone.utc)


def make_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_acceptance_document():
    return etree.fromstring(
        '<document xmlns="urn:example:acceptance">'
        '<acceptance-record date="2023-05-01">初验通过</acceptance-record>'
        '<acceptance-record date="2023-06-01">复验通过</acceptance-record>'
        "<body>历史验收结论正文</body>"
        "</document>"
    )


class LegacyReviewTestCase(unittest.TestCase):
    def setUp(self):
        self.document_key = make_rsa_key()
        self.evidence_key = make_rsa_key()
        self.other_key = make_rsa_key()
        self.policy_table = build_default_policy_table()
        self.reviewer = OfflineReviewer(
            trusted_public_key=self.document_key.public_key(),
            trusted_evidence_key=self.evidence_key.public_key(),
            policy_tables=self.policy_table,
            now=REVIEW_TIME,
        )
        legacy_signer = LegacyDocumentSigner(
            method=SignatureConstructionMethod.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA1,
            digest_algorithm=DigestAlgorithm.SHA1,
        )
        signed_root = legacy_signer.sign(build_acceptance_document(), key=self.document_key)
        self.legacy_document = etree.tostring(signed_root, encoding="utf-8", xml_declaration=True)
        self.evidence = issue_trusted_time_evidence(
            self.legacy_document,
            attestation_key=self.evidence_key,
            attestation_time=LEGACY_TIME,
        )

    def test_policy_table_resolves_historical_and_current_versions(self):
        historical = self.policy_table.policy_at(LEGACY_TIME)
        current = self.policy_table.current_policy(REVIEW_TIME)
        self.assertEqual(historical.version, "v1")
        self.assertEqual(current.version, "v2")
        self.assertTrue(historical.admits(SignatureMethod.RSA_SHA1, DigestAlgorithm.SHA1))
        self.assertFalse(current.admits(SignatureMethod.RSA_SHA1, DigestAlgorithm.SHA1))
        self.assertTrue(current.admits(SignatureMethod.RSA_SHA256, DigestAlgorithm.SHA256))

    def test_policy_table_rejects_time_before_first_policy(self):
        with self.assertRaisesRegex(ReviewError, "no admission policy in force"):
            self.policy_table.policy_at(datetime(1969, 1, 1, tzinfo=timezone.utc))

    def test_naive_timestamps_are_rejected(self):
        with self.assertRaises(ReviewError):
            issue_trusted_time_evidence(
                self.legacy_document,
                attestation_key=self.evidence_key,
                attestation_time=datetime(2023, 6, 1),
            )

    def test_legacy_document_is_historical_accepted_but_needs_reissue(self):
        report = self.reviewer.review(self.legacy_document, time_evidence=self.evidence)
        self.assertIs(report.outcome, ReviewOutcome.ACCEPTED_HISTORIC_REISSUE_NEEDED)
        self.assertTrue(report.historical_accepted)
        self.assertTrue(report.reissue_required)
        self.assertEqual(report.historical_policy_version, "v1")
        self.assertEqual(report.current_policy_version, "v2")
        self.assertIs(report.signature_method, SignatureMethod.RSA_SHA1)
        self.assertIs(report.digest_algorithm, DigestAlgorithm.SHA1)
        self.assertFalse(report.current_policy_admitted)
        checklist_names = {item.name: item for item in report.checklist}
        self.assertTrue(checklist_names["cryptographic-verification"].passed)
        self.assertTrue(checklist_names["historical-admission"].passed)
        self.assertFalse(checklist_names["current-admission"].passed)
        self.assertFalse(checklist_names["current-strict-verification"].passed)
        self.assertIn("does not undo the historical acceptance", checklist_names["current-strict-verification"].detail)

    def test_default_verifier_rejects_sha1_but_history_stands(self):
        with self.assertRaises(InvalidInput):
            XMLVerifier().verify(self.legacy_document, expect_config=SignatureConfiguration(require_x509=False))
        report = self.reviewer.review(self.legacy_document, time_evidence=self.evidence)
        self.assertTrue(report.historical_accepted)

    def test_missing_evidence_is_reported_not_raised(self):
        report = self.reviewer.review(self.legacy_document)
        self.assertIs(report.outcome, ReviewOutcome.REJECTED_NO_EVIDENCE)
        self.assertFalse(report.historical_accepted)

    def test_forged_evidence_is_rejected(self):
        forged = issue_trusted_time_evidence(
            self.legacy_document,
            attestation_key=self.other_key,
            attestation_time=LEGACY_TIME,
        )
        report = self.reviewer.review(self.legacy_document, time_evidence=forged)
        self.assertIs(report.outcome, ReviewOutcome.REJECTED_EVIDENCE)
        self.assertFalse(any(item.passed for item in report.checklist if item.name == "trusted-time-evidence"))

    def test_evidence_bound_to_other_document_is_rejected(self):
        other_root = build_acceptance_document()
        body = other_root.find(".//{urn:example:acceptance}body")
        body.text = "另一份不相关文书的正文"
        other_document = LegacyDocumentSigner(
            method=SignatureConstructionMethod.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA1,
            digest_algorithm=DigestAlgorithm.SHA1,
        ).sign(other_root, key=self.document_key)
        other_bytes = etree.tostring(other_document, encoding="utf-8", xml_declaration=True)
        foreign_evidence = issue_trusted_time_evidence(
            other_bytes, attestation_key=self.evidence_key, attestation_time=LEGACY_TIME
        )
        report = self.reviewer.review(self.legacy_document, time_evidence=foreign_evidence)
        self.assertIs(report.outcome, ReviewOutcome.REJECTED_TAMPERED)
        binding = next(item for item in report.checklist if item.name == "evidence-document-binding")
        self.assertFalse(binding.passed)

    def test_body_substitution_is_detected_as_tampering(self):
        swapped = self.legacy_document.replace("历史验收结论正文".encode("utf-8"), "被替换后的正文".encode("utf-8"))
        self.assertNotEqual(swapped, self.legacy_document)
        report = self.reviewer.review(swapped, time_evidence=self.evidence)
        self.assertIs(report.outcome, ReviewOutcome.REJECTED_TAMPERED)
        self.assertFalse(report.historical_accepted)
        checklist_names = {item.name: item for item in report.checklist}
        self.assertFalse(checklist_names["cryptographic-verification"].passed)
        rendered = report.render_checklist()
        self.assertIn("rejected-tampered", rendered)
        self.assertIn("[FAIL] cryptographic-verification", rendered)

    def test_signature_with_untrusted_key_is_rejected(self):
        foreign_signer = LegacyDocumentSigner(
            method=SignatureConstructionMethod.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA1,
            digest_algorithm=DigestAlgorithm.SHA1,
        )
        foreign_document = etree.tostring(
            foreign_signer.sign(build_acceptance_document(), key=self.other_key),
            encoding="utf-8",
            xml_declaration=True,
        )
        foreign_evidence = issue_trusted_time_evidence(
            foreign_document, attestation_key=self.evidence_key, attestation_time=LEGACY_TIME
        )
        report = self.reviewer.review(foreign_document, time_evidence=foreign_evidence)
        self.assertIs(report.outcome, ReviewOutcome.REJECTED_TAMPERED)
        self.assertFalse({item.name for item in report.checklist if not item.passed}.isdisjoint({"signing-key-match"}))

    def test_unadmitted_algorithm_at_evidence_time_is_rejected(self):
        strict_historical = AdmissionPolicy(
            version="strict-v1",
            effective_from=datetime(1970, 1, 1, tzinfo=timezone.utc),
            signature_methods=frozenset(method for method in SignatureMethod if "SHA1" not in method.name),
            digest_algorithms=frozenset(algorithm for algorithm in DigestAlgorithm if "SHA1" not in algorithm.name),
        )
        strict_table = AdmissionPolicyTable(name="strict", policies=(strict_historical,))
        strict_reviewer = OfflineReviewer(
            trusted_public_key=self.document_key.public_key(),
            trusted_evidence_key=self.evidence_key.public_key(),
            policy_tables=strict_table,
            now=REVIEW_TIME,
        )
        report = strict_reviewer.review(self.legacy_document, time_evidence=self.evidence)
        self.assertIs(report.outcome, ReviewOutcome.REJECTED_UNADMITTED_AT_TIME)
        self.assertFalse(report.historical_accepted)

    def test_upgrade_reissues_same_material_and_receipt_binds_both(self):
        bundle = issue_upgrade(
            self.reviewer, self.legacy_document, reissue_key=self.document_key, time_evidence=self.evidence
        )
        ok, items = verify_upgrade_receipt(
            bundle,
            original_document=self.legacy_document,
            trusted_reissue_key=self.document_key.public_key(),
        )
        self.assertTrue(ok)
        self.assertTrue(all(item.passed for item in items))
        self.assertEqual(
            bundle.receipt.original_fingerprint_hex,
            document_fingerprint(self.legacy_document).hex(),
        )
        self.assertEqual(
            bundle.receipt.reissued_fingerprint_hex,
            document_fingerprint(bundle.reissued_document).hex(),
        )
        self.assertIs(bundle.receipt.reissued_signature_method, SignatureMethod.RSA_SHA256)
        fresh_evidence = issue_trusted_time_evidence(
            bundle.reissued_document, attestation_key=self.evidence_key, attestation_time=UPGRADE_TIME
        )
        reissued_report = review_reissued_document(self.reviewer, bundle, current_time_evidence=fresh_evidence)
        self.assertIs(reissued_report.outcome, ReviewOutcome.ACCEPTED_HISTORIC_CURRENT)
        self.assertFalse(reissued_report.reissue_required)

    def test_reissued_document_preserves_verified_body(self):
        bundle = issue_upgrade(
            self.reviewer, self.legacy_document, reissue_key=self.document_key, time_evidence=self.evidence
        )
        original_payload = self.reviewer.review(self.legacy_document, time_evidence=self.evidence).signed_data
        reissued_payload = self.reviewer.review(
            bundle.reissued_document,
            time_evidence=issue_trusted_time_evidence(
                bundle.reissued_document,
                attestation_key=self.evidence_key,
                attestation_time=UPGRADE_TIME,
            ),
        ).signed_data
        self.assertEqual(original_payload, reissued_payload)

    def test_receipt_detects_body_swapped_document(self):
        bundle = issue_upgrade(
            self.reviewer, self.legacy_document, reissue_key=self.document_key, time_evidence=self.evidence
        )
        swapped = self.legacy_document.replace("历史验收结论正文".encode("utf-8"), "偷换后的另一正文".encode("utf-8"))
        ok, items = verify_upgrade_receipt(
            bundle,
            original_document=swapped,
            trusted_reissue_key=self.document_key.public_key(),
        )
        self.assertFalse(ok)
        binding = next(item for item in items if item.name == "original-material-binding")
        self.assertFalse(binding.passed)

    def test_upgrade_refuses_tampered_and_current_documents(self):
        swapped = self.legacy_document.replace("历史验收结论正文".encode("utf-8"), "篡改正文".encode("utf-8"))
        with self.assertRaisesRegex(ReviewError, "not historically accepted"):
            issue_upgrade(self.reviewer, swapped, reissue_key=self.document_key, time_evidence=self.evidence)
        modern_signer = LegacyDocumentSigner(
            method=SignatureConstructionMethod.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
        )
        modern_document = etree.tostring(
            modern_signer.sign(build_acceptance_document(), key=self.document_key),
            encoding="utf-8",
            xml_declaration=True,
        )
        modern_evidence = issue_trusted_time_evidence(
            modern_document, attestation_key=self.evidence_key, attestation_time=UPGRADE_TIME
        )
        with self.assertRaisesRegex(ReviewError, "no re-signature is required"):
            issue_upgrade(self.reviewer, modern_document, reissue_key=self.document_key, time_evidence=modern_evidence)

    def test_upgrade_with_deprecated_algorithm_is_refused(self):
        with self.assertRaisesRegex(ReviewError, "not admitted by current policy"):
            issue_upgrade(
                self.reviewer,
                self.legacy_document,
                reissue_key=self.document_key,
                time_evidence=self.evidence,
                signature_method=SignatureMethod.RSA_SHA1,
                digest_algorithm=DigestAlgorithm.SHA1,
            )

    def test_self_reported_dates_never_drive_the_decision(self):
        redated = self.legacy_document.replace(b"2023-05-01", b"2025-05-01")
        report_original = self.reviewer.review(self.legacy_document, time_evidence=self.evidence)
        report_redated = self.reviewer.review(redated, time_evidence=self.evidence)
        self.assertIs(report_original.outcome, ReviewOutcome.ACCEPTED_HISTORIC_REISSUE_NEEDED)
        self.assertIs(report_redated.outcome, ReviewOutcome.REJECTED_TAMPERED)
        self.assertEqual(report_original.evidence_time, LEGACY_TIME)

    def test_checklists_distinguish_reissued_and_swapped_documents(self):
        bundle = issue_upgrade(
            self.reviewer, self.legacy_document, reissue_key=self.document_key, time_evidence=self.evidence
        )
        fresh_evidence = issue_trusted_time_evidence(
            bundle.reissued_document, attestation_key=self.evidence_key, attestation_time=UPGRADE_TIME
        )
        reissued_report = review_reissued_document(self.reviewer, bundle, current_time_evidence=fresh_evidence)
        swapped = self.legacy_document.replace("历史验收结论正文".encode("utf-8"), "替换正文".encode("utf-8"))
        swapped_report = self.reviewer.review(swapped, time_evidence=self.evidence)
        self.assertNotEqual(reissued_report.outcome, swapped_report.outcome)
        reissued_text = reissued_report.render_checklist()
        swapped_text = swapped_report.render_checklist()
        self.assertIn("accepted-historic-and-current", reissued_text)
        self.assertIn("reissue-required: False", reissued_text)
        self.assertIn("rejected-tampered", swapped_text)
        self.assertIn("[FAIL] cryptographic-verification", swapped_text)


if __name__ == "__main__":
    unittest.main()
