import os
import sys
import unittest

from cryptography import x509
from lxml import etree

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from signxml import (
    AttachmentDeclaration,
    SignatureConfiguration,
    SignatureMethod,
    VerifiedAttachment,
    XMLSigner,
    XMLVerifier,
    combine_verifications,
)
from signxml.xades import XAdESSignaturePolicy, XAdESSigner, XAdESVerifier, XAdESVerifyResult
from signxml.algorithms import DigestAlgorithm


def _load_example_keys():
    base = os.path.dirname(__file__)
    with open(os.path.join(base, "example.pem"), "rb") as fh:
        cert = fh.read()
    with open(os.path.join(base, "example.key"), "rb") as fh:
        key = fh.read()
    return cert, key


def _verification_time(cert_text):
    certificate = x509.load_pem_x509_certificate(cert_text)
    return certificate.not_valid_before_utc + (certificate.not_valid_after_utc - certificate.not_valid_before_utc) / 2


class TestCombinedVerification(unittest.TestCase):
    def test_order_and_name_independent_lookup(self):
        key = b"receipt-demo-key"
        data = etree.fromstring(b'<root><one Id="one">first</one><two Id="two">second</two></root>')
        signed = XMLSigner(signature_algorithm=SignatureMethod.HMAC_SHA256).sign(
            data, key=key, reference_uri=["one", "two"]
        )
        results = XMLVerifier().verify(
            signed,
            hmac_key=key,
            expect_references=2,
            expect_config=SignatureConfiguration(require_x509=False),
        )

        combined = combine_verifications(results)
        self.assertEqual(len(combined), 2)
        self.assertEqual({attachment.archive_name for attachment in combined}, {"one", "two"})
        self.assertEqual(len(combined.independent_sources), 1)
        self.assertEqual(combined.minimal_sources, combined.independent_sources)
        self.assertTrue(combined.sufficient)

        for attachment in combined:
            self.assertIsNotNone(attachment.digest_value)
            self.assertEqual(attachment.clause_version, "HMAC_SHA256")
            self.assertEqual(attachment.responsibility, None)
            self.assertIsNotNone(combined.get(attachment.archive_name, attachment.digest_value))

        reordered = combine_verifications(reversed(results))
        self.assertEqual(
            {attachment.archive_name: attachment.digest_value for attachment in combined},
            {attachment.archive_name: attachment.digest_value for attachment in reordered},
        )
        for attachment in combined:
            self.assertEqual(
                reordered.get(attachment.archive_name, attachment.digest_value).declaration,
                attachment.declaration,
            )

    def test_missing_declaration_does_not_hide_present_attachments(self):
        data = etree.fromstring(b'<root><one Id="one">first</one><two Id="two">second</two></root>')
        key = b"receipt-demo-key"
        signed = XMLSigner(signature_algorithm=SignatureMethod.HMAC_SHA256).sign(
            data, key=key, reference_uri=["one", "two"]
        )
        results = XMLVerifier().verify(
            signed,
            hmac_key=key,
            expect_references=2,
            expect_config=SignatureConfiguration(require_x509=False),
        )
        expected = [
            AttachmentDeclaration(archive_name="one"),
            AttachmentDeclaration(archive_name="two"),
            AttachmentDeclaration(archive_name="three"),
        ]

        combined = combine_verifications(results, expected=expected)
        self.assertFalse(combined.complete)
        self.assertEqual([declaration.archive_name for declaration in combined.missing], ["three"])
        self.assertIsNotNone(combined.get("one"))
        self.assertIsNotNone(combined.get("two"))
        self.assertIsNone(combined.get("three"))
        self.assertFalse(combined.sufficient)

    def test_duplicate_names_are_disambiguated_by_digest(self):
        first = VerifiedAttachment(
            archive_name="report.xml",
            digest_value=b"a" * 32,
            clause_version="policy:1",
            responsibility="author",
            source_id="key:first",
        )
        second = VerifiedAttachment(
            archive_name="report.xml",
            digest_value=b"b" * 32,
            clause_version="policy:1",
            responsibility="reviewer",
            source_id="key:second",
        )
        combined = combine_verifications([second, first])

        self.assertEqual(len(combined.lookup("report.xml")), 2)
        self.assertEqual(combined.get("report.xml", b"a" * 32), first)
        self.assertEqual(combined.get("report.xml", b"b" * 32), second)
        self.assertEqual(combined.get("report.xml", responsibility="reviewer"), second)
        self.assertEqual(set(combined.independent_sources), {"key:first", "key:second"})

    def test_minimal_independent_source_cover(self):
        declarations = [AttachmentDeclaration(archive_name="a"), AttachmentDeclaration(archive_name="b")]
        attachments = [
            VerifiedAttachment(archive_name="a", digest_value=b"1" * 32, source_id="key:a"),
            VerifiedAttachment(archive_name="b", digest_value=b"2" * 32, source_id="key:b"),
            VerifiedAttachment(archive_name="a", digest_value=b"1" * 32, source_id="key:both"),
            VerifiedAttachment(archive_name="b", digest_value=b"2" * 32, source_id="key:both"),
        ]

        combined = combine_verifications(attachments, expected=declarations)
        self.assertEqual(combined.minimal_sources, ("key:both",))
        self.assertTrue(combined.sufficient)

        without_shared_source = combine_verifications(attachments[:2], expected=declarations)
        self.assertEqual(without_shared_source.minimal_sources, ("key:a", "key:b"))

    def test_distinct_signatures_are_distinct_sources(self):
        config = SignatureConfiguration(require_x509=False)
        results = []
        for name, key in (("a", b"source-one"), ("b", b"source-two")):
            data = etree.fromstring(f'<root><{name} Id="{name}">{name}</{name}></root>'.encode())
            signed = XMLSigner(signature_algorithm=SignatureMethod.HMAC_SHA256).sign(data, key=key, reference_uri=name)
            results.append(
                XMLVerifier().verify(
                    signed,
                    hmac_key=key,
                    expect_config=config,
                )
            )

        combined = combine_verifications(reversed(results), expected=["a", "b"])
        self.assertEqual(len(combined.independent_sources), 2)
        self.assertEqual(len(combined.minimal_sources), 2)
        self.assertTrue(combined.sufficient)

    def test_responsibility_requirements_are_reported(self):
        declarations = [AttachmentDeclaration(archive_name="a")]
        combined = combine_verifications(
            [VerifiedAttachment(archive_name="a", digest_value=b"1" * 32, source_id="key:a", roles=("author",))],
            expected=declarations,
            required_responsibilities={"author": 1, "reviewer": 1},
        )
        self.assertEqual(combined.responsibility_sources, {"author": ("key:a",)})
        self.assertEqual(combined.unsatisfied_responsibilities, ("reviewer",))
        self.assertFalse(combined.sufficient)

    def test_xades_metadata_is_attached_to_result(self):
        cert, key = _load_example_keys()
        config = SignatureConfiguration(verification_time=_verification_time(cert))
        policy = XAdESSignaturePolicy(
            Identifier="urn:sbr:signature-policy:xml:2.0",
            Description="Test description",
            DigestMethod=DigestAlgorithm.SHA256,
            DigestValue="sVHhN1eqNH/PZ1B6h//ehyC1OwRQOrz/tJ3ZYaRrBgA=",
        )
        signed = XAdESSigner(signature_policy=policy, claimed_roles=["author", "reviewer"]).sign(
            etree.fromstring(b"<doc><value>hello</value></doc>"), key=key, cert=cert
        )
        results = XAdESVerifier().verify(
            signed,
            x509_cert=cert,
            expect_references=3,
            expect_signature_policy=policy,
            expect_config=config,
        )
        xades_result = next(result for result in results if isinstance(result, XAdESVerifyResult))
        self.assertEqual(xades_result.claimed_roles, ("author", "reviewer"))
        self.assertEqual(xades_result.signature_policy_identifier, policy.Identifier)
        self.assertEqual(xades_result.signature_policy.Identifier, policy.Identifier)
        self.assertEqual(xades_result.roles, ("author", "reviewer"))
        self.assertEqual(xades_result.responsibility, "author")

        data_result = next(
            result
            for result in results
            if not isinstance(result, XAdESVerifyResult)
            and getattr(result.signed_xml, "tag", None) != "{http://uri.etsi.org/01903/v1.3.2#}SignedProperties"
        )
        self.assertEqual(data_result.roles, ("author", "reviewer"))
        self.assertEqual(data_result.responsibility, "author")
        self.assertEqual(data_result.clause_version, policy.Identifier)

        combined = combine_verifications(results)
        attachment = combined.get(xades_result.archive_name, xades_result.digest_value)
        self.assertIsNotNone(attachment)
        self.assertIn("author", attachment.roles)
        data_attachment = combined.get(data_result.archive_name, data_result.digest_value)
        self.assertIsNotNone(data_attachment)
        self.assertEqual(data_attachment.signing_certificate_digest, xades_result.signing_certificate_digest)


if __name__ == "__main__":
    unittest.main()
