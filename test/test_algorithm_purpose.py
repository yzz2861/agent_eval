import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from lxml import etree

from signxml import (
    AlgorithmAdmission,
    AlgorithmPolicyViolation,
    CanonicalizationMethod,
    DigestAlgorithm,
    SignatureAlgorithmPolicy,
    SignatureConfiguration,
    SignatureMethod,
    SignaturePurpose,
    XMLSigner,
    XMLVerifier,
    admission_matrix,
)
from signxml.xades import XAdESSignatureConfiguration, XAdESSigner, XAdESVerifier


def _make_rsa_certificate(key):
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "algorithm-policy-test")])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
        .sign(key, hashes.SHA256())
    )


class TestAlgorithmPurposePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec_key = ec.generate_private_key(ec.SECP256R1())
        cls.cert = _make_rsa_certificate(cls.rsa_key)
        cls.document = etree.fromstring(b"<Receipt><Item>42</Item></Receipt>")

    def _new_document(self):
        return etree.fromstring(etree.tostring(self.document))

    def test_admission_matrix_distinguishes_denied_unconfigured_and_unsupported(self):
        archive = SignatureAlgorithmPolicy.for_purpose(SignaturePurpose.ARCHIVE)
        delivery = SignatureAlgorithmPolicy.for_purpose(SignaturePurpose.DELIVERY)
        expected = {
            (SignatureMethod.RSA_SHA256, DigestAlgorithm.SHA256): (
                AlgorithmAdmission.UNCONFIGURED,
                AlgorithmAdmission.ALLOWED,
                AlgorithmAdmission.ALLOWED,
            ),
            (SignatureMethod.SHA256_RSA_MGF1, DigestAlgorithm.SHA256): (
                AlgorithmAdmission.UNCONFIGURED,
                AlgorithmAdmission.ALLOWED,
                AlgorithmAdmission.DENIED,
            ),
            (SignatureMethod.RSA_SHA256, DigestAlgorithm.SHA3_256): (
                AlgorithmAdmission.UNCONFIGURED,
                AlgorithmAdmission.ALLOWED,
                AlgorithmAdmission.DENIED,
            ),
            (SignatureMethod.ECDSA_SHA3_256, DigestAlgorithm.SHA256): (
                AlgorithmAdmission.UNCONFIGURED,
                AlgorithmAdmission.ALLOWED,
                AlgorithmAdmission.DENIED,
            ),
        }
        for (signature_method, digest_algorithm), statuses in expected.items():
            with self.subTest(signature_method=signature_method, digest_algorithm=digest_algorithm):
                self.assertEqual(
                    SignatureAlgorithmPolicy.for_purpose(None).admission(signature_method, digest_algorithm),
                    statuses[0],
                )
                self.assertEqual(archive.admission(signature_method, digest_algorithm), statuses[1])
                self.assertEqual(delivery.admission(signature_method, digest_algorithm), statuses[2])

        for purpose in (None, SignaturePurpose.ARCHIVE, SignaturePurpose.DELIVERY):
            with self.subTest(purpose=purpose):
                matrix = admission_matrix(
                    purpose,
                    signature_methods=("urn:example:unsupported", SignatureMethod.RSA_SHA256),
                    digest_algorithms=(DigestAlgorithm.SHA256,),
                )
                self.assertEqual(
                    matrix[("urn:example:unsupported", DigestAlgorithm.SHA256, None)], AlgorithmAdmission.UNSUPPORTED
                )
                self.assertEqual(
                    matrix[(SignatureMethod.RSA_SHA256, DigestAlgorithm.SHA256, None)],
                    AlgorithmAdmission.UNCONFIGURED if purpose is None else AlgorithmAdmission.ALLOWED,
                )

        self.assertEqual(
            SignatureConfiguration().admission(SignatureMethod.RSA_SHA256, DigestAlgorithm.SHA256),
            AlgorithmAdmission.UNCONFIGURED,
        )
        self.assertEqual(
            SignatureConfiguration(purpose=SignaturePurpose.DELIVERY).admission(
                SignatureMethod.SHA256_RSA_MGF1, DigestAlgorithm.SHA256
            ),
            AlgorithmAdmission.DENIED,
        )
        self.assertEqual(
            SignatureAlgorithmPolicy(signature_methods=[]).admission(SignatureMethod.RSA_SHA256),
            AlgorithmAdmission.DENIED,
        )

    def test_delivery_profile_rejects_archive_only_c14n(self):
        signed = XMLSigner(
            c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0_WITH_COMMENTS,
            purpose=SignaturePurpose.ARCHIVE,
        ).sign(self._new_document(), key=self.rsa_key, cert=[self.cert])
        XMLVerifier().verify(
            etree.tostring(signed),
            x509_cert=self.cert,
            expect_config=SignatureConfiguration(purpose=SignaturePurpose.ARCHIVE),
        )
        with self.assertRaisesRegex(AlgorithmPolicyViolation, "Canonicalization method.*for purpose delivery"):
            XMLVerifier().verify(
                etree.tostring(signed),
                x509_cert=self.cert,
                expect_config=SignatureConfiguration(purpose=SignaturePurpose.DELIVERY),
            )
        with self.assertRaisesRegex(AlgorithmPolicyViolation, "Canonicalization method.*for purpose delivery"):
            XMLSigner(
                c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0_WITH_COMMENTS,
                purpose=SignaturePurpose.DELIVERY,
            )

    def test_delivery_profile_rejects_archive_only_signature_and_digest(self):
        for signature_algorithm, digest_algorithm in (
            (SignatureMethod.SHA256_RSA_MGF1, DigestAlgorithm.SHA256),
            (SignatureMethod.RSA_SHA256, DigestAlgorithm.SHA3_256),
            (SignatureMethod.ECDSA_SHA3_256, DigestAlgorithm.SHA256),
        ):
            with self.subTest(signature_algorithm=signature_algorithm, digest_algorithm=digest_algorithm):
                with self.assertRaisesRegex(
                    AlgorithmPolicyViolation, "forbidden by configuration for purpose delivery"
                ):
                    XMLSigner(
                        signature_algorithm=signature_algorithm,
                        digest_algorithm=digest_algorithm,
                        purpose=SignaturePurpose.DELIVERY,
                    )

    def test_acceptance_sample_is_valid_but_rejected_for_delivery(self):
        signed = XMLSigner(
            signature_algorithm=SignatureMethod.SHA256_RSA_MGF1,
            digest_algorithm=DigestAlgorithm.SHA256,
            purpose=SignaturePurpose.ARCHIVE,
        ).sign(self._new_document(), key=self.rsa_key, cert=[self.cert])

        # With no purpose policy the signature is cryptographically valid. This is the "unconfigured" case.
        XMLVerifier().verify(etree.tostring(signed), x509_cert=self.cert)

        # The same bytes pass the archival policy, but are refused by the delivery endpoint.
        XMLVerifier().verify(
            etree.tostring(signed),
            x509_cert=self.cert,
            expect_config=SignatureConfiguration(purpose=SignaturePurpose.ARCHIVE),
        )
        with self.assertRaisesRegex(AlgorithmPolicyViolation, "Signature method SHA256_RSA_MGF1.*delivery"):
            XMLVerifier().verify(
                etree.tostring(signed),
                x509_cert=self.cert,
                expect_config=SignatureConfiguration(purpose=SignaturePurpose.DELIVERY),
            )

    def test_xades_acceptance_sample_is_valid_but_rejected_for_delivery(self):
        signed = XAdESSigner(
            signature_algorithm=SignatureMethod.SHA256_RSA_MGF1,
            digest_algorithm=DigestAlgorithm.SHA256,
            purpose=SignaturePurpose.ARCHIVE,
        ).sign(self._new_document(), key=self.rsa_key, cert=[self.cert])
        results = XAdESVerifier().verify(
            etree.tostring(signed),
            x509_cert=self.cert,
            expect_config=XAdESSignatureConfiguration(purpose=SignaturePurpose.ARCHIVE),
        )
        self.assertEqual(len(results), 3)
        with self.assertRaisesRegex(AlgorithmPolicyViolation, "Signature method SHA256_RSA_MGF1.*delivery"):
            XAdESVerifier().verify(
                etree.tostring(signed),
                x509_cert=self.cert,
                expect_config=XAdESSignatureConfiguration(purpose=SignaturePurpose.DELIVERY),
            )


if __name__ == "__main__":
    unittest.main()
