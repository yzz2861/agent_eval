"""Tests for offline DSSE verification evidence."""

import copy
import datetime
import json
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from securesystemslib.dsse import Envelope, verify_evidence
from securesystemslib.exceptions import EvidenceError, VerificationError
from securesystemslib.signer import CryptoSigner, Key, SSlibKey

PEMS_DIR = Path(__file__).parent / "data" / "pems"
EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "offline_dsse"
ED25519_ARTIFACT = b"artifact-000\n"
ED25519_ARTIFACT_CHANGED = b"artifact-001\n"


class TestEvidence(unittest.TestCase):
    """Tests for sealing and recomputing DSSE evidence."""

    @classmethod
    def setUpClass(cls):
        cls.signers = {}
        cls.keys = {}
        for keytype in ("rsa", "ecdsa", "ed25519"):
            private_key = load_pem_private_key(
                (PEMS_DIR / f"{keytype}_private.pem").read_bytes(), None
            )
            signer = CryptoSigner(private_key)
            cls.signers[keytype] = signer
            cls.keys[keytype] = signer.public_key

    def _envelope(self, *keytypes):
        envelope = Envelope(ED25519_ARTIFACT, "application/vnd.example+json", {})
        for keytype in keytypes:
            envelope.sign(self.signers[keytype])
        return envelope

    def test_evidence_records_exact_input_and_public_identity(self):
        envelope = self._envelope("ed25519")
        evidence = envelope.verify_with_evidence(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
            artifact_name="artifact.txt",
        )
        document = evidence.to_dict()

        self.assertEqual(evidence.sealed_status, "verified")
        self.assertEqual(document["signatureInput"]["rule"], "DSSEv1-PAE")
        self.assertEqual(
            document["signatureInput"]["paeBase64"],
            evidence.to_dict()["signatureInput"]["pae"],
        )
        self.assertEqual(
            document["signatureInput"]["paeBase64"],
            __import__("base64").b64encode(envelope.pae()).decode(),
        )
        self.assertEqual(
            document["artifact"]["digest"]["sha256"],
            __import__("hashlib").sha256(ED25519_ARTIFACT).hexdigest(),
        )
        self.assertEqual(document["artifact"]["name"], "artifact.txt")
        self.assertEqual(
            document["signatures"][0]["algorithm"],
            {"keytype": "ed25519", "scheme": "ed25519"},
        )
        self.assertIn("key", document["signatures"][0])
        self.assertIn("keyFingerprint", document["signatures"][0])
        self.assertNotIn("PRIVATE KEY", json.dumps(document))

    def test_reformatted_outer_json_still_verifies(self):
        envelope = self._envelope("ed25519")
        evidence = envelope.verify_with_evidence(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
        )
        reformatted = json.dumps(evidence.to_dict(), indent=4, sort_keys=True)
        report = verify_evidence(
            reformatted,
            keys=[self.keys["ed25519"]],
            artifact=ED25519_ARTIFACT,
        )
        self.assertTrue(report.passed)
        self.assertEqual(report.status, "verified")

    def test_artifact_changed_by_one_byte_is_rejected(self):
        envelope = self._envelope("ed25519")
        evidence = envelope.verify_with_evidence(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
        )
        report = evidence.verify(
            keys=[self.keys["ed25519"]],
            artifact=ED25519_ARTIFACT_CHANGED,
        )
        self.assertEqual(report.status, "rejected")
        self.assertTrue(report.recomputable)
        self.assertEqual(report["artifact"]["status"], "invalid")
        self.assertEqual(report["artifact"]["reason"], "artifact-digest-mismatch")
        self.assertIn("artifact-digest-mismatch", report.message)
        with self.assertRaises(VerificationError):
            report.raise_for_status()

    def test_unverifiable_and_invalid_are_distinct(self):
        envelope = self._envelope("ed25519")
        evidence = envelope.verify_with_evidence(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
        )

        missing_key = evidence.to_dict()
        del missing_key["signatures"][0]["key"]
        report = verify_evidence(missing_key, artifact=ED25519_ARTIFACT)
        self.assertEqual(report.status, "unverifiable")
        self.assertFalse(report.recomputable)
        self.assertEqual(report["signers"][0]["status"], "unverifiable")

        bad_signature = evidence.to_dict()
        bad_signature["signatures"][0]["signature"]["sig"] = "AAAA"
        report = verify_evidence(
            bad_signature,
            keys=[self.keys["ed25519"]],
            artifact=ED25519_ARTIFACT,
        )
        self.assertEqual(report.status, "rejected")
        self.assertTrue(report.recomputable)
        self.assertEqual(report["signers"][0]["status"], "invalid")

    def test_multiple_signers_keep_their_own_algorithm(self):
        envelope = self._envelope("rsa", "ecdsa", "ed25519")
        keys = [self.keys[name] for name in ("rsa", "ecdsa", "ed25519")]
        evidence = envelope.verify_with_evidence(
            keys,
            3,
            artifact=ED25519_ARTIFACT,
        )
        document = evidence.to_dict()
        algorithms = {
            signer["keyid"]: signer["algorithm"] for signer in document["signatures"]
        }
        self.assertEqual(
            algorithms[self.keys["rsa"].keyid]["scheme"], "rsassa-pss-sha256"
        )
        self.assertEqual(
            algorithms[self.keys["ecdsa"].keyid]["scheme"], "ecdsa-sha2-nistp256"
        )
        self.assertEqual(algorithms[self.keys["ed25519"].keyid]["scheme"], "ed25519")
        self.assertTrue(evidence.verify(keys=keys, artifact=ED25519_ARTIFACT).passed)

    def test_disabled_backend_preserves_sealed_conclusion(self):
        envelope = self._envelope("ed25519")
        evidence = envelope.verify_with_evidence(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
        )
        report = evidence.verify(
            keys=[self.keys["ed25519"]],
            artifact=ED25519_ARTIFACT,
            backend_status={"pyca/cryptography": "retired"},
        )
        self.assertEqual(report.status, "unverifiable")
        self.assertFalse(report.recomputable)
        preserved = report["conclusion"]["preservedConclusions"]
        self.assertEqual(preserved[0]["sealedStatus"], "verified")
        self.assertEqual(preserved[0]["reason"], "verification-backend-retired")

    def test_recorded_scheme_wins_over_caller_default(self):
        private_key = load_pem_private_key(
            (PEMS_DIR / "rsa_private.pem").read_bytes(), None
        )
        recorded_key = SSlibKey.from_crypto(
            private_key.public_key(), scheme="rsassa-pss-sha384"
        )
        signer = CryptoSigner(private_key, recorded_key)
        envelope = Envelope(b"payload", "text/plain", {})
        envelope.sign(signer)
        evidence = envelope.verify_with_evidence([recorded_key], 1, artifact=b"payload")
        self.assertEqual(
            evidence.to_dict()["signatures"][0]["algorithm"]["scheme"],
            "rsassa-pss-sha384",
        )

        caller_default_key = SSlibKey.from_crypto(private_key.public_key())
        self.assertEqual(caller_default_key.scheme, "rsassa-pss-sha256")
        report = evidence.verify(
            keys=[caller_default_key],
            artifact=b"payload",
        )
        self.assertTrue(report.passed)

        missing_scheme = evidence.to_dict()
        del missing_scheme["signatures"][0]["key"]["scheme"]
        report = verify_evidence(missing_scheme, artifact=b"payload")
        self.assertEqual(report.status, "unverifiable")
        self.assertFalse(report.recomputable)

    def test_caller_supplied_certificate(self):
        private_key = load_pem_private_key(
            (PEMS_DIR / "ed25519_private.pem").read_bytes(), None
        )
        signer = CryptoSigner(private_key)
        envelope = Envelope(b"payload", "text/plain", {})
        envelope.sign(signer)
        evidence = envelope.verify_with_evidence(
            [signer.public_key], 1, artifact=b"payload"
        )

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        now = datetime.datetime.now(datetime.UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(private_key, None)
        )

        report = evidence.verify(
            certificates=[certificate],
            allow_embedded_keys=False,
            artifact=b"payload",
        )
        self.assertTrue(report.passed)

    def test_private_key_material_is_refused(self):
        envelope = self._envelope("ed25519")
        evidence = envelope.verify_with_evidence(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
        )
        document = copy.deepcopy(evidence.to_dict())
        document["private_key"] = "-----BEGIN PRIVATE KEY-----\nsecret\n"
        with self.assertRaises(EvidenceError):
            type(evidence)(document)

    def test_verify_evidence_does_not_need_embedded_key_by_default(self):
        class PublicOnlyKey(Key):
            def __init__(self, key):
                super().__init__(
                    key.keyid, key.keytype, key.scheme, copy.deepcopy(key.keyval)
                )
                self._key = key

            @classmethod
            def from_dict(cls, keyid, key_dict):
                raise NotImplementedError

            def to_dict(self):
                return self._key.to_dict()

            def verify_signature(self, signature, data):
                return self._key.verify_signature(signature, data)

        envelope = self._envelope("ed25519")
        evidence = envelope.verify_with_evidence(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
        )
        report = verify_evidence(
            evidence.to_dict(),
            keys=[PublicOnlyKey(self.keys["ed25519"])],
            artifact=ED25519_ARTIFACT,
        )
        self.assertTrue(report.passed)

    def test_evidence_output_destination(self):
        envelope = self._envelope("ed25519")
        envelope.verify(
            [self.keys["ed25519"]],
            1,
            artifact=ED25519_ARTIFACT,
            evidence=True,
        )
        self.assertEqual(envelope.last_evidence.sealed_status, "verified")

    def test_exchange_samples(self):
        sample1 = EXAMPLES_DIR / "sample1"
        sample2 = EXAMPLES_DIR / "sample2"

        evidence = json.loads((sample1 / "evidence.json").read_text())
        reformatted = json.dumps(evidence, indent=2, sort_keys=True)
        report = verify_evidence(
            reformatted,
            keys=[self.keys["ed25519"]],
            artifact=(sample1 / "artifact.txt").read_bytes(),
        )
        self.assertTrue(report.passed)

        artifact1 = (sample1 / "artifact.txt").read_bytes()
        artifact2 = (sample2 / "artifact.txt").read_bytes()
        self.assertEqual(len(artifact1), len(artifact2))
        self.assertEqual(
            sum(
                left != right for left, right in zip(artifact1, artifact2, strict=True)
            ),
            1,
        )

        report = verify_evidence(
            sample2 / "evidence.json",
            keys=[self.keys["ed25519"]],
            artifact=artifact2,
        )
        self.assertEqual(report.status, "rejected")
        self.assertEqual(report["artifact"]["reason"], "artifact-digest-mismatch")

    def test_raw_public_key_material_is_caller_supplied(self):
        sample = EXAMPLES_DIR / "sample1"
        pem = (sample / "public_key.pem").read_bytes()
        report = verify_evidence(
            sample / "evidence.json",
            keys=[pem],
            artifact=(sample / "artifact.txt").read_bytes(),
        )
        self.assertTrue(report.passed)


if __name__ == "__main__":
    unittest.main()
