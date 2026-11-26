"""Tests for offline legacy-to-DSSE conversion reviews."""

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib._internal.utils import b64enc
from securesystemslib.conversion_review import (
    DISPOSITION_REJECTED,
    DISPOSITION_RESIGN_CANDIDATE,
    DISPOSITION_REUSABLE,
    review_conversion,
    review_conversions,
    review_file,
)
from securesystemslib.conversion_review import main as review_main
from securesystemslib.dsse import Envelope
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import CryptoSigner

DATA_DIR = Path(__file__).parent / "data" / "conversion_review"
PEMS_DIR = Path(__file__).parent / "data" / "pems"


class ConversionReviewFixtureTests(unittest.TestCase):
    """The two look-alike fixtures must keep independent conclusions."""

    @classmethod
    def setUpClass(cls):
        cls.encoding_record = json.loads(
            (DATA_DIR / "same_text_different_encoding.json").read_text("utf-8")
        )
        cls.usage_record = json.loads(
            (DATA_DIR / "same_text_different_usage.json").read_text("utf-8")
        )

    def test_encoding_fixture_keeps_non_normalized_bytes(self):
        review = review_conversion(self.encoding_record)

        self.assertEqual(DISPOSITION_REUSABLE, review.disposition)
        self.assertTrue(review.verification_record_reusable)
        self.assertTrue(review.can_reuse_record)
        self.assertFalse(review.needs_resign)
        self.assertTrue(review.legacy_signature_valid)
        self.assertTrue(review.envelope_signature_valid)

        media = review.claims["media_type"]
        self.assertTrue(media.attested)
        self.assertEqual(27, media.source_byte_length)
        self.assertEqual(27, media.target_byte_length)
        self.assertIn("63616665cc81", media.source_utf8_hex or "")
        self.assertEqual(media.source_sha256, media.target_sha256)

        content = review.claims["content"]
        self.assertTrue(content.attested)
        self.assertEqual(content.source_sha256, content.target_sha256)

    def test_usage_fixture_keeps_its_own_resign_conclusion(self):
        review = review_conversion(self.usage_record)

        self.assertEqual(DISPOSITION_RESIGN_CANDIDATE, review.disposition)
        self.assertTrue(review.already_resigned)
        self.assertFalse(review.needs_resign)
        self.assertFalse(review.verification_record_reusable)

        purpose = review.claims["signing_purpose"]
        self.assertFalse(purpose.attested)
        self.assertFalse(purpose.exact_match)
        self.assertIn("value_mismatch", purpose.reasons)
        self.assertEqual(16, purpose.source_byte_length)
        self.assertEqual(14, purpose.target_byte_length)

        self.assertTrue(review.claims["content"].attested)
        self.assertTrue(review.claims["media_type"].attested)

    def test_report_preserves_both_fixture_ids(self):
        report = review_conversions([self.encoding_record, self.usage_record])
        result = report.to_dict()

        self.assertEqual(
            ["same-text-different-encoding"], result["summary"]["reusable"]
        )
        self.assertEqual(
            ["same-text-different-usage"],
            result["summary"]["resign_candidates"],
        )
        self.assertEqual([], result["summary"]["resign_required"])
        self.assertEqual(2, result["summary"]["total"])

    def test_review_file_loads_fixture(self):
        report = review_file(DATA_DIR / "same_text_different_encoding.json")
        self.assertEqual(["same-text-different-encoding"], report.reusable)

    def test_strict_cli_distinguishes_fixture_outcomes(self):
        output = io.StringIO()
        encoding_path = str(DATA_DIR / "same_text_different_encoding.json")
        usage_path = str(DATA_DIR / "same_text_different_usage.json")

        with redirect_stdout(output):
            self.assertEqual(0, review_main([encoding_path, "--strict"]))
        with redirect_stdout(output):
            self.assertEqual(1, review_main([usage_path, "--strict"]))

    def test_visual_equal_normalization_is_not_byte_equal(self):
        record = copy.deepcopy(self.encoding_record)
        # NFC looks identical to the NFD fixture in many fonts.
        record["envelope"]["payloadType"] = "application/vnd.caf\u00e9+json"

        review = review_conversion(record)

        self.assertEqual(DISPOSITION_RESIGN_CANDIDATE, review.disposition)
        self.assertFalse(review.envelope_signature_valid)
        media = review.claims["media_type"]
        self.assertFalse(media.exact_match)
        self.assertIn("value_mismatch", media.reasons)
        self.assertIn("envelope_signature_invalid", review.reasons)

    def test_invalid_legacy_signature_is_rejected(self):
        record = copy.deepcopy(self.encoding_record)
        signature = record["legacy"]["signature"]["sig"]
        record["legacy"]["signature"]["sig"] = (
            "00" + signature[2:]
            if not signature.startswith("00")
            else "11" + signature[2:]
        )

        review = review_conversion(record)

        self.assertEqual(DISPOSITION_REJECTED, review.disposition)
        self.assertFalse(review.legacy_signature_valid)
        self.assertIn("legacy_signature_invalid", review.reasons)


class ConversionReviewConstructionTests(unittest.TestCase):
    """Construct edge cases that fixtures on disk do not cover."""

    @classmethod
    def setUpClass(cls):
        private_key = load_pem_private_key(
            (PEMS_DIR / "ed25519_private.pem").read_bytes(), None
        )
        cls.signer = CryptoSigner(private_key)
        cls.key = cls.signer.public_key
        cls.key_dict = {"keyid": cls.key.keyid, **cls.key.to_dict()}

    def _signed_envelope(self, usage="release-approval"):
        payload = encode_canonical({"artifact": "demo", "usage": usage}).encode("utf-8")
        envelope = Envelope(payload, "application/vnd.demo+json", {})
        envelope.sign(self.signer)
        return envelope

    def test_usage_in_unsigned_extension_is_present_but_not_attested(self):
        envelope = self._signed_envelope()
        envelope.unrecognized_fields["usage"] = "release-approval"

        legacy_signed = {
            "content_b64": b64enc(envelope.payload),
            "media_type": envelope.payload_type,
            "usage": "release-approval",
        }
        legacy_signature = self.signer.sign(
            encode_canonical(legacy_signed).encode("utf-8")
        )
        record = {
            "id": "unsigned-usage-extension",
            "key": self.key_dict,
            "field_mapping": {
                "content": {
                    "source": "/legacy/signed/content_b64",
                    "source_encoding": "base64",
                    "target": "payload",
                },
                "media_type": {
                    "source": "/legacy/signed/media_type",
                    "target": "payload_type",
                },
                "signing_purpose": {
                    "source": "/legacy/signed/usage",
                    "target": "unsigned_extension",
                    "target_path": "/usage",
                },
            },
            "legacy": {
                "signed": legacy_signed,
                "signature": legacy_signature.to_dict(),
            },
            "envelope": envelope.to_dict(),
        }

        review = review_conversion(record)
        purpose = review.claims["signing_purpose"]

        self.assertTrue(purpose.target_present)
        self.assertTrue(purpose.exact_match)
        self.assertFalse(purpose.target_signed)
        self.assertFalse(purpose.attested)
        self.assertEqual(DISPOSITION_RESIGN_CANDIDATE, review.disposition)
        self.assertTrue(review.already_resigned)

    def test_legacy_dsse_pae_signature_is_portable(self):
        envelope = self._signed_envelope()
        pae = envelope.pae()
        pae_signature = self.signer.sign(pae)
        record = {
            "id": "portable-pae",
            "key": self.key_dict,
            "legacy": {
                "signed": {
                    "content": envelope.payload.decode("utf-8"),
                    "media_type": envelope.payload_type,
                    "usage": "release-approval",
                },
                "signed_bytes_b64": b64enc(pae),
                "signature": pae_signature.to_dict(),
                "signing_format": "dsse-pae",
            },
            "envelope": envelope.to_dict(),
        }

        review = review_conversion(record)

        self.assertTrue(review.legacy_signature_valid)
        self.assertTrue(review.envelope_signature_valid)
        self.assertTrue(review.signature_portable)
        self.assertEqual(DISPOSITION_REUSABLE, review.disposition)

    def test_preimage_mismatch_blocks_record_reuse(self):
        envelope = self._signed_envelope()
        legacy_signed = {
            "content_b64": b64enc(envelope.payload),
            "media_type": envelope.payload_type,
            "usage": "release-approval",
        }
        decoy_preimage = b"different signed bytes"
        legacy_signature = self.signer.sign(decoy_preimage)
        record = {
            "id": "preimage-mismatch",
            "key": self.key_dict,
            "field_mapping": {
                "content": {
                    "source": "/legacy/signed/content_b64",
                    "source_encoding": "base64",
                    "target": "payload",
                },
                "media_type": {
                    "source": "/legacy/signed/media_type",
                    "target": "payload_type",
                },
                "signing_purpose": {
                    "source": "/legacy/signed/usage",
                    "target": "payload_json",
                    "target_path": "/usage",
                },
            },
            "legacy": {
                "signed": legacy_signed,
                "signed_bytes_b64": b64enc(decoy_preimage),
                "signature": legacy_signature.to_dict(),
            },
            "envelope": envelope.to_dict(),
        }

        review = review_conversion(record)

        self.assertTrue(review.legacy_signature_valid)
        self.assertFalse(review.legacy_preimage_consistent)
        self.assertIn("legacy_signed_bytes_mismatch", review.reasons)
        self.assertEqual(DISPOSITION_RESIGN_CANDIDATE, review.disposition)
        self.assertFalse(review.claims["content"].source_attested)


class EnvelopeExtensionPreservationTests(unittest.TestCase):
    def test_unrecognized_top_level_fields_survive_round_trip(self):
        envelope_dict = {
            "payload": b64enc(b"payload"),
            "payloadType": "application/example",
            "usage": "release-approval",
            "futureField": {"kept": True},
            "signatures": [],
        }

        envelope = Envelope.from_dict(copy.deepcopy(envelope_dict))
        self.assertEqual("release-approval", envelope.unrecognized_fields["usage"])

        round_trip = envelope.to_dict()
        self.assertEqual("release-approval", round_trip["usage"])
        self.assertEqual({"kept": True}, round_trip["futureField"])

        again = Envelope.from_dict(round_trip)
        self.assertEqual(envelope, again)
        self.assertEqual(hash(envelope), hash(again))


if __name__ == "__main__":
    unittest.main()
