"""Tests for the read-only evidence inventory (msoffcrypto.evidence).

Fixtures (both derived from existing test inputs, with the tail of the
encrypted stream deleted):

* ``inputs/evidence_tail_cut.docx``: from ``example_password.docx``; the
  last sectors of the EncryptedPackage FAT chain are marked ENDOFCHAIN, so
  the directory still declares 12008 bytes while only 11776 are readable.
  The EncryptionInfo stream (mini stream) is untouched.
* ``inputs/evidence_tail_cut.xlsx``: from ``ecma376agile_sha1_password.xlsx``
  with the final 512 bytes of the OLE file removed; EncryptedPackage reads
  8192 of 8392 declared bytes, EncryptionInfo remains fully readable.
"""

import doctest
import io
import json
import unittest
from contextlib import redirect_stdout

from msoffcrypto import evidence
from msoffcrypto.evidence import inspect


def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite(evidence))
    return tests


class TruncatedFixtureTest(unittest.TestCase):
    def test_tail_cut_docx(self):
        report = inspect("tests/inputs/evidence_tail_cut.docx")
        obs = report["physical_observations"]

        declaration = obs["protection_declaration"]
        self.assertTrue(declaration["present"])
        self.assertTrue(declaration["readable"])
        self.assertTrue(declaration["parsed"])
        self.assertEqual(declaration["encryption_type"], "agile")
        self.assertEqual(declaration["declared_size"], 1289)
        self.assertEqual(declaration["readable_size"], 1289)

        stream = obs["encrypted_stream"]
        self.assertEqual(stream["name"], "EncryptedPackage")
        self.assertEqual(stream["declared_size"], 12008)
        self.assertLess(stream["readable_size"], stream["declared_size"])
        self.assertFalse(stream["complete"])

        # The protection declaration survives, the seal does not.
        self.assertTrue(report["assessment"]["protection_declared"])
        self.assertFalse(report["assessment"]["sealed_content_complete"])
        self.assertIn("encrypted_stream_truncated", report["findings"])
        explanation = report["assessment"]["explanation"]
        self.assertIn("proves the original file carried an encryption declaration", explanation)
        self.assertIn("cannot confirm that the sealed content is intact", explanation)

    def test_tail_cut_xlsx(self):
        report = inspect("tests/inputs/evidence_tail_cut.xlsx")
        obs = report["physical_observations"]

        declaration = obs["protection_declaration"]
        self.assertTrue(declaration["present"])
        self.assertTrue(declaration["readable"])
        self.assertEqual(declaration["encryption_type"], "agile")

        stream = obs["encrypted_stream"]
        self.assertEqual(stream["declared_size"], 8392)
        self.assertEqual(stream["readable_size"], 8192)
        self.assertFalse(stream["complete"])

        self.assertTrue(report["assessment"]["protection_declared"])
        self.assertFalse(report["assessment"]["sealed_content_complete"])

    def test_intact_file(self):
        report = inspect("tests/inputs/example_password.docx")
        self.assertTrue(report["assessment"]["protection_declared"])
        self.assertTrue(report["assessment"]["sealed_content_complete"])
        self.assertIn("encrypted_stream_complete", report["findings"])


class FormatBehaviorTest(unittest.TestCase):
    def test_unrecognized_container(self):
        report = inspect("README.md")
        obs = report["physical_observations"]
        self.assertEqual(obs["container"], "unrecognized")
        self.assertIn("unrecognized_behavior", obs)
        self.assertIn("unrecognized_container", report["findings"])
        self.assertIsNone(report["assessment"]["protection_declared"])
        json.dumps(report)  # must stay JSON-serializable

    def test_plain_ole97(self):
        report = inspect("tests/inputs/plain.doc")
        self.assertEqual(report["physical_observations"]["format"], "doc97")
        self.assertFalse(report["assessment"]["protection_declared"])
        self.assertIn("protection_declaration_absent", report["findings"])

    def test_encrypted_ole97(self):
        report = inspect("tests/inputs/rc4cryptoapi_password.doc")
        self.assertEqual(report["physical_observations"]["format"], "doc97")
        self.assertTrue(report["assessment"]["protection_declared"])

    def test_standard_encryption_declaration(self):
        report = inspect("tests/inputs/ecma376standard_password.docx")
        declaration = report["physical_observations"]["protection_declaration"]
        self.assertEqual(declaration["encryption_type"], "standard")
        self.assertEqual(declaration["cipher"], "AES-128")

    def test_no_password_needed(self):
        report = inspect("tests/inputs/evidence_tail_cut.docx")
        self.assertFalse(report["tool"]["password_used"])
        self.assertEqual(report["tool"]["mode"], "read-only")


class PreservationRecordsTest(unittest.TestCase):
    RECORDS = [
        {
            "record_id": "registry-001",
            "registrar": "custodian A",
            "claim": "encrypted_original_intact",
            "statement": "The encrypted original was intact at handover.",
        },
        {
            "record_id": "registry-002",
            "registrar": "custodian B",
            "statement": "Free-form note without an intact claim.",
        },
    ]

    def test_records_stored_separately_and_verbatim(self):
        report = inspect(
            "tests/inputs/evidence_tail_cut.docx",
            preservation_records=self.RECORDS,
        )
        # Personnel statements are archived verbatim, apart from the
        # physically checkable observations.
        self.assertEqual(report["preservation_records"], self.RECORDS)
        self.assertNotIn(
            "registry-001", json.dumps(report["physical_observations"])
        )

    def test_intact_claim_contradicted_by_truncation(self):
        report = inspect(
            "tests/inputs/evidence_tail_cut.docx",
            preservation_records=self.RECORDS,
        )
        notes = report["consistency_notes"]
        self.assertEqual(len(notes), 1)
        self.assertIn("registry-001", notes[0])
        self.assertIn("NOT corroborated", notes[0])

    def test_intact_claim_consistent_with_complete_readback(self):
        report = inspect(
            "tests/inputs/example_password.docx",
            preservation_records=self.RECORDS,
        )
        notes = report["consistency_notes"]
        self.assertEqual(len(notes), 1)
        self.assertIn("consistent with the claim", notes[0])
        self.assertIn("not verified", notes[0])

    def test_no_records(self):
        report = inspect("tests/inputs/evidence_tail_cut.docx")
        self.assertEqual(report["preservation_records"], [])
        self.assertEqual(report["consistency_notes"], [])


class CliTest(unittest.TestCase):
    def test_main_json_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            evidence.main(["tests/inputs/evidence_tail_cut.xlsx", "--compact"])
        report = json.loads(buf.getvalue())
        self.assertEqual(report["schema"], "msoffcrypto-evidence/1")
        self.assertFalse(report["assessment"]["sealed_content_complete"])


if __name__ == "__main__":
    unittest.main()
