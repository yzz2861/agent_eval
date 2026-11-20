"""Tests for the forensic evidence export entry point."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from os.path import abspath, dirname
from os.path import join as pjoin

TEST_BASE_DIR = dirname(abspath(__file__))
MODULE_BASE_DIR = dirname(TEST_BASE_DIR)
if sys.path[0] != MODULE_BASE_DIR:
    sys.path.insert(0, MODULE_BASE_DIR)

import msoffcrypto
from msoffcrypto import exceptions
from msoffcrypto.forensics import export_evidence, verify_receipt

PASSWORD = "Password1234_"
AGILE_INPUT = pjoin(TEST_BASE_DIR, "inputs", "example_password.docx")
AGILE_PLAIN = pjoin(TEST_BASE_DIR, "outputs", "example.docx")
STANDARD_INPUT = pjoin(TEST_BASE_DIR, "inputs", "ecma376standard_password.docx")


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _load_officefile(path, password=PASSWORD, verify_password=True):
    f = open(path, "rb")
    officefile = msoffcrypto.OfficeFile(f)
    officefile.load_key(password=password, verify_password=verify_password)
    return officefile


class ShortWriteStream(io.BytesIO):
    """In-memory sink that accepts only part of every write."""

    def __init__(self, accept_ratio=0.5):
        super().__init__()
        self._accept_ratio = accept_ratio

    def write(self, data):
        accepted = max(1, int(len(data) * self._accept_ratio))
        super().write(bytes(data[:accepted]))
        return accepted


class FailingStream(io.BytesIO):
    """In-memory sink whose write raises mid-handover."""

    def write(self, data):
        raise OSError("simulated backend failure")


class ExportEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="msoffcrypto-forensics-")
        self.receipt_path = pjoin(self.tmpdir, "receipt.json")
        self.derived_path = pjoin(self.tmpdir, "derived.docx")

    def _export(self, outfile, source=AGILE_INPUT, password=PASSWORD,
                verify_password=True):
        officefile = _load_officefile(source, password, verify_password)
        try:
            return export_evidence(
                officefile, source, outfile, self.receipt_path
            )
        finally:
            officefile.file.close()

    def test_receipt_binds_digests_integrity_and_status(self):
        with open(self.derived_path, "wb") as outfile:
            receipt = self._export(outfile)

        self.assertEqual(receipt["schema"], "msoffcrypto.evidence-receipt/1")
        self.assertEqual(receipt["status"], "handed_over")
        self.assertEqual(receipt["integrity"], "verified")
        self.assertEqual(receipt["hash_algorithm"], "sha256")
        self.assertEqual(receipt["source"]["digest"], _sha256(AGILE_INPUT))
        self.assertEqual(receipt["derived"]["digest"], _sha256(self.derived_path))

        with open(self.receipt_path, encoding="utf-8") as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["source"]["digest"], receipt["source"]["digest"])
        self.assertEqual(on_disk["derived"]["digest"], receipt["derived"]["digest"])
        self.assertEqual(on_disk["status"], "handed_over")

    def test_receipt_never_stores_password(self):
        with open(self.derived_path, "wb") as outfile:
            self._export(outfile)
        with open(self.receipt_path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn(PASSWORD, raw)
        self.assertNotIn("password", raw.lower())

    def test_standard_encryption_reports_integrity_unavailable(self):
        with open(self.derived_path, "wb") as outfile:
            receipt = self._export(outfile, source=STANDARD_INPUT)
        self.assertEqual(receipt["integrity"], "unavailable")
        self.assertEqual(receipt["status"], "handed_over")

    def test_verify_receipt_independent_process(self):
        with open(self.derived_path, "wb") as outfile:
            self._export(outfile)

        # Same-process check.
        result = verify_receipt(self.receipt_path, AGILE_INPUT, self.derived_path)
        self.assertTrue(result["ok"])
        self.assertTrue(result["source_match"])
        self.assertTrue(result["derived_match"])

        # Independent-process check: only stdlib + receipt + both exhibits.
        script = (
            "import sys;"
            "sys.path.insert(0, {mod!r});"
            "from msoffcrypto.forensics import verify_receipt;"
            "r = verify_receipt({rec!r}, {src!r}, {der!r});"
            "sys.exit(0 if r['ok'] else 1)"
        ).format(mod=MODULE_BASE_DIR, rec=self.receipt_path,
                 src=AGILE_INPUT, der=self.derived_path)
        rc = subprocess.call([sys.executable, "-c", script])
        self.assertEqual(rc, 0)

    def test_verify_receipt_detects_tampering(self):
        with open(self.derived_path, "wb") as outfile:
            self._export(outfile)
        with open(self.derived_path, "ab") as f:
            f.write(b"tampered")
        result = verify_receipt(self.receipt_path, AGILE_INPUT, self.derived_path)
        self.assertFalse(result["ok"])
        self.assertTrue(result["source_match"])
        self.assertFalse(result["derived_match"])

    def test_short_write_leaves_only_exception_record(self):
        sink = ShortWriteStream()
        with self.assertRaises(exceptions.EvidenceExportError):
            self._export(sink)

        self.assertFalse(os.path.exists(self.receipt_path))

        exception_path = self.receipt_path + ".exception.json"
        self.assertTrue(os.path.exists(exception_path))
        with open(exception_path, encoding="utf-8") as f:
            record = json.load(f)
        self.assertEqual(record["schema"], "msoffcrypto.evidence-exception/1")
        self.assertEqual(record["status"], "failed")
        self.assertIn("write", record["reason"].lower())
        # The digests gathered before the failure are still recorded.
        self.assertEqual(record["source"]["digest"], _sha256(AGILE_INPUT))
        self.assertEqual(record["integrity"], "verified")
        # No password material in the exception record either.
        self.assertNotIn(PASSWORD, json.dumps(record))

    def test_failing_sink_leaves_only_exception_record(self):
        with self.assertRaises(exceptions.EvidenceExportError):
            self._export(FailingStream())
        self.assertFalse(os.path.exists(self.receipt_path))
        self.assertTrue(
            os.path.exists(self.receipt_path + ".exception.json")
        )

    def test_decryption_failure_leaves_only_exception_record(self):
        with self.assertRaises(exceptions.EvidenceExportError):
            self._export(io.BytesIO(), password="wrong-password",
                         verify_password=False)
        self.assertFalse(os.path.exists(self.receipt_path))
        self.assertTrue(
            os.path.exists(self.receipt_path + ".exception.json")
        )


if __name__ == "__main__":
    unittest.main()
