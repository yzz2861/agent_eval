"""
Robust, reason-code based classification of OOXML containers.

The fixtures are generated on the fly from trusted inputs so the suite stays
small while still covering unencrypted OOXML, encrypted OOXML (OLE compound
file with an ``EncryptionInfo`` stream), corrupted ZIPs and files whose
extension lies about their content.
"""

import io
import os
import shutil
import unittest
import zipfile
from os.path import dirname, join

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.ooxml import (
    OOXMLDetectionReason,
    OOXMLFile,
    _is_ooxml,
    detect_ooxml,
)

DATA_DIR = join(dirname(__file__), "inputs")

#: Namespaced ``[Content_Types].xml`` of a minimal OPC package.
CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    "</Types>"
)

#: XML that parses fine but is not an OPC content-types descriptor.
WRONG_ROOT_XML = '<?xml version="1.0"?><SomethingElse xmlns="urn:fake"/>'


def _make_zip(entries):
    """Build an in-memory ZIP archive from ``{name: bytes}`` entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buf.getvalue()


class OOXMLDetectionTest(unittest.TestCase):
    """See module doc."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = join(DATA_DIR, "detection")
        os.makedirs(cls.tmp, exist_ok=True)
        cls.samples = {}

        # 1. Unencrypted docx: a valid OPC (ZIP) package named .docx.
        plain_docx = join(cls.tmp, "plain.docx")
        with open(plain_docx, "wb") as handle:
            handle.write(
                _make_zip(
                    {
                        "[Content_Types].xml": CONTENT_TYPES_XML.encode("utf-8"),
                        "word/document.xml": (
                            b'<?xml version="1.0"?>'
                            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>'
                        ),
                    }
                )
            )
        cls.samples["plain_docx"] = plain_docx

        # 2. Encrypted docx: real OLE compound file carrying EncryptionInfo.
        encrypted_docx = join(cls.tmp, "encrypted.docx")
        shutil.copyfile(join(DATA_DIR, "example_password.docx"), encrypted_docx)
        cls.samples["encrypted_docx"] = encrypted_docx

        # 3. Corrupted zip: valid local header start, broken central directory.
        corrupt_zip = join(cls.tmp, "corrupt_zip.docx")
        valid_zip = _make_zip({"[Content_Types].xml": CONTENT_TYPES_XML.encode("utf-8")})
        with open(corrupt_zip, "wb") as handle:
            handle.write(valid_zip[:30] + b"\x00" * 16 + valid_zip[46:])
        cls.samples["corrupt_zip"] = corrupt_zip

        # 4. Plain ZIP without an OPC content-types part, faking a .docx name.
        fake_zip = join(cls.tmp, "fake_zip.docx")
        with open(fake_zip, "wb") as handle:
            handle.write(_make_zip({"readme.txt": b"not an office document"}))
        cls.samples["fake_zip"] = fake_zip

        # 5. Plain text faking a .docx extension (not even a container).
        fake_text = join(cls.tmp, "fake_text.docx")
        with open(fake_text, "wb") as handle:
            handle.write(b"this is definitely not a zip or OLE file")
        cls.samples["fake_text"] = fake_text

        # 6. OPC zip whose content-types part is missing.
        missing_ct = join(cls.tmp, "missing_content_types.docx")
        with open(missing_ct, "wb") as handle:
            handle.write(_make_zip({"word/document.xml": b"<xml/>"}))
        cls.samples["missing_ct"] = missing_ct

        # 7. OPC zip whose content-types part contains broken XML.
        malformed_ct = join(cls.tmp, "malformed_content_types.docx")
        with open(malformed_ct, "wb") as handle:
            handle.write(
                _make_zip({"[Content_Types].xml": b"<Types><unterminated>"})
            )
        cls.samples["malformed_ct"] = malformed_ct

        # 8. OPC zip whose content-types part has the wrong root element.
        invalid_ct = join(cls.tmp, "invalid_content_types.docx")
        with open(invalid_ct, "wb") as handle:
            handle.write(
                _make_zip({"[Content_Types].xml": WRONG_ROOT_XML.encode("utf-8")})
            )
        cls.samples["invalid_ct"] = invalid_ct

        # 9. Legacy OLE compound file (Word 97 doc) renamed to .docx.
        ole_fake = join(cls.tmp, "legacy_ole.docx")
        shutil.copyfile(join(DATA_DIR, "plain.doc"), ole_fake)
        cls.samples["ole_fake"] = ole_fake

    def _detect(self, key):
        with open(self.samples[key], "rb") as handle:
            return detect_ooxml(handle)

    def test_unencrypted_docx(self):
        result = self._detect("plain_docx")
        self.assertFalse(result.encrypted)
        self.assertEqual(result.reason, OOXMLDetectionReason.PLAIN_OOXML)
        with open(self.samples["plain_docx"], "rb") as handle:
            self.assertTrue(_is_ooxml(handle))
            self.assertFalse(handle.closed)
            self.assertEqual(handle.tell(), 0)

        with open(self.samples["plain_docx"], "rb") as handle:
            office = OOXMLFile(handle)
            self.assertFalse(office.is_encrypted())
            self.assertEqual(office.type, "plain")
            reason_result = office.is_encrypted(with_reason=True)
            self.assertFalse(bool(reason_result))
            self.assertEqual(reason_result.reason, OOXMLDetectionReason.PLAIN_OOXML)

    def test_encrypted_docx(self):
        result = self._detect("encrypted_docx")
        self.assertTrue(result.encrypted)
        self.assertTrue(bool(result))
        self.assertEqual(result.reason, OOXMLDetectionReason.ENCRYPTED)
        with open(self.samples["encrypted_docx"], "rb") as handle:
            self.assertFalse(_is_ooxml(handle))
            self.assertFalse(handle.closed)

        with open(self.samples["encrypted_docx"], "rb") as handle:
            office = OfficeFile(handle)
            self.assertTrue(office.is_encrypted())
            reason_result = office.is_encrypted(with_reason=True)
            self.assertTrue(reason_result.encrypted)
            self.assertEqual(reason_result.reason, OOXMLDetectionReason.ENCRYPTED)
            self.assertIn(office.type, ("agile", "standard"))

    def test_corrupted_zip_never_raises(self):
        result = self._detect("corrupt_zip")
        self.assertFalse(result.encrypted)
        self.assertEqual(result.reason, OOXMLDetectionReason.ZIP_CORRUPT)
        with open(self.samples["corrupt_zip"], "rb") as handle:
            self.assertFalse(handle.closed)

        with open(self.samples["corrupt_zip"], "rb") as handle:
            with self.assertRaises(exceptions.FileFormatError) as ctx:
                OOXMLFile(handle)
            self.assertIn("zip_corrupt", str(ctx.exception))
            self.assertFalse(handle.closed)

    def test_fake_zip_extension(self):
        result = self._detect("fake_zip")
        self.assertFalse(result.encrypted)
        self.assertEqual(result.reason, OOXMLDetectionReason.MISSING_CONTENT_TYPES)

        with open(self.samples["fake_zip"], "rb") as handle:
            with self.assertRaises(exceptions.FileFormatError):
                OOXMLFile(handle)

    def test_fake_text_extension(self):
        result = self._detect("fake_text")
        self.assertFalse(result.encrypted)
        self.assertEqual(result.reason, OOXMLDetectionReason.NOT_OOXML)

        with open(self.samples["fake_text"], "rb") as handle:
            with self.assertRaises(exceptions.FileFormatError):
                OOXMLFile(handle)

    def test_missing_content_types(self):
        result = self._detect("missing_ct")
        self.assertEqual(result.reason, OOXMLDetectionReason.MISSING_CONTENT_TYPES)

    def test_malformed_content_types(self):
        result = self._detect("malformed_ct")
        self.assertEqual(result.reason, OOXMLDetectionReason.MALFORMED_CONTENT_TYPES)

        with open(self.samples["malformed_ct"], "rb") as handle:
            with self.assertRaises(exceptions.FileFormatError):
                OOXMLFile(handle)

    def test_invalid_content_types(self):
        result = self._detect("invalid_ct")
        self.assertEqual(result.reason, OOXMLDetectionReason.INVALID_CONTENT_TYPES)

    def test_legacy_ole_without_encryption_info(self):
        result = self._detect("ole_fake")
        self.assertFalse(result.encrypted)
        self.assertEqual(result.reason, OOXMLDetectionReason.OLE_NO_ENCRYPTION_INFO)
        with open(self.samples["ole_fake"], "rb") as handle:
            self.assertFalse(handle.closed)

    def test_backwards_compatible_booleans(self):
        encrypted = self._detect("encrypted_docx")
        plain = self._detect("plain_docx")
        self.assertEqual(encrypted, True)
        self.assertEqual(plain, False)
        self.assertNotEqual(encrypted, plain)


if __name__ == "__main__":
    unittest.main()
