import struct
import unittest

from export_test import PE_32

import pefile


def make_pkcs7_blob():
    """Build a minimal DER structure resembling a PKCS#7 SignedData blob."""
    oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"  # signedData
    content = oid + b"\x30\x02\x05\x00"
    return b"\x30" + bytes([len(content)]) + content


def make_certificate(blob, revision=0x0200, certificate_type=2, declared_length=None):
    length = 8 + len(blob) if declared_length is None else declared_length
    return struct.pack("<IHH", length, revision, certificate_type) + blob


def align8(data):
    return data + bytes((-len(data)) % 8)


def make_signed_pe(cert_table, directory_offset=None, directory_size=None):
    """Return a PE image with a security directory appended to PE_32."""
    data = bytearray(PE_32)
    if directory_offset is None:
        directory_offset = (len(data) + 7) & ~7
    if directory_size is None:
        directory_size = len(cert_table)
    if len(data) < directory_offset + len(cert_table):
        data.extend(bytes(directory_offset + len(cert_table) - len(data)))
    data[directory_offset : directory_offset + len(cert_table)] = cert_table

    pe = pefile.PE(data=bytes(PE_32), fast_load=True)
    entry_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ].get_file_offset()
    struct.pack_into("<II", data, entry_offset, directory_offset, directory_size)
    return bytes(data)


def security_warnings(pe):
    return [w for w in pe.get_warnings() if w.startswith("Security directory")]


class TestSecurityDirectory(unittest.TestCase):
    def test_unsigned_pe_has_no_security_directory(self):
        pe = pefile.PE(data=bytes(PE_32))
        self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_SECURITY"))
        # Existing attributes stay compatible.
        self.assertIsNotNone(pe.RICH_HEADER)
        self.assertEqual(security_warnings(pe), [])

    def test_valid_signature(self):
        blob = make_pkcs7_blob()
        cert_table = align8(make_certificate(blob))
        pe = pefile.PE(data=make_signed_pe(cert_table))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertTrue(security.valid)
        self.assertIsNone(security.error)
        self.assertEqual(len(security.certificates), 1)
        certificate = security.certificates[0]
        self.assertEqual(certificate.Length, 8 + len(blob))
        self.assertEqual(certificate.Revision, 0x0200)
        self.assertEqual(certificate.CertificateType, 2)
        self.assertEqual(certificate.Certificate, blob)
        self.assertEqual(security_warnings(pe), [])

    def test_truncated_directory(self):
        cert_table = align8(make_certificate(make_pkcs7_blob()))
        # The directory claims a size extending past the end of the file.
        pe = pefile.PE(data=make_signed_pe(cert_table, directory_size=len(cert_table) + 64))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        self.assertIn("end of the file", security.error)
        self.assertEqual(security.certificates, [])
        self.assertTrue(security_warnings(pe))

    def test_directory_smaller_than_header(self):
        pe = pefile.PE(data=make_signed_pe(b"\x00" * 4, directory_size=4))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        self.assertIn("smaller than a WIN_CERTIFICATE header", security.error)

    def test_unaligned_directory_offset(self):
        cert_table = align8(make_certificate(make_pkcs7_blob()))
        offset = ((len(PE_32) + 7) & ~7) + 1
        pe = pefile.PE(data=make_signed_pe(cert_table, directory_offset=offset))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        self.assertIn("not 8-byte aligned", security.error)

    def test_certificate_length_overflow(self):
        blob = make_pkcs7_blob()
        cert_table = align8(make_certificate(blob, declared_length=0x1000))
        pe = pefile.PE(data=make_signed_pe(cert_table))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        self.assertIn("exceeding the remaining directory size", security.error)
        self.assertEqual(security.certificates, [])

    def test_certificate_length_too_small(self):
        cert_table = align8(make_certificate(b"", declared_length=4))
        pe = pefile.PE(data=make_signed_pe(cert_table))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        self.assertIn("invalid length", security.error)

    def test_truncated_asn1_blob(self):
        blob = make_pkcs7_blob()
        # Cut the blob so the DER length declares more than is present.
        cert_table = align8(make_certificate(blob[:-3]))
        pe = pefile.PE(data=make_signed_pe(cert_table))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        self.assertIn("ASN.1", security.error)

    def test_trailing_bytes_too_small_for_header(self):
        cert_table = align8(make_certificate(make_pkcs7_blob())) + b"\x00" * 4
        pe = pefile.PE(data=make_signed_pe(cert_table))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        self.assertIn("trailing byte(s)", security.error)
        # The first certificate was still recovered.
        self.assertEqual(len(security.certificates), 1)

    def test_multiple_certificates(self):
        first = align8(make_certificate(make_pkcs7_blob()))
        second = align8(make_certificate(make_pkcs7_blob(), certificate_type=1))
        pe = pefile.PE(data=make_signed_pe(first + second))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertTrue(security.valid)
        self.assertEqual(len(security.certificates), 2)
        self.assertEqual(
            [c.CertificateType for c in security.certificates], [2, 1]
        )

    def test_errors_do_not_leak_certificate_data(self):
        marker = b"SENSITIVE-KEY-MATERIAL"
        blob = make_pkcs7_blob() + marker
        blob = b"\x30" + bytes([len(blob) - 2]) + blob[2:]
        cert_table = align8(make_certificate(blob, declared_length=0x1000))
        pe = pefile.PE(data=make_signed_pe(cert_table))

        security = pe.DIRECTORY_ENTRY_SECURITY
        self.assertFalse(security.valid)
        for message in [security.error, *security_warnings(pe)]:
            self.assertNotIn(marker.decode(), message)
            self.assertNotIn(blob.hex(), message)


class TestRichHeaderBoundaries(unittest.TestCase):
    def test_rich_header_values_unchanged(self):
        pe = pefile.PE(data=bytes(PE_32))
        self.assertEqual(pe.RICH_HEADER.checksum, 0x8C5513E9)
        self.assertEqual(pe.RICH_HEADER.key, b"\xe9\x13\x55\x8c")
        self.assertEqual(pe.RICH_HEADER.values, [16807922, 1, 16938994, 1])
        self.assertEqual(len(pe.RICH_HEADER.raw_data), 32)

    def test_rich_signature_without_preceding_dans(self):
        # A "Rich" string at an arbitrary offset must not yield a key.
        data = bytearray(PE_32)
        data[0x50:0x58] = b"RichXXXX"
        pe = pefile.PE(data=bytes(data))
        self.assertIsNone(pe.RICH_HEADER)


if __name__ == "__main__":
    unittest.main()
