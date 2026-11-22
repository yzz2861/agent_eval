import json
import os
import shutil
import struct
import sys
import tempfile

from macholib import macho_crypt
from macholib.mach_o import (
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
    LC_SEGMENT,
    LC_SEGMENT_64,
    MH_EXECUTE,
    MH_MAGIC,
    MH_MAGIC_64,
)

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

if __import__("sys").version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest


CPU_TYPE_I386 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
FAT_MAGIC = 0xCAFEBABE

TEXT_FILE_OFFSET = 0x1000
SLICE_SIZE = 0x3000


def _pad(data, size):
    return data + (b"\x00" * (size - len(data)))


def build_slice(
    cputype=CPU_TYPE_X86_64,
    cpusubtype=3,
    cryptoff=TEXT_FILE_OFFSET,
    cryptsize=0x1000,
    cryptid=1,
    segment_filesize=SLICE_SIZE,
):
    """Build one little-endian 64-bit Mach-O slice with one encrypted segment."""
    segment_cmdsize = 8 + 64 + 80
    encryption_cmdsize = 8 + 16
    sizeofcmds = segment_cmdsize + encryption_cmdsize

    header = struct.pack(
        "<IiiIIIII",
        MH_MAGIC_64,
        cputype,
        cpusubtype,
        MH_EXECUTE,
        2,
        sizeofcmds,
        0,
        0,
    )

    segment = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        segment_cmdsize,
        b"__TEXT" + (b"\x00" * 10),
        0x100000000,
        segment_filesize,
        0,
        segment_filesize,
        7,
        5,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text" + (b"\x00" * 10),
        b"__TEXT" + (b"\x00" * 10),
        0x100000000 + TEXT_FILE_OFFSET,
        0x1000,
        TEXT_FILE_OFFSET,
        4,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    encryption = struct.pack(
        "<IIIIII",
        LC_ENCRYPTION_INFO_64,
        encryption_cmdsize,
        cryptoff,
        cryptsize,
        cryptid,
        0,
    )

    body = header + segment + section + encryption
    body = _pad(body, SLICE_SIZE)
    return body


def build_thin(**kwargs):
    return build_slice(**kwargs)


def build_slice32(
    cryptoff=TEXT_FILE_OFFSET,
    cryptsize=0x1000,
    cryptid=1,
    segment_filesize=SLICE_SIZE,
):
    """Build one little-endian 32-bit Mach-O slice."""
    segment_cmdsize = 8 + 48 + 68
    encryption_cmdsize = 8 + 12
    sizeofcmds = segment_cmdsize + encryption_cmdsize

    header = struct.pack(
        "<IiiIIII",
        MH_MAGIC,
        CPU_TYPE_I386,
        3,
        MH_EXECUTE,
        2,
        sizeofcmds,
        0,
    )
    segment = struct.pack(
        "<II16sIIIIiiII",
        LC_SEGMENT,
        segment_cmdsize,
        b"__TEXT" + (b"\x00" * 10),
        TEXT_FILE_OFFSET,
        segment_filesize,
        0,
        segment_filesize,
        7,
        5,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sIIIIIIIII",
        b"__text" + (b"\x00" * 10),
        b"__TEXT" + (b"\x00" * 10),
        TEXT_FILE_OFFSET + TEXT_FILE_OFFSET,
        0x1000,
        TEXT_FILE_OFFSET,
        4,
        0,
        0,
        0x80000400,
        0,
        0,
    )
    encryption = struct.pack(
        "<IIIII",
        LC_ENCRYPTION_INFO,
        encryption_cmdsize,
        cryptoff,
        cryptsize,
        cryptid,
    )
    return _pad(header + segment + section + encryption, SLICE_SIZE)


def build_fat(slices, offsets=(0x1000, 0x5000)):
    nfat_arch = len(slices)
    fat_header = struct.pack(">II", FAT_MAGIC, nfat_arch)
    arch_table = b"".join(
        struct.pack(
            ">iiIII",
            CPU_TYPE_X86_64 if index == 0 else CPU_TYPE_ARM64,
            3 if index == 0 else 0,
            offset,
            len(slice_data),
            12,
        )
        for index, (slice_data, offset) in enumerate(zip(slices, offsets))
    )
    data = bytearray(max(offset + len(value) for value, offset in zip(slices, offsets)))
    header_end = len(fat_header)
    table_end = header_end + len(arch_table)
    data[:header_end] = fat_header
    data[header_end:table_end] = arch_table
    for slice_data, offset in zip(slices, offsets):
        slice_end = offset + len(slice_data)
        data[offset:slice_end] = slice_data
    return bytes(data)


class TestMachoEncryptionAudit(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="macholib-crypt-")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write(self, name, data):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as stream:
            stream.write(data)
        return path

    def _report(self, name, data):
        return macho_crypt.audit_file(self._write(name, data))

    def test_thin_file_reports_fully_visible_range(self):
        report = self._report("thin", build_thin())

        self.assertFalse(report["fat"])
        self.assertEqual(report["status"], macho_crypt.STATUS_FULLY_VISIBLE)
        self.assertEqual(len(report["slices"]), 1)

        finding = report["slices"][0]["findings"][0]
        self.assertEqual(finding["status"], macho_crypt.STATUS_FULLY_VISIBLE)
        self.assertEqual(finding["command"], "LC_ENCRYPTION_INFO_64")
        self.assertEqual(finding["declared_local_range"], [0x1000, 0x2000])
        self.assertEqual(finding["declared_archive_range"], [0x1000, 0x2000])
        self.assertEqual(finding["saved_local_range"], [0x1000, 0x2000])
        self.assertEqual(finding["saved_archive_range"], [0x1000, 0x2000])
        self.assertEqual(finding["segment_names"], ["__TEXT"])
        self.assertEqual(finding["evidence"][0]["size"], 0x1000)

    def test_fat_slices_map_the_same_local_range_to_different_archive_ranges(self):
        report = self._report(
            "fat", build_fat([build_slice(), build_slice(cputype=CPU_TYPE_ARM64)])
        )

        self.assertTrue(report["fat"])
        first, second = report["slices"]
        self.assertEqual(first["findings"][0]["declared_local_range"], [0x1000, 0x2000])
        self.assertEqual(
            second["findings"][0]["declared_local_range"], [0x1000, 0x2000]
        )
        self.assertEqual(
            first["findings"][0]["declared_archive_range"], [0x2000, 0x3000]
        )
        self.assertEqual(
            second["findings"][0]["declared_archive_range"], [0x6000, 0x7000]
        )
        self.assertEqual(
            [value["archive_range"] for value in report["evidence"]],
            [[0x2000, 0x3000], [0x6000, 0x7000]],
        )

    def test_truncated_fat_slice_is_declaration_only(self):
        full = build_fat(
            [build_slice(), build_slice(cputype=CPU_TYPE_ARM64)],
            offsets=(0x1000, 0x5000),
        )
        report = self._report("fat-truncated", full[:0x5800])

        first, second = report["slices"]
        self.assertEqual(first["status"], macho_crypt.STATUS_FULLY_VISIBLE)
        self.assertEqual(second["status"], macho_crypt.STATUS_DECLARATION_ONLY)
        self.assertIsNone(second["findings"][0]["saved_local_range"])
        self.assertEqual(second["findings"][0]["evidence"], [])
        self.assertEqual(report["summary"][macho_crypt.STATUS_FULLY_VISIBLE], 1)
        self.assertEqual(report["summary"][macho_crypt.STATUS_DECLARATION_ONLY], 1)
        self.assertEqual(len(report["evidence"]), 1)

    def test_thin_file_truncated_before_crypt_is_declaration_only(self):
        report = self._report("thin-truncated", build_thin()[:0x800])

        finding = report["slices"][0]["findings"][0]
        self.assertEqual(finding["status"], macho_crypt.STATUS_DECLARATION_ONLY)
        self.assertIsNone(finding["saved_local_range"])
        self.assertEqual(finding["evidence"], [])

    def test_partial_file_is_contradictory_and_evidence_is_only_saved_bytes(self):
        report = self._report("thin-partial", build_thin()[:0x1800])

        finding = report["slices"][0]["findings"][0]
        self.assertEqual(finding["status"], macho_crypt.STATUS_CONTRADICTORY)
        self.assertEqual(finding["declared_local_range"], [0x1000, 0x2000])
        self.assertEqual(finding["saved_local_range"], [0x1000, 0x1800])
        self.assertEqual(finding["evidence"][0]["local_range"], [0x1000, 0x1800])
        self.assertEqual(finding["evidence"][0]["size"], 0x800)

    def test_segment_mismatch_is_contradictory(self):
        report = self._report("thin-segment", build_thin(segment_filesize=0x1800))

        finding = report["slices"][0]["findings"][0]
        self.assertEqual(finding["status"], macho_crypt.STATUS_CONTRADICTORY)
        self.assertFalse(finding["segment_coverage"]["complete"])
        self.assertEqual(finding["segment_coverage"]["covered"], 0x800)

    def test_segment_outside_range_still_reports_declared_segment(self):
        report = self._report("thin-outside", build_thin(segment_filesize=0x800))

        finding = report["slices"][0]["findings"][0]
        self.assertEqual(finding["status"], macho_crypt.STATUS_CONTRADICTORY)
        self.assertEqual(finding["overlapping_segments"], [])
        self.assertEqual(finding["segment_names"], ["__TEXT"])
        self.assertEqual(finding["all_segment_names"], ["__TEXT"])
        self.assertEqual(len(finding["segments"]), 1)

    def test_cryptid_zero_is_not_treated_as_encrypted(self):
        report = self._report("thin-clear", build_thin(cryptid=0))

        self.assertFalse(report["has_encryption"])
        self.assertEqual(report["status"], macho_crypt.STATUS_NOT_ENCRYPTED)
        self.assertEqual(
            report["slices"][0]["findings"][0]["status"],
            macho_crypt.STATUS_NOT_ENCRYPTED,
        )

    def test_32bit_encryption_command_is_supported(self):
        report = self._report("thin32", build_slice32())

        finding = report["slices"][0]["findings"][0]
        self.assertEqual(finding["command"], "LC_ENCRYPTION_INFO")
        self.assertEqual(finding["status"], macho_crypt.STATUS_FULLY_VISIBLE)
        self.assertEqual(finding["declared_local_range"], [0x1000, 0x2000])

    def test_format_and_print_use_saved_range_as_evidence(self):
        path = self._write("thin", build_thin())
        fp = StringIO()
        macho_crypt.print_file(fp, path)

        output = fp.getvalue()
        self.assertIn("status=fully-visible", output)
        self.assertIn("evidence local=[0x1000, 0x2000)", output)
        self.assertNotIn("decrypt", output.lower())

    def test_cli_json_report(self):
        path = self._write("thin", build_thin())
        output = StringIO()
        saved_stdout = sys.stdout
        try:
            sys.stdout = output
            self.assertEqual(macho_crypt.main(["--json", path]), 0)
        finally:
            sys.stdout = saved_stdout

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], macho_crypt.STATUS_FULLY_VISIBLE)
        self.assertEqual(
            payload["slices"][0]["findings"][0]["saved_local_range"],
            [0x1000, 0x2000],
        )

    def test_iter_findings_includes_slice_context(self):
        path = self._write("thin", build_thin())
        findings = list(macho_crypt.iter_findings(path))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["slice_offset"], 0)
        self.assertEqual(findings[0]["status"], macho_crypt.STATUS_FULLY_VISIBLE)
        self.assertEqual(
            findings[0]["finding"]["status"], macho_crypt.STATUS_FULLY_VISIBLE
        )


if __name__ == "__main__":
    unittest.main()
