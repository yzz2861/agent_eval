import contextlib
import os
import struct
import sys
import tempfile

from macholib import mach_o
from macholib.version_audit import (
    STATUS_BELOW_MINIMUM,
    STATUS_COVERED,
    STATUS_NO_VERSION_COMMAND,
    STATUS_PLATFORM_MISMATCH,
    STATUS_UNDETERMINABLE,
    audit_file,
    normalize_platform,
    parse_version,
)

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest

CPU_TYPE_X86_64 = 0x1000007
CPU_TYPE_ARM64 = 0x100000C
MH_FILETYPE_EXECUTE = 0x2


def encode_version(major, minor, patch):
    return (major << 16) | (minor << 8) | patch


def lc_version_min(cmd, version, sdk):
    return struct.pack(">IIII", cmd, 16, version, sdk)


def lc_build_version(platform, minos, sdk):
    return struct.pack(
        ">IIIIII", mach_o.LC_BUILD_VERSION, 24, platform, minos, sdk, 0
    )


def lc_uuid():
    return struct.pack(">II16s", mach_o.LC_UUID, 24, b"\0" * 16)


def thin_macho(cputype, load_commands):
    sizeofcmds = sum(len(lc) for lc in load_commands)
    header = struct.pack(
        ">IIIIIIII",
        mach_o.MH_MAGIC_64,
        cputype,
        0,
        MH_FILETYPE_EXECUTE,
        len(load_commands),
        sizeofcmds,
        0,
        0,
    )
    return header + b"".join(load_commands)


def fat_macho(slices):
    # slices: list of (cputype, slice_bytes); returns
    # (fat_bytes, [slice_offset, ...])
    offset = 8 + 20 * len(slices)
    archs = []
    offsets = []
    for cputype, data in slices:
        archs.append(struct.pack(">IIIII", cputype, 0, offset, len(data), 0))
        offsets.append(offset)
        offset += len(data)
    blob = struct.pack(">II", mach_o.FAT_MAGIC, len(slices))
    blob += b"".join(archs)
    blob += b"".join(data for _cputype, data in slices)
    return blob, offsets


@contextlib.contextmanager
def temporary_macho_file(blob):
    fd, name = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(blob)
        yield name
    finally:
        os.unlink(name)


class TestHelpers(unittest.TestCase):
    def test_normalize_platform(self):
        self.assertEqual(normalize_platform("macos"), "macOS")
        self.assertEqual(normalize_platform("macOS"), "macOS")
        self.assertEqual(normalize_platform(" iOS "), "iOS")
        self.assertRaises(ValueError, normalize_platform, "aix")

    def test_parse_version(self):
        self.assertEqual(parse_version("10.15"), (10, 15, 0))
        self.assertEqual(parse_version("10.15.3"), (10, 15, 3))
        self.assertRaises(ValueError, parse_version, "ten.fifteen")


class TestAuditFile(unittest.TestCase):
    def test_fat_binary_declaration_covers_matching_slice_only(self):
        # Two slices with the same version (10.15.0) but different
        # platforms: the macOS declaration must cover the x86_64
        # slice and set the arm64/iOS slice aside for review.
        version = encode_version(10, 15, 0)
        x86_slice = thin_macho(
            CPU_TYPE_X86_64,
            [lc_version_min(mach_o.LC_VERSION_MIN_MACOSX, version, version)],
        )
        arm_slice = thin_macho(
            CPU_TYPE_ARM64,
            [lc_version_min(mach_o.LC_VERSION_MIN_IPHONEOS, version, version)],
        )
        blob, offsets = fat_macho(
            [(CPU_TYPE_X86_64, x86_slice), (CPU_TYPE_ARM64, arm_slice)]
        )
        with temporary_macho_file(blob) as filename:
            report = audit_file(filename, "macOS", "10.15")

        self.assertEqual(report["declaration"]["platform"], "macOS")
        self.assertEqual(report["declaration"]["min_version"], "10.15.0")
        self.assertEqual(len(report["slices"]), 2)
        self.assertEqual(report["covered_arches"], ["x86_64"])
        self.assertEqual(report["review_arches"], ["ARM64"])

        x86, arm = report["slices"]
        self.assertEqual(x86["arch"], "x86_64")
        self.assertEqual(x86["status"], STATUS_COVERED)
        self.assertTrue(x86["covered"])
        self.assertFalse(x86["needs_review"])

        self.assertEqual(arm["arch"], "ARM64")
        self.assertEqual(arm["status"], STATUS_PLATFORM_MISMATCH)
        self.assertFalse(arm["covered"])
        self.assertTrue(arm["needs_review"])

        # Original locations are preserved for both slices.
        for slice_result, offset in zip(report["slices"], offsets):
            self.assertEqual(slice_result["offset"], offset)
            self.assertEqual(len(slice_result["commands"]), 1)
            command = slice_result["commands"][0]
            self.assertEqual(command["command_index"], 0)
            self.assertEqual(command["file_offset"], offset + 32)
            self.assertTrue(command["decodable"])
            self.assertEqual(command["version"], "10.15.0")
        self.assertEqual(x86["commands"][0]["cmd"], "LC_VERSION_MIN_MACOSX")
        self.assertEqual(arm["commands"][0]["cmd"], "LC_VERSION_MIN_IPHONEOS")

    def test_slice_with_both_commands_uses_decodable_version_min(self):
        version = encode_version(10, 15, 0)
        blob = thin_macho(
            CPU_TYPE_X86_64,
            [
                lc_build_version(mach_o.PLATFORM_MACOS, version, version),
                lc_version_min(mach_o.LC_VERSION_MIN_MACOSX, version, version),
            ],
        )
        with temporary_macho_file(blob) as filename:
            report = audit_file(filename, "macOS", "10.14")

        (slice_result,) = report["slices"]
        self.assertEqual(slice_result["status"], STATUS_COVERED)
        self.assertTrue(slice_result["covered"])
        self.assertEqual(len(slice_result["commands"]), 2)

        build_cmd, min_cmd = slice_result["commands"]
        self.assertEqual(build_cmd["cmd"], "LC_BUILD_VERSION")
        self.assertFalse(build_cmd["decodable"])
        self.assertEqual(build_cmd["command_index"], 0)
        self.assertEqual(build_cmd["file_offset"], 32)
        self.assertEqual(min_cmd["cmd"], "LC_VERSION_MIN_MACOSX")
        self.assertTrue(min_cmd["decodable"])
        self.assertEqual(min_cmd["command_index"], 1)
        self.assertEqual(min_cmd["file_offset"], 32 + 24)

        self.assertEqual(slice_result["effective"], min_cmd)

    def test_build_version_only_slice_is_set_aside_for_review(self):
        version = encode_version(10, 15, 0)
        blob = thin_macho(
            CPU_TYPE_X86_64,
            [lc_build_version(mach_o.PLATFORM_MACOS, version, version)],
        )
        with temporary_macho_file(blob) as filename:
            report = audit_file(filename, "macOS", "10.15")

        (slice_result,) = report["slices"]
        self.assertEqual(slice_result["status"], STATUS_UNDETERMINABLE)
        self.assertFalse(slice_result["covered"])
        self.assertTrue(slice_result["needs_review"])
        self.assertIsNone(slice_result["effective"])
        self.assertEqual(report["covered_arches"], [])
        self.assertEqual(report["review_arches"], ["x86_64"])

    def test_slice_below_declared_minimum_is_not_covered(self):
        version = encode_version(10, 12, 0)
        blob = thin_macho(
            CPU_TYPE_X86_64,
            [lc_version_min(mach_o.LC_VERSION_MIN_MACOSX, version, version)],
        )
        with temporary_macho_file(blob) as filename:
            report = audit_file(filename, "macOS", "10.15")

        (slice_result,) = report["slices"]
        self.assertEqual(slice_result["status"], STATUS_BELOW_MINIMUM)
        self.assertFalse(slice_result["covered"])
        self.assertFalse(slice_result["needs_review"])

    def test_slice_without_version_command_is_set_aside_for_review(self):
        blob = thin_macho(CPU_TYPE_X86_64, [lc_uuid()])
        with temporary_macho_file(blob) as filename:
            report = audit_file(filename, "macOS", "10.15")

        (slice_result,) = report["slices"]
        self.assertEqual(slice_result["status"], STATUS_NO_VERSION_COMMAND)
        self.assertFalse(slice_result["covered"])
        self.assertTrue(slice_result["needs_review"])
        self.assertEqual(slice_result["commands"], [])


if __name__ == "__main__":
    unittest.main()
