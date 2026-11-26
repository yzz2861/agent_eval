"""
Tests for macholib.codesig: read-only verification of embedded
CodeDirectory page hashes.

The fixtures are synthetic (universal) Mach-O files with hand-built
embedded signature SuperBlobs, so the tests do not depend on a codesign
toolchain.
"""

import hashlib
import os
import struct
import sys
import tempfile
import unittest

from macholib import MachO, mach_o
from macholib.codesig import (
    CS_HASHTYPE_SHA1,
    CS_HASHTYPE_SHA256,
    CSSLOT_ALTERNATE_CODEDIRECTORIES,
    CSSLOT_CODEDIRECTORY,
    STATUS_MISMATCH,
    STATUS_OK,
    STATUS_TRUNCATED,
    STATUS_UNSUPPORTED,
    verify_code_signature,
)

if sys.version_info[0] == 2:
    range = xrange  # noqa: F821

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
MH_FILETYPE_EXECUTE = 0x2

PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT

_HASHERS = {
    CS_HASHTYPE_SHA1: hashlib.sha1,
    CS_HASHTYPE_SHA256: hashlib.sha256,
}


def _code_bytes(code_limit, seed):
    return bytes(bytearray((seed + 7 * i) % 256 for i in range(code_limit)))


def build_code_directory(
    ident,
    hash_type,
    code_limit,
    code,
    scatter=False,
    declared_length_extra=0,
):
    """
    Build a CodeDirectory blob (version 0x20400 layout) whose normal
    code slots cover *code* (exactly *code_limit* bytes) with 4KiB
    pages; the last slot hashes the short tail page.
    """
    constructor = _HASHERS.get(hash_type, hashlib.sha256)
    n_slots = (code_limit + PAGE_SIZE - 1) // PAGE_SIZE
    hashes = []
    for index in range(n_slots):
        chunk = code[index * PAGE_SIZE : min((index + 1) * PAGE_SIZE, code_limit)]
        hashes.append(constructor(chunk).digest())
    hash_size = constructor().digest_size
    ident_bytes = ident.encode("ascii") + b"\x00"
    hash_offset = 88 + len(ident_bytes)
    length = 88 + len(ident_bytes) + n_slots * hash_size
    header = struct.pack(
        ">9I4B4I4Q",
        0xFADE0C02,  # CSMAGIC_CODEDIRECTORY
        length + declared_length_extra,
        0x20400,  # version
        0,  # flags
        hash_offset,
        88,  # identOffset
        0,  # nSpecialSlots
        n_slots,
        code_limit,
        hash_size,
        hash_type,
        0,  # platform
        PAGE_SHIFT,
        0,  # spare2
        0x40 if scatter else 0,  # scatterOffset
        0,  # teamOffset
        0,  # spare3
        0,  # codeLimit64
        0,  # execSegBase
        0,  # execSegLimit
        0,  # execSegFlags
    )
    return header + ident_bytes + b"".join(hashes)


def build_superblob(entries):
    """
    Build an embedded signature SuperBlob from (slot_type, blob) pairs.
    """
    count = len(entries)
    index = b""
    offset = 12 + 8 * count
    blobs = b""
    for slot_type, blob in entries:
        index += struct.pack(">2I", slot_type, offset)
        blobs += blob
        offset += len(blob)
    return struct.pack(">3I", 0xFADE0CC0, offset, count) + index + blobs


def build_slice(cputype, code, directories):
    """
    Build a thin 64-bit Mach-O slice whose code region is *code* and
    whose LC_CODE_SIGNATURE points at a SuperBlob containing
    *directories*, a list of (slot_type, ident, hash_type, kwargs)
    tuples; the extra kwargs are passed to build_code_directory.

    The directory hashes are computed over the actual slice bytes
    (including the mach header), exactly as they appear in the file.
    """
    code_limit = len(code)
    sig_offset = (code_limit + 15) & ~15
    n_slots = (code_limit + PAGE_SIZE - 1) // PAGE_SIZE

    # The SuperBlob length is fixed by the directory layouts and must
    # be known before the load command (which is itself hashed) can
    # be written.
    superblob_size = 12 + 8 * len(directories)
    for _slot_type, ident, hash_type, kwargs in directories:
        hash_size = _HASHERS.get(hash_type, hashlib.sha256)().digest_size
        superblob_size += 88 + len(ident) + 1 + n_slots * hash_size

    header = struct.pack(
        "<8I",
        mach_o.MH_MAGIC_64,
        cputype,
        0,  # cpusubtype
        MH_FILETYPE_EXECUTE,
        1,  # ncmds
        16,  # sizeofcmds
        0,  # flags
        0,  # reserved
    )
    command = struct.pack(
        "<4I",
        mach_o.LC_CODE_SIGNATURE,
        16,
        sig_offset,
        superblob_size,
    )
    code_region = header + command
    code_region += code[len(code_region) :]
    blobs = []
    for slot_type, ident, hash_type, kwargs in directories:
        blobs.append(
            (
                slot_type,
                build_code_directory(
                    ident, hash_type, code_limit, code_region, **kwargs
                ),
            )
        )
    superblob = build_superblob(blobs)
    assert len(superblob) == superblob_size
    slice_bytes = code_region
    slice_bytes += b"\x00" * (sig_offset - len(slice_bytes))
    slice_bytes += superblob
    return slice_bytes


def build_fat(arch_slices):
    """
    Build a universal binary from (cputype, slice_bytes) pairs, placing
    slices at 4KiB-aligned offsets in the given order.
    """
    nfat = len(arch_slices)
    header_size = 8 + 20 * nfat
    offset = (header_size + 0xFFF) & ~0xFFF
    arches = b""
    body = b""
    for cputype, slice_bytes in arch_slices:
        arches += struct.pack(">5I", cputype, 0, offset, len(slice_bytes), 12)
        pad = offset - (header_size + len(body))
        body += b"\x00" * pad + slice_bytes
        offset += len(slice_bytes)
        offset = (offset + 0xFFF) & ~0xFFF
    return struct.pack(">2I", mach_o.FAT_MAGIC, nfat) + arches + body


def make_slices():
    """
    Return {(cputype): slice_bytes} for a small dual-architecture file;
    the x86_64 slice uses a SHA-256 primary and SHA-1 alternate
    directory, the arm64 slice the other way around.
    """
    x86_code = _code_bytes(5000, 3)
    arm_code = _code_bytes(9000, 11)
    slices = {}
    slices[CPU_TYPE_X86_64] = build_slice(
        CPU_TYPE_X86_64,
        x86_code,
        [
            (
                CSSLOT_CODEDIRECTORY,
                "com.example.x86",
                CS_HASHTYPE_SHA256,
                {},
            ),
            (
                CSSLOT_ALTERNATE_CODEDIRECTORIES,
                "com.example.x86",
                CS_HASHTYPE_SHA1,
                {},
            ),
        ],
    )
    slices[CPU_TYPE_ARM64] = build_slice(
        CPU_TYPE_ARM64,
        arm_code,
        [
            (
                CSSLOT_CODEDIRECTORY,
                "com.example.arm",
                CS_HASHTYPE_SHA1,
                {},
            ),
            (
                CSSLOT_ALTERNATE_CODEDIRECTORIES,
                "com.example.arm",
                CS_HASHTYPE_SHA256,
                {},
            ),
        ],
    )
    return slices


class TempFileMixin(object):
    def write_temp(self, data):
        fd, filename = tempfile.mkstemp()
        self.addCleanup(os.unlink, filename)
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
        return filename


def slice_by_arch(result, cputype):
    for slice_ in result.slices:
        if slice_.cputype == cputype:
            return slice_
    raise AssertionError("no slice for cputype 0x%x" % (cputype,))


def directory_by_slot(slice_, slot_type):
    for directory in slice_.directories:
        if directory.slot_type == slot_type:
            return directory
    raise AssertionError("no directory for slot type 0x%x" % (slot_type,))


class TestCodeSignatureVerification(TempFileMixin, unittest.TestCase):
    def test_fat_file_all_slots_match(self):
        slices = make_slices()
        filename = self.write_temp(
            build_fat(
                [
                    (CPU_TYPE_X86_64, slices[CPU_TYPE_X86_64]),
                    (CPU_TYPE_ARM64, slices[CPU_TYPE_ARM64]),
                ]
            )
        )

        result = verify_code_signature(filename)
        self.assertTrue(result.matches)
        self.assertEqual(len(result.slices), 2)

        x86 = slice_by_arch(result, CPU_TYPE_X86_64)
        self.assertEqual(x86.arch, "x86_64")
        self.assertEqual(len(x86.directories), 2)

        primary = directory_by_slot(x86, CSSLOT_CODEDIRECTORY)
        self.assertEqual(primary.status, STATUS_OK)
        self.assertEqual(primary.hash_name, "sha256")
        self.assertEqual(primary.page_size, PAGE_SIZE)
        self.assertEqual(primary.code_limit, 5000)
        self.assertFalse(primary.is_alternate)
        self.assertEqual(len(primary.slots), 2)

        # Slots point back at file ranges; the tail page uses its
        # actual (short) length.
        first, last = primary.slots
        self.assertEqual(first.file_range, (x86.offset, x86.offset + 4096))
        self.assertEqual(last.file_range, (x86.offset + 4096, x86.offset + 5000))
        self.assertEqual(last.length, 5000 - 4096)
        self.assertTrue(all(slot.matches for slot in primary.slots))

        alternate = directory_by_slot(x86, CSSLOT_ALTERNATE_CODEDIRECTORIES)
        self.assertEqual(alternate.status, STATUS_OK)
        self.assertEqual(alternate.hash_name, "sha1")
        self.assertTrue(alternate.is_alternate)
        self.assertEqual(len(alternate.slots), 2)

        arm = slice_by_arch(result, CPU_TYPE_ARM64)
        self.assertEqual(arm.arch, "ARM64")
        arm_primary = directory_by_slot(arm, CSSLOT_CODEDIRECTORY)
        self.assertEqual(arm_primary.hash_name, "sha1")
        self.assertEqual(len(arm_primary.slots), 3)
        self.assertEqual(arm_primary.slots[-1].length, 9000 - 2 * 4096)

        # The report must not claim anything about signer trust.
        self.assertIn("trust", result.note)
        self.assertIn("signer", result.note)
        described = result.describe()
        self.assertEqual(described["note"], result.note)
        self.assertTrue(described["matches"])

    def test_results_follow_architecture_when_slices_swap(self):
        slices = make_slices()
        original = self.write_temp(
            build_fat(
                [
                    (CPU_TYPE_X86_64, slices[CPU_TYPE_X86_64]),
                    (CPU_TYPE_ARM64, slices[CPU_TYPE_ARM64]),
                ]
            )
        )
        swapped = self.write_temp(
            build_fat(
                [
                    (CPU_TYPE_ARM64, slices[CPU_TYPE_ARM64]),
                    (CPU_TYPE_X86_64, slices[CPU_TYPE_X86_64]),
                ]
            )
        )

        original_result = verify_code_signature(original)
        swapped_result = verify_code_signature(swapped)
        self.assertTrue(original_result.matches)
        self.assertTrue(swapped_result.matches)

        for cputype in (CPU_TYPE_X86_64, CPU_TYPE_ARM64):
            before = slice_by_arch(original_result, cputype)
            after = slice_by_arch(swapped_result, cputype)
            # The physical position changed...
            self.assertNotEqual(before.offset, after.offset)
            # ...but the per-architecture conclusions travel along.
            self.assertEqual(
                [d.status for d in before.directories],
                [d.status for d in after.directories],
            )
            for before_dir, after_dir in zip(before.directories, after.directories):
                self.assertEqual(before_dir.slot_type, after_dir.slot_type)
                self.assertEqual(
                    [s.expected for s in before_dir.slots],
                    [s.expected for s in after_dir.slots],
                )
                self.assertEqual(
                    [s.length for s in before_dir.slots],
                    [s.length for s in after_dir.slots],
                )
                self.assertTrue(all(s.matches for s in after_dir.slots))

    def test_single_byte_change_in_tail_page(self):
        slices = make_slices()
        data = build_fat(
            [
                (CPU_TYPE_X86_64, slices[CPU_TYPE_X86_64]),
                (CPU_TYPE_ARM64, slices[CPU_TYPE_ARM64]),
            ]
        )
        filename = self.write_temp(data)

        result = verify_code_signature(filename)
        arm = slice_by_arch(result, CPU_TYPE_ARM64)
        primary = directory_by_slot(arm, CSSLOT_CODEDIRECTORY)
        tail = primary.slots[-1]
        tamper_offset = tail.file_range[0] + tail.length // 2

        with open(filename, "r+b") as fp:
            fp.seek(tamper_offset)
            (byte,) = fp.read(1)
            fp.seek(tamper_offset)
            if isinstance(byte, int):  # Python 3
                fp.write(bytes([byte ^ 0xFF]))
            else:  # Python 2
                fp.write(chr(ord(byte) ^ 0xFF))

        result = verify_code_signature(filename)
        self.assertFalse(result.matches)

        # The untouched slice still fully matches.
        self.assertTrue(slice_by_arch(result, CPU_TYPE_X86_64).matches)

        arm = slice_by_arch(result, CPU_TYPE_ARM64)
        self.assertFalse(arm.matches)
        for directory in arm.directories:
            self.assertEqual(directory.status, STATUS_MISMATCH)
            mismatched = [s for s in directory.slots if not s.matches]
            # Exactly the slot covering the tampered byte is flagged.
            self.assertEqual(len(mismatched), 1)
            (slot,) = mismatched
            self.assertEqual(slot.index, len(directory.slots) - 1)
            self.assertLessEqual(slot.file_range[0], tamper_offset)
            self.assertLess(tamper_offset, slot.file_range[1])

    def test_scatter_directory_keeps_other_conclusions(self):
        code = _code_bytes(5000, 5)
        slice_bytes = build_slice(
            CPU_TYPE_X86_64,
            code,
            [
                (
                    CSSLOT_CODEDIRECTORY,
                    "com.example.x",
                    CS_HASHTYPE_SHA256,
                    {"scatter": True},
                ),
                (
                    CSSLOT_ALTERNATE_CODEDIRECTORIES,
                    "com.example.x",
                    CS_HASHTYPE_SHA1,
                    {},
                ),
            ],
        )
        filename = self.write_temp(slice_bytes)

        result = verify_code_signature(filename)
        (slice_,) = result.slices
        primary = directory_by_slot(slice_, CSSLOT_CODEDIRECTORY)
        self.assertEqual(primary.status, STATUS_UNSUPPORTED)
        self.assertIn("scatter", primary.reason)
        alternate = directory_by_slot(slice_, CSSLOT_ALTERNATE_CODEDIRECTORIES)
        self.assertEqual(alternate.status, STATUS_OK)
        self.assertTrue(alternate.matches)
        self.assertFalse(result.matches)

    def test_unknown_hash_type_keeps_other_conclusions(self):
        code = _code_bytes(5000, 5)
        slice_bytes = build_slice(
            CPU_TYPE_X86_64,
            code,
            [
                (
                    CSSLOT_CODEDIRECTORY,
                    "com.example.x",
                    42,
                    {},
                ),
                (
                    CSSLOT_ALTERNATE_CODEDIRECTORIES,
                    "com.example.x",
                    CS_HASHTYPE_SHA256,
                    {},
                ),
            ],
        )
        filename = self.write_temp(slice_bytes)

        result = verify_code_signature(filename)
        (slice_,) = result.slices
        primary = directory_by_slot(slice_, CSSLOT_CODEDIRECTORY)
        self.assertEqual(primary.status, STATUS_UNSUPPORTED)
        self.assertIn("unknown hash type", primary.reason)
        alternate = directory_by_slot(slice_, CSSLOT_ALTERNATE_CODEDIRECTORIES)
        self.assertEqual(alternate.status, STATUS_OK)
        self.assertTrue(alternate.matches)

    def test_truncated_directory_keeps_other_conclusions(self):
        code = _code_bytes(5000, 5)
        slice_bytes = build_slice(
            CPU_TYPE_X86_64,
            code,
            [
                (
                    CSSLOT_ALTERNATE_CODEDIRECTORIES,
                    "com.example.x",
                    CS_HASHTYPE_SHA1,
                    {},
                ),
                (
                    CSSLOT_CODEDIRECTORY,
                    "com.example.x",
                    CS_HASHTYPE_SHA256,
                    {"declared_length_extra": 0x100},
                ),
            ],
        )
        filename = self.write_temp(slice_bytes)

        result = verify_code_signature(filename)
        (slice_,) = result.slices
        primary = directory_by_slot(slice_, CSSLOT_CODEDIRECTORY)
        self.assertEqual(primary.status, STATUS_TRUNCATED)
        self.assertIn("truncated", primary.reason)
        alternate = directory_by_slot(slice_, CSSLOT_ALTERNATE_CODEDIRECTORIES)
        self.assertEqual(alternate.status, STATUS_OK)
        self.assertTrue(alternate.matches)

    def test_macho_convenience_method(self):
        slices = make_slices()
        filename = self.write_temp(
            build_fat(
                [
                    (CPU_TYPE_X86_64, slices[CPU_TYPE_X86_64]),
                    (CPU_TYPE_ARM64, slices[CPU_TYPE_ARM64]),
                ]
            )
        )
        result = MachO.MachO(filename).verify_code_signature()
        self.assertTrue(result.matches)
        self.assertEqual(result.filename, filename)


if __name__ == "__main__":
    unittest.main()
