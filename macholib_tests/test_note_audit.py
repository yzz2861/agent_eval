from __future__ import absolute_import, print_function

import contextlib
import os
import struct
import sys
import tempfile
import unittest

from macholib.note_audit import (
    KNOWN_OWNER_UNVERIFIED_ORIGIN,
    UNKNOWN_OWNER,
    AuditDict,
    audit_notes,
    find_overlaps,
    format_audit_report,
    format_audit_report_zh,
)
from macholib.mach_o import FAT_MAGIC, LC_NOTE, MH_MAGIC_64

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest  # noqa: F811


CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C
SLICE_ALIGN = 4096
PAYLOAD_OFFSET = 128


def lc_note(owner, offset, size):
    if isinstance(owner, bytes):
        owner_bytes = owner
    else:
        owner_bytes = owner.encode("ascii")
    return struct.pack(
        ">II16sQQ",
        LC_NOTE,
        40,
        owner_bytes[:16].ljust(16, b"\0"),
        offset,
        size,
    )


def make_slice(cpu_type, note_commands, payload=b"", slice_size=256):
    sizeofcmds = 40 * len(note_commands)
    header = struct.pack(
        ">IIIIIIII",
        MH_MAGIC_64,
        cpu_type,
        0,
        2,
        len(note_commands),
        sizeofcmds,
        0,
        0,
    )
    blob = header + b"".join(note_commands)
    if len(blob) > PAYLOAD_OFFSET:
        raise AssertionError("test commands overlap payload area")
    blob += b"\0" * (PAYLOAD_OFFSET - len(blob))
    blob += payload
    if len(blob) > slice_size:
        raise AssertionError("payload exceeds test slice size")
    blob += b"\0" * (slice_size - len(blob))
    return blob


def make_fat(slices):
    header = struct.pack(">II", FAT_MAGIC, len(slices))
    arch_table = b""
    offset = SLICE_ALIGN
    body = []
    for cpu_type, slice_bytes in slices:
        arch_table += struct.pack(
            ">IIIII",
            cpu_type,
            0,
            offset,
            len(slice_bytes),
            12,
        )
        body.append((offset, slice_bytes))
        offset += ((len(slice_bytes) + SLICE_ALIGN - 1) // SLICE_ALIGN) * SLICE_ALIGN

    fat = bytearray(offset)
    prefix = header + arch_table
    fat[: len(prefix)] = prefix
    for body_offset, slice_bytes in body:
        fat[body_offset : body_offset + len(slice_bytes)] = slice_bytes
    return bytes(fat)


def three_note_fat_bytes():
    build_owner = "fixture.build"
    scan_owner = "fixture.scan"
    build0 = b"BLD1" + b"0" * 20
    scan = b"SCN1" + b"s" * 20
    build1 = b"BLD1" + b"1" * 20

    slice0_payload = bytearray(64)
    slice0_payload[0 : len(build0)] = build0
    scan_payload_offset = 32
    slice0_payload[scan_payload_offset : scan_payload_offset + len(scan)] = scan

    note0 = lc_note(build_owner, PAYLOAD_OFFSET, len(build0))
    note1 = lc_note(
        scan_owner,
        PAYLOAD_OFFSET + scan_payload_offset,
        len(scan),
    )
    slice0 = make_slice(CPU_X86_64, [note0, note1], bytes(slice0_payload))

    slice1_payload = bytearray(32)
    slice1_payload[0 : len(build1)] = build1
    note2 = lc_note(build_owner, PAYLOAD_OFFSET, len(build1))
    slice1 = make_slice(CPU_ARM64, [note2], bytes(slice1_payload))

    return make_fat([(CPU_X86_64, slice0), (CPU_ARM64, slice1)])


@contextlib.contextmanager
def three_note_fat_file():
    path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".fat") as fp:
            fp.write(three_note_fat_bytes())
            path = fp.name
        yield path
    finally:
        if path is not None and os.path.exists(path):
            os.unlink(path)


def fixture_registry():
    return {
        "fixture.build": {
            "basis": "FIXTURE-BUILD-NOTE-V1 deterministic test interpretation",
            "magic": b"BLD1",
        },
        "fixture.scan": (
            "FIXTURE-SCAN-NOTE-V1 registered owner, but no source proof is registered"
        ),
    }


class NoteAuditTests(unittest.TestCase):
    FIXTURE_PATH = os.path.join(
        os.path.dirname(__file__), "fixtures", "three_plain_lc_notes.fat"
    )

    def test_three_note_fixture_records_slice_range_bytes_and_basis(self):
        with three_note_fat_file() as path:
            with open(path, "rb") as before_file:
                before = before_file.read()
            report = audit_notes(path, registry=fixture_registry())
            with open(path, "rb") as after_file:
                after = after_file.read()

        self.assertEqual(before, after)
        self.assertTrue(report.read_only)
        self.assertFalse(report.executed_sample)
        self.assertTrue(report.is_fat)
        self.assertEqual(report.slice_count, 2)
        self.assertEqual(report.note_count, 3)

        by_id = {entry.id: entry for entry in report.entries}
        self.assertEqual(
            sorted(by_id),
            ["slice0-note0", "slice0-note1", "slice1-note0"],
        )

        build0 = by_id["slice0-note0"]
        scan = by_id["slice0-note1"]
        build1 = by_id["slice1-note0"]

        self.assertEqual(build0.slice_index, 0)
        self.assertEqual(build1.slice_index, 1)
        self.assertEqual(build0.owner, "fixture.build")
        self.assertEqual(build1.owner, "fixture.build")
        self.assertEqual(scan.owner, "fixture.scan")

        self.assertEqual(build0.declared_offset, PAYLOAD_OFFSET)
        self.assertEqual(build0.declared_size, 24)
        self.assertEqual(build0.declared_interval, (128, 152))
        self.assertEqual(build0.file_offset, 4096 + 128)
        self.assertEqual(build0.readable_bytes, b"BLD1" + b"0" * 20)
        self.assertEqual(build1.file_offset, 8192 + 128)
        self.assertEqual(build1.readable_bytes, b"BLD1" + b"1" * 20)
        self.assertEqual(scan.readable_bytes, b"SCN1" + b"s" * 20)

        self.assertIn(
            "FIXTURE-BUILD-NOTE-V1",
            build0.registered_interpretation["basis"],
        )
        self.assertIn(
            "FIXTURE-SCAN-NOTE-V1",
            scan.registered_interpretation["basis"],
        )
        self.assertEqual(build0.status, "confirmed")
        self.assertEqual(build1.status, "confirmed")
        self.assertEqual(scan.status, KNOWN_OWNER_UNVERIFIED_ORIGIN)

    def test_report_identifies_name_only_pair_and_excluded_note(self):
        with three_note_fat_file() as path:
            report = audit_notes(path, registry=fixture_registry())

        self.assertEqual(len(report.same_name_only_pairs), 1)
        pair = report.same_name_only_pairs[0]
        self.assertEqual(pair.note_ids, ["slice0-note0", "slice1-note0"])
        self.assertEqual(pair.owner, "fixture.build")
        self.assertTrue(pair.distinct_slices)
        self.assertTrue(pair.same_name_only)
        self.assertFalse(pair.payload_digests_equal)

        self.assertEqual(
            report.confirmation_evidence_ids,
            ["slice0-note0", "slice1-note0"],
        )
        self.assertEqual(report.excluded_ids, ["slice0-note1"])
        self.assertEqual(
            report.excluded_from_confirmation[0].status,
            KNOWN_OWNER_UNVERIFIED_ORIGIN,
        )

        text = format_audit_report(report)
        self.assertIn("Same owner name only:", text)
        self.assertIn("slice0-note0 and slice1-note0 share only", text)
        self.assertIn("Confirmation evidence:", text)
        self.assertIn("Not confirmation evidence:", text)
        self.assertIn("slice0-note1", text)

        chinese = format_audit_report_zh(report)
        self.assertIn("仅同名关系:", chinese)
        self.assertIn("不应纳入确认证据:", chinese)
        self.assertIn("slice0-note1（known_owner_unverified_origin）", chinese)

    def test_unknown_owner_and_known_unprovenanced_owner_differ(self):
        payload = b"UNKNOWN!" + b"KNOWNOK!"
        slice_bytes = make_slice(
            CPU_X86_64,
            [
                lc_note("unknown.owner", PAYLOAD_OFFSET, 8),
                lc_note("known.owner", PAYLOAD_OFFSET + 8, 8),
            ],
            payload,
        )
        report = audit_notes(
            slice_bytes,
            registry={"known.owner": "REGISTERED-OWNER-BASIS"},
        )

        unknown = report.unknown_owner_notes[0]
        unverified = report.unverified_origin_notes[0]
        self.assertEqual(unknown.status, UNKNOWN_OWNER)
        self.assertIsNone(unknown.registration)
        self.assertIsNone(unknown.registered_interpretation)
        self.assertEqual(unverified.status, KNOWN_OWNER_UNVERIFIED_ORIGIN)
        self.assertIsNotNone(unverified.registration)
        self.assertIn("REGISTERED-OWNER-BASIS", unverified.registration.basis)
        self.assertNotEqual(unknown.status, unverified.status)
        self.assertFalse(unknown.confirmation_eligible)
        self.assertFalse(unverified.confirmation_eligible)

    def test_readable_bytes_are_clamped_to_declared_slice(self):
        slice_bytes = make_slice(
            CPU_X86_64,
            [lc_note("trunc.owner", PAYLOAD_OFFSET, 64)],
            b"abc",
            slice_size=160,
        )
        report = audit_notes(slice_bytes, registry={})
        entry = report.entries[0]
        self.assertEqual(entry.declared_size, 64)
        self.assertEqual(entry.readable_size, 32)
        self.assertEqual(entry.readable_bytes, b"abc" + b"\0" * 29)
        self.assertTrue(entry.truncated)
        self.assertFalse(entry.fully_readable)

    def test_small_overlap_has_no_read_order_winner(self):
        first = AuditDict(
            id="first",
            slice_index=0,
            declared_offset=128,
            declared_size=32,
            command_index=0,
        )
        second = AuditDict(
            id="second",
            slice_index=0,
            declared_offset=156,
            declared_size=32,
            command_index=1,
        )
        forward = find_overlaps([first, second])
        reverse = find_overlaps(
            [
                AuditDict(**second),
                AuditDict(**first),
            ]
        )

        self.assertEqual(len(forward), 1)
        self.assertEqual(forward[0].note_ids, ["first", "second"])
        self.assertEqual(forward[0].overlap_size, 4)
        self.assertIsNone(forward[0].winner)
        self.assertEqual(forward[0].resolution, "ambiguous_no_read_order_winner")
        self.assertEqual(
            [(item.note_ids, item.overlap_size, item.winner) for item in forward],
            [(item.note_ids, item.overlap_size, item.winner) for item in reverse],
        )

    def test_reversed_command_order_produces_same_owner_overlap_result(self):
        note_a = lc_note("owner.a", 128, 32)
        note_b = lc_note("owner.b", 156, 32)
        payload = b"x" * 64
        forward_bytes = make_slice(CPU_X86_64, [note_a, note_b], payload)
        reverse_bytes = make_slice(CPU_X86_64, [note_b, note_a], payload)
        registry = {
            "owner.a": {"basis": "A-BASIS", "provenance": "registered-source-a"},
            "owner.b": {"basis": "B-BASIS", "provenance": "registered-source-b"},
        }

        forward = audit_notes(forward_bytes, registry=registry)
        reverse = audit_notes(reverse_bytes, registry=registry)

        self.assertEqual(len(forward.overlaps), 1)
        self.assertEqual(forward.overlaps[0].overlap_size, 4)
        self.assertIsNone(forward.overlaps[0].winner)
        self.assertEqual(len(reverse.overlaps), 1)
        self.assertEqual(reverse.overlaps[0].overlap_size, 4)
        self.assertIsNone(reverse.overlaps[0].winner)

        forward_by_owner = {entry.owner: entry for entry in forward.entries}
        reverse_by_owner = {entry.owner: entry for entry in reverse.entries}
        for owner in ("owner.a", "owner.b"):
            self.assertEqual(
                forward_by_owner[owner].readable_bytes,
                reverse_by_owner[owner].readable_bytes,
            )
            self.assertTrue(forward_by_owner[owner].has_overlap)
            self.assertTrue(reverse_by_owner[owner].has_overlap)
            self.assertEqual(
                forward_by_owner[owner].status,
                reverse_by_owner[owner].status,
            )


if __name__ == "__main__":
    unittest.main()
