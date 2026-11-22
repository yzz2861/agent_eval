import contextlib
import os
import struct
import sys
import tempfile

from macholib import mach_o, note_audit

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ALL = 0x0
MH_FILETYPE_EXECUTE = 0x2

KNOWN_OWNER = "ACME.BLD"
KNOWN_MAGIC = b"ACBL\x01"
KNOWN_REFERENCE = "build-tools runbook rev.7"
UNKNOWN_OWNER = "QRST.UNK"

PAYLOAD_GENUINE = KNOWN_MAGIC + b"build 147"
PAYLOAD_UNKNOWN = b"QRST team note"
PAYLOAD_FORGED = b"XXXX not a genuine stamp"


def make_registry():
    registry = note_audit.NoteRegistry()
    registry.register(
        KNOWN_OWNER,
        magic=KNOWN_MAGIC,
        description="ACME internal build stamp",
        reference=KNOWN_REFERENCE,
    )
    return registry


def lc_note(owner, offset, size):
    note_format = ">II16sQQ"
    return struct.pack(
        note_format,
        mach_o.LC_NOTE,
        struct.calcsize(note_format),
        owner.encode("ascii"),
        offset,
        size,
    )


def thin_slice(cputype, load_commands, payload_area):
    """
    Bytes for one Mach-O slice: header, load commands, then padding
    up to the payload area, which is written at its declared offsets.
    """
    mach_header_format = ">IIIIIIII"
    header = struct.pack(
        mach_header_format,
        mach_o.MH_MAGIC_64,
        cputype,
        CPU_SUBTYPE_ALL,
        MH_FILETYPE_EXECUTE,
        len(load_commands),
        sum(len(lc) for lc in load_commands),
        0,
        0,
    )
    blob = bytearray(header + b"".join(load_commands))
    for offset, data in payload_area:
        if len(blob) < offset:
            blob.extend(b"\x00" * (offset - len(blob)))
        blob[offset : offset + len(data)] = data
    return bytes(blob)


def fat_file(slices):
    """
    Wrap (cputype, slice_bytes) pairs into a fat Mach-O.
    """
    arch_format = ">IIIII"
    header_size = struct.calcsize(">II") + len(slices) * struct.calcsize(arch_format)
    offset = header_size
    archs = []
    for cputype, slice_bytes in slices:
        archs.append((cputype, offset, len(slice_bytes)))
        offset += len(slice_bytes)
    blob = bytearray(struct.pack(">II", mach_o.FAT_MAGIC, len(slices)))
    for (cputype, slice_offset, slice_size), (_, slice_bytes) in zip(archs, slices):
        blob.extend(
            struct.pack(
                arch_format, cputype, CPU_SUBTYPE_ALL, slice_offset, slice_size, 0
            )
        )
    for (cputype, slice_offset, slice_size), (_, slice_bytes) in zip(archs, slices):
        blob[slice_offset : slice_offset + slice_size] = slice_bytes
    return bytes(blob)


def three_note_fixture():
    """
    Fat Mach-O with two slices and three ordinary notes:

    * note A (x86_64 slice): owner ACME.BLD, genuine payload,
    * note B (x86_64 slice): owner QRST.UNK, not registered,
    * note C (ARM64 slice): owner ACME.BLD again, but a payload that
      cannot be proven to come from the registered owner.
    """
    slice_x86 = thin_slice(
        CPU_TYPE_X86_64,
        [
            lc_note(KNOWN_OWNER, 0x100, len(PAYLOAD_GENUINE)),
            lc_note(UNKNOWN_OWNER, 0x120, len(PAYLOAD_UNKNOWN)),
        ],
        [(0x100, PAYLOAD_GENUINE), (0x120, PAYLOAD_UNKNOWN)],
    )
    slice_arm = thin_slice(
        CPU_TYPE_ARM64,
        [lc_note(KNOWN_OWNER, 0x100, len(PAYLOAD_FORGED))],
        [(0x100, PAYLOAD_FORGED)],
    )
    return fat_file([(CPU_TYPE_X86_64, slice_x86), (CPU_TYPE_ARM64, slice_arm)])


@contextlib.contextmanager
def temporary_file(contents):
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        fp.write(contents)
        fp.close()
        yield fp.name
        os.unlink(fp.name)


class TestThreeNoteFixture(unittest.TestCase):
    def setUp(self):
        self.registry = make_registry()
        self.fixture = three_note_fixture()
        self._tmp = temporary_file(self.fixture)
        self.filename = self._tmp.__enter__()
        self.addCleanup(self._tmp.__exit__, None, None, None)
        self.report = note_audit.audit_notes(self.filename, self.registry)

    def test_audit_is_read_only(self):
        with open(self.filename, "rb") as fp:
            self.assertEqual(fp.read(), self.fixture)

    def test_unknown_and_unproven_are_different_results(self):
        statuses = [note.status for note in self.report.notes]
        self.assertEqual(
            statuses,
            [
                note_audit.STATUS_CONFIRMED,
                note_audit.STATUS_UNKNOWN_OWNER,
                note_audit.STATUS_UNPROVEN_OWNER,
            ],
        )
        self.assertNotEqual(
            note_audit.STATUS_UNKNOWN_OWNER, note_audit.STATUS_UNPROVEN_OWNER
        )

    def test_slice_range_bytes_and_basis_are_preserved(self):
        genuine, unknown, forged = self.report.notes

        self.assertEqual(genuine.slice_index, 0)
        self.assertEqual(genuine.cpu_name, "x86_64")
        self.assertEqual(genuine.declared_offset, 0x100)
        self.assertEqual(genuine.declared_size, len(PAYLOAD_GENUINE))
        self.assertEqual(genuine.readable_size, len(PAYLOAD_GENUINE))
        self.assertEqual(genuine.payload, PAYLOAD_GENUINE)
        self.assertFalse(genuine.truncated)
        self.assertIsNotNone(genuine.basis)
        self.assertEqual(genuine.basis.reference, KNOWN_REFERENCE)

        self.assertEqual(unknown.slice_index, 0)
        self.assertIsNone(unknown.basis)

        self.assertEqual(forged.slice_index, 1)
        self.assertEqual(forged.cpu_name, "ARM64")
        self.assertEqual(forged.payload, PAYLOAD_FORGED)
        self.assertIsNotNone(forged.basis)
        self.assertEqual(forged.basis.reference, KNOWN_REFERENCE)

    def test_same_named_notes_and_evidence_exclusion(self):
        # Both slices use owner ACME.BLD, but the two notes only share
        # the name: their payloads differ.
        self.assertEqual(self.report.same_owner_groups(), [(KNOWN_OWNER, [0, 2])])

        # Only the genuine note may be used as confirmation evidence.
        evidence = self.report.confirmed_evidence()
        self.assertEqual(evidence, [self.report.notes[0]])

        output = self.report.explain()
        self.assertIn("merely same-named", output)
        self.assertIn("note[0]", output)
        self.assertIn("note[2]", output)
        # The forged note in the ARM64 slice is the one that must not
        # be used as confirmation evidence.
        self.assertIn(
            "note[2] excluded from confirmation evidence: "
            "owner 'ACME.BLD' is registered but the payload does not "
            "match the registered basis",
            output,
        )
        self.assertIn(
            "note[1] excluded from confirmation evidence: "
            "owner 'QRST.UNK' is not registered",
            output,
        )
        self.assertNotIn("note[0] excluded", output)


def overlapping_notes_file(note_order):
    """
    Thin Mach-O where two genuine-looking notes overlap by 8 bytes;
    *note_order* controls the load command order in the file.
    """
    first = KNOWN_MAGIC + b"first"
    second = KNOWN_MAGIC + b"second"
    payload = bytearray(b"\x00" * 0x20)
    payload[0x00 : 0x00 + len(first)] = first
    payload[0x08 : 0x08 + len(second)] = second
    notes = [
        lc_note(KNOWN_OWNER, 0x100, 0x10),
        lc_note(KNOWN_OWNER, 0x108, 0x10),
    ]
    commands = [notes[index] for index in note_order]
    return thin_slice(CPU_TYPE_X86_64, commands, [(0x100, bytes(payload))])


class TestOverlap(unittest.TestCase):
    def test_small_overlap_is_not_decided_by_read_order(self):
        registry = make_registry()
        summaries = []
        for order in ([0, 1], [1, 0]):
            with temporary_file(overlapping_notes_file(order)) as filename:
                report = note_audit.audit_notes(filename, registry)
            summaries.append(
                [
                    (
                        note.declared_offset,
                        note.status,
                        note.overlaps,
                        note.is_confirmation_evidence,
                    )
                    for note in report.notes
                ]
            )
        self.assertEqual(summaries[0], summaries[1])

        # Both notes would be confirmed on payload alone, but the
        # overlap flags both of them, whichever was read first.
        for declared_offset, status, overlaps, is_evidence in summaries[0]:
            self.assertEqual(status, note_audit.STATUS_CONFIRMED)
            self.assertEqual(len(overlaps), 1)
            self.assertFalse(is_evidence)

    def test_overlap_exclusion_is_explained(self):
        registry = make_registry()
        with temporary_file(overlapping_notes_file([0, 1])) as filename:
            report = note_audit.audit_notes(filename, registry)
        self.assertEqual(report.confirmed_evidence(), [])
        output = report.explain()
        self.assertIn("note[0] excluded from confirmation evidence", output)
        self.assertIn("overlaps note[1]", output)
        self.assertIn("note[1] excluded from confirmation evidence", output)
        self.assertIn("overlaps note[0]", output)


class TestTruncatedRange(unittest.TestCase):
    def test_declared_range_past_slice_end(self):
        registry = make_registry()
        contents = thin_slice(
            CPU_TYPE_X86_64,
            [lc_note(KNOWN_OWNER, 0x100, 0x100)],
            [(0x100, PAYLOAD_GENUINE)],
        )
        with temporary_file(contents) as filename:
            report = note_audit.audit_notes(filename, registry)
        (note,) = report.notes
        self.assertEqual(note.declared_size, 0x100)
        self.assertEqual(note.readable_size, len(PAYLOAD_GENUINE))
        self.assertEqual(note.payload, PAYLOAD_GENUINE)
        self.assertTrue(note.truncated)
        self.assertFalse(note.is_confirmation_evidence)
        self.assertIn(
            "not fully readable (%d of 256 bytes)" % (len(PAYLOAD_GENUINE),),
            report.explain(),
        )


if __name__ == "__main__":
    unittest.main()
