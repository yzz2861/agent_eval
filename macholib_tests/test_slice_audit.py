import os
import shutil
import struct
import tempfile
import uuid

from macholib import mach_o, slice_audit

try:
    import unittest2 as unittest
except ImportError:
    import unittest

CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_X86_64_ALL = 3
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0

MH_FILETYPE_EXECUTE = 0x2

UUID_X86_64 = uuid.UUID("11111111-2222-3333-4444-555555555555")
UUID_ARM64 = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
UUID_FOREIGN = uuid.UUID("deadbeef-dead-beef-dead-beefdeadbeef")

MACH_HEADER_64_SIZE = 32
LC_UUID_SIZE = 24


def lc_uuid(macho_uuid):
    return struct.pack(">II16s", mach_o.LC_UUID, LC_UUID_SIZE, macho_uuid.bytes)


def thin_macho(cputype, cpusubtype, macho_uuid, ncmds=None, tail=b""):
    load_commands = []
    if macho_uuid is not None:
        load_commands.append(lc_uuid(macho_uuid))
    if ncmds is None:
        ncmds = len(load_commands)
    sizeofcmds = sum(len(command) for command in load_commands)
    header = struct.pack(
        ">IIIIIIII",
        mach_o.MH_MAGIC_64,
        cputype,
        cpusubtype,
        MH_FILETYPE_EXECUTE,
        ncmds,
        sizeofcmds,
        0,
        0,
    )
    return header + b"".join(load_commands) + tail


def fat_macho(slices):
    arch_format = ">iIIII"
    arch_size = struct.calcsize(arch_format)
    offset = 8 + arch_size * len(slices)
    archs = []
    body = b""
    for cputype, cpusubtype, data in slices:
        padding = -offset % 8
        body += b"\x00" * padding
        offset += padding
        archs.append(
            struct.pack(arch_format, cputype, cpusubtype, offset, len(data), 3)
        )
        body += data
        offset += len(data)
    return struct.pack(">II", mach_o.FAT_MAGIC, len(slices)) + b"".join(archs) + body


class ReleaseFixture(object):
    """
    A release set that pairs completely: a universal Mach-O with x86_64 and
    arm64 slices, an archive with one extracted member per architecture and
    one standalone debug file per architecture.
    """

    def __init__(self, root):
        self.root = root
        self.universal = os.path.join(root, "universal")
        self.archive = os.path.join(root, "archive")
        os.mkdir(self.archive)
        self.archive_x86_64 = os.path.join(self.archive, "member-x86_64")
        self.archive_arm64 = os.path.join(self.archive, "member-arm64")
        self.debug_x86_64 = os.path.join(root, "debug-x86_64.dwarf")
        self.debug_arm64 = os.path.join(root, "debug-arm64.dwarf")

        self._write(
            self.universal,
            fat_macho(
                [
                    (
                        CPU_TYPE_X86_64,
                        CPU_SUBTYPE_X86_64_ALL,
                        thin_macho(
                            CPU_TYPE_X86_64,
                            CPU_SUBTYPE_X86_64_ALL,
                            UUID_X86_64,
                        ),
                    ),
                    (
                        CPU_TYPE_ARM64,
                        CPU_SUBTYPE_ARM64_ALL,
                        thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, UUID_ARM64),
                    ),
                ]
            ),
        )
        self._write(
            self.archive_x86_64,
            thin_macho(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, UUID_X86_64),
        )
        self._write(
            self.archive_arm64,
            thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, UUID_ARM64),
        )
        self._write(
            self.debug_x86_64,
            thin_macho(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, UUID_X86_64),
        )
        self._write(
            self.debug_arm64,
            thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, UUID_ARM64),
        )

    @staticmethod
    def _write(path, data):
        with open(path, "wb") as fh:
            fh.write(data)

    @property
    def debug_files(self):
        return [self.debug_x86_64, self.debug_arm64]

    def audit(self, archive=None, debug_files=None):
        if archive is None:
            archive = self.archive
        if debug_files is None:
            debug_files = self.debug_files
        return slice_audit.audit_release(self.universal, archive, debug_files)


class TestSliceAudit(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.fixture = ReleaseFixture(self.root)

    def test_complete_release_pairs_uniquely(self):
        report = self.fixture.audit()
        self.assertTrue(report.ok, report.summary())
        self.assertEqual(len(report.uniques), 2)
        self.assertEqual(report.duplicates, [])
        self.assertEqual(report.incompletes, [])
        self.assertEqual(report.unmatcheds, [])
        for pairing in report.uniques:
            self.assertEqual(pairing.roles, ["archive", "debug", "universal"])
            self.assertEqual(len(pairing.slices), 3)

    def test_command_provenance_is_preserved(self):
        report = self.fixture.audit()
        self.assertTrue(report.ok, report.summary())

        slices = slice_audit.read_slices(self.fixture.universal, "universal")
        self.assertEqual(len(slices), 2)
        first, second = slices
        self.assertEqual(first.slice_offset, 48)
        self.assertEqual(second.slice_offset, 104)

        uuid_command = second.commands[0]
        self.assertEqual(uuid_command.source, self.fixture.universal)
        self.assertEqual(uuid_command.slice_offset, 104)
        self.assertEqual(uuid_command.command_offset, 104 + MACH_HEADER_64_SIZE)
        self.assertEqual(uuid_command.cmd, mach_o.LC_UUID)
        self.assertEqual(uuid.UUID(bytes=uuid_command.uuid), UUID_ARM64)

        thin = slice_audit.read_slices(self.fixture.debug_x86_64, "debug")
        self.assertEqual(len(thin), 1)
        self.assertEqual(thin[0].slice_offset, 0)
        self.assertEqual(thin[0].commands[0].command_offset, MACH_HEADER_64_SIZE)
        self.assertEqual(thin[0].commands[0].source, self.fixture.debug_x86_64)

    def test_swapped_archive_member_is_identified(self):
        # Replace the arm64 archive member with a foreign slice: the audit
        # must point at the archive member, not at anything else.
        self.fixture._write(
            self.fixture.archive_arm64,
            thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, UUID_FOREIGN),
        )
        report = self.fixture.audit()
        self.assertFalse(report.ok)
        self.assertEqual(len(report.uniques), 1)
        self.assertEqual(report.duplicates, [])
        self.assertEqual(report.incompletes, [])

        unmatched_sources = {}
        for unmatched in report.unmatcheds:
            unmatched_sources.setdefault(unmatched.slice.source, set()).add(
                unmatched.slice.role
            )
        self.assertIn(self.fixture.archive_arm64, unmatched_sources)
        self.assertEqual(unmatched_sources[self.fixture.archive_arm64], {"archive"})
        # The orphaned universal and debug slices are reported as well.
        self.assertIn(self.fixture.universal, unmatched_sources)
        self.assertIn(self.fixture.debug_arm64, unmatched_sources)
        # The healthy x86_64 members stay paired.
        self.assertNotIn(self.fixture.archive_x86_64, unmatched_sources)
        self.assertNotIn(self.fixture.debug_x86_64, unmatched_sources)
        self.assertIn(self.fixture.archive_arm64, report.summary())

    def test_swapped_archive_member_found_as_directory_and_list(self):
        self.fixture._write(
            self.fixture.archive_arm64,
            thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, UUID_FOREIGN),
        )
        as_directory = self.fixture.audit()
        as_list = self.fixture.audit(
            archive=[self.fixture.archive_x86_64, self.fixture.archive_arm64]
        )
        self.assertEqual(as_directory.summary(), as_list.summary())

    def test_duplicate_identity_is_order_independent(self):
        # Two archive members share the x86_64 identity: neither may be
        # consumed as "the" match, regardless of input order.
        dupe = os.path.join(self.root, "archive", "member-x86_64-copy")
        self.fixture._write(
            dupe,
            thin_macho(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, UUID_X86_64),
        )
        members = [self.fixture.archive_x86_64, dupe, self.fixture.archive_arm64]

        report = self.fixture.audit(archive=members)
        self.assertFalse(report.ok)
        self.assertEqual(len(report.duplicates), 1)
        duplicate_sources = set(slice_.source for slice_ in report.duplicates[0].slices)
        self.assertEqual(
            duplicate_sources,
            set(
                [
                    self.fixture.archive_x86_64,
                    dupe,
                    self.fixture.universal,
                    self.fixture.debug_x86_64,
                ]
            ),
        )
        self.assertEqual(len(report.uniques), 1)

        reversed_report = self.fixture.audit(archive=list(reversed(members)))
        self.assertEqual(report.summary(), reversed_report.summary())

    def test_input_order_does_not_change_classification(self):
        forward = self.fixture.audit()
        shuffled = self.fixture.audit(
            archive=[self.fixture.archive_arm64, self.fixture.archive_x86_64],
            debug_files=[self.fixture.debug_arm64, self.fixture.debug_x86_64],
        )
        self.assertEqual(forward.summary(), shuffled.summary())

    def test_incomplete_command_read(self):
        # ncmds claims two load commands but the file ends after the first.
        truncated = os.path.join(self.root, "archive", "member-arm64")
        self.fixture._write(
            truncated,
            thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, UUID_ARM64, ncmds=2),
        )
        report = self.fixture.audit()
        self.assertFalse(report.ok)
        self.assertEqual(len(report.incompletes), 1)
        incomplete = report.incompletes[0]
        self.assertEqual(incomplete.source, truncated)
        self.assertEqual(incomplete.role, "archive")
        self.assertIsNotNone(incomplete.error)
        # The truncated slice must not be paired on partial evidence.
        for pairing in report.uniques:
            for slice_ in pairing.slices:
                self.assertNotEqual(slice_.source, truncated)

    def test_missing_uuid_has_insufficient_evidence(self):
        no_uuid = os.path.join(self.root, "debug-plain.dwarf")
        self.fixture._write(
            no_uuid,
            thin_macho(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, None),
        )
        report = self.fixture.audit(debug_files=self.fixture.debug_files + [no_uuid])
        self.assertFalse(report.ok)
        reasons = dict(
            (unmatched.slice.source, unmatched.reason)
            for unmatched in report.unmatcheds
        )
        self.assertIn(no_uuid, reasons)
        self.assertIn("LC_UUID", reasons[no_uuid])

    def test_read_slices_does_not_modify_files(self):
        paths = [
            self.fixture.universal,
            self.fixture.archive_x86_64,
            self.fixture.debug_arm64,
        ]
        before = {}
        for path in paths:
            with open(path, "rb") as fh:
                before[path] = fh.read()
        self.fixture.audit()
        for path in paths:
            with open(path, "rb") as fh:
                self.assertEqual(before[path], fh.read())


if __name__ == "__main__":
    unittest.main()
