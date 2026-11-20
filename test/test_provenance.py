#-------------------------------------------------------------------------------
# elftools tests
#
# Tests for read-only board-address provenance queries.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
import io
import struct
import unittest

from elftools.elf.elffile import ELFFile
from elftools.elf.provenance import (
    ProvenanceKind,
    StorageWindow,
    WindowMappingError,
)


def _offline_fixture():
    """Build a small ELF image plus a deterministic file-byte pattern.

    The three PT_LOAD segments deliberately leave a gap between the first
    segment's zero-fill end and the second segment's start.  This makes it
    possible to test all provenance kinds in one offline fixture.
    """

    # (p_vaddr, p_offset, p_filesz, p_memsz)
    segments = (
        (0x1000, 0x400, 0x130, 0x180),
        (0x1240, 0x600, 0x080, 0x080),
        (0x1500, 0x700, 0x040, 0x040),
    )
    image = bytearray(0x740)
    payloads = []
    for segment_index, (_vaddr, offset, filesz, _memsz) in enumerate(segments):
        payload = bytes(
            (index * 53 + segment_index * 17 + 11) & 0xff
            for index in range(filesz))
        image[offset:offset + filesz] = payload
        payloads.append(payload)

    ident = b'\x7fELF' + bytes((2, 1, 1, 0)) + b'\x00' * 8
    header = struct.pack(
        '<16sHHIQQQIHHHHHH',
        ident,
        2,              # ET_EXEC
        62,             # EM_X86_64
        1,              # e_version
        0,              # e_entry
        64,             # e_phoff
        0,              # e_shoff
        0,              # e_flags
        64,             # e_ehsize
        56,             # e_phentsize
        len(segments),  # e_phnum
        0,              # e_shentsize
        0,              # e_shnum
        0,              # e_shstrndx
    )
    image[0:64] = header

    for index, (vaddr, offset, filesz, memsz) in enumerate(segments):
        program_header = struct.pack(
            '<IIQQQQQQ',
            1,       # PT_LOAD
            5,       # PF_R | PF_X
            offset,
            vaddr,
            vaddr,
            filesz,
            memsz,
            0x1000,
        )
        start = 64 + index * 56
        image[start:start + 56] = program_header

    return io.BytesIO(bytes(image)), payloads


class TestAddressProvenance(unittest.TestCase):
    def setUp(self):
        self.stream, self.payloads = _offline_fixture()
        self.elf = ELFFile(self.stream)

    def test_range_crosses_window_and_segment_boundaries(self):
        windows = [
            StorageWindow(0x8000, 0x100, 0x1000),
            {
                'board_start': 0x8100,
                'board_end': 0x8200,
                'elf_address': 0x1100,
            },
            (0x8200, 0x8300, 0x1200),
        ]

        report = self.elf.query_address_provenance(
            0x80E0, 0x190, windows, state=None)

        self.assertEqual(report.start, 0x80E0)
        self.assertEqual(report.end, 0x8270)
        self.assertFalse(report.ambiguous)
        self.assertEqual(len(report.spans), 6)

        expected = [
            # address, size, kind, elf address, file offset, segment
            (0x80E0, 0x20, ProvenanceKind.FILE_BYTES, 0x10E0, 0x4E0, 0),
            (0x8100, 0x30, ProvenanceKind.FILE_BYTES, 0x1100, 0x500, 0),
            (0x8130, 0x50, ProvenanceKind.ZERO_FILL, 0x1130, None, 0),
            (0x8180, 0x80, ProvenanceKind.UNATTESTED, 0x1180, None, None),
            (0x8200, 0x40, ProvenanceKind.UNATTESTED, 0x1200, None, None),
            (0x8240, 0x30, ProvenanceKind.FILE_BYTES, 0x1240, 0x600, 1),
        ]
        actual = [
            (
                span.start,
                span.size,
                span.kind,
                span.sources[0].elf_address,
                span.sources[0].file_offset,
                span.sources[0].segment_index,
            )
            for span in report.spans
        ]
        self.assertEqual(actual, expected)

        # Reviewers can follow every file-backed piece back to the original
        # bytes without relying on any reconstructed memory image.
        self.stream.seek(0)
        for source in report.iter_segments(ProvenanceKind.FILE_BYTES):
            data = source.read_data(self.stream)
            self.assertEqual(
                data,
                bytes(self.stream.getvalue()[
                    source.file_offset:source.file_offset + source.size]))
        self.assertEqual(self.stream.tell(), 0)

        file_sources = list(report.iter_segments('file_bytes'))
        self.assertEqual(
            [source.file_offset for source in file_sources],
            [0x4E0, 0x500, 0x600])
        self.assertEqual(
            [source.size for source in file_sources],
            [0x20, 0x30, 0x30])

    def test_unknown_state_returns_parallel_sources(self):
        windows = [
            StorageWindow(0x8100, 0x100, 0x1100, state='boot-a'),
            StorageWindow(0x8100, 0x100, 0x1500, state='boot-b'),
        ]

        report = self.elf.resolve_address_range(0x8100, 0x40, windows)

        self.assertTrue(report.ambiguous)
        self.assertEqual(len(report.spans), 2)
        first, second = report.spans

        self.assertTrue(first.ambiguous)
        self.assertEqual(first.start, 0x8100)
        self.assertEqual(first.size, 0x30)
        self.assertEqual(
            [
                (source.state, source.kind, source.file_offset)
                for source in first.sources
            ],
            [
                ('boot-a', ProvenanceKind.FILE_BYTES, 0x500),
                ('boot-b', ProvenanceKind.FILE_BYTES, 0x700),
            ])

        self.assertTrue(second.ambiguous)
        self.assertEqual(second.start, 0x8130)
        self.assertEqual(second.size, 0x10)
        self.assertEqual(
            [
                (source.state, source.kind, source.file_offset)
                for source in second.sources
            ],
            [
                ('boot-a', ProvenanceKind.ZERO_FILL, None),
                ('boot-b', ProvenanceKind.FILE_BYTES, 0x730),
            ])

    def test_known_state_selects_one_window(self):
        windows = [
            StorageWindow(0x8100, 0x100, 0x1100, state='boot-a'),
            StorageWindow(0x8100, 0x100, 0x1500, state='boot-b'),
        ]

        report_a = self.elf.query_address_provenance(
            0x8100, 0x40, windows, state='boot-a')
        self.assertFalse(report_a.ambiguous)
        self.assertEqual(
            [span.kind for span in report_a.spans],
            [ProvenanceKind.FILE_BYTES, ProvenanceKind.ZERO_FILL])

        report_b = self.elf.query_address_provenance(
            0x8100, 0x40, windows, state='boot-b')
        self.assertFalse(report_b.ambiguous)
        self.assertEqual(
            [span.kind for span in report_b.spans],
            [ProvenanceKind.FILE_BYTES, ProvenanceKind.FILE_BYTES])
        self.assertEqual(
            [span.file_offset for span in report_b.spans],
            [0x700, 0x730])

    def test_unmapped_and_zero_length_ranges(self):
        windows = [StorageWindow(0x8000, 0x100, 0x1000)]

        report = self.elf.query_address_provenance(0x7000, 0x10, windows)
        self.assertEqual(len(report.spans), 1)
        self.assertEqual(report.spans[0].kind, ProvenanceKind.UNMAPPED)
        self.assertIsNone(report.spans[0].file_offset)

        empty = self.elf.query_address_provenance(0x8000, 0, windows)
        self.assertEqual(empty.spans, ())
        self.assertEqual(empty.segments, ())

    def test_conflicting_windows_in_one_state_are_rejected(self):
        windows = [
            StorageWindow(0x8000, 0x100, 0x1000, state='boot-a'),
            StorageWindow(0x8080, 0x100, 0x2000, state='boot-a'),
        ]

        with self.assertRaises(WindowMappingError):
            self.elf.query_address_provenance(0x8000, 0x10, windows)

        with self.assertRaises(ValueError):
            self.elf.query_address_provenance(
                0x8000, 0x10, windows, state='boot-a')

    def test_mapping_dictionary_aliases(self):
        window = StorageWindow.from_mapping({
            'address': 0x8000,
            'length': 0x100,
            'vaddr': 0x1000,
            'mode': 'boot-a',
            'label': 'flash-bank-0',
        })
        self.assertEqual(window.start, 0x8000)
        self.assertEqual(window.end, 0x8100)
        self.assertEqual(window.elf_start, 0x1000)
        self.assertEqual(window.state, 'boot-a')
        self.assertEqual(window.name, 'flash-bank-0')


if __name__ == '__main__':
    unittest.main()
