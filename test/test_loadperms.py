"""
Tests for elftools/elf/loadperms.py

All ELF images are built in-memory with struct; nothing is executed,
emulated, or delegated to native tools.
"""
import io
import struct
import unittest

from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.loadperms import (
    DiagnosticKind,
    MappingPolicy,
    analyze_load_permissions,
)

RX = P_FLAGS.PF_R | P_FLAGS.PF_X
RW = P_FLAGS.PF_W | P_FLAGS.PF_R
R = P_FLAGS.PF_R
RWX = P_FLAGS.PF_R | P_FLAGS.PF_W | P_FLAGS.PF_X

PAGE = 0x1000


def build_elf64(segments, osabi=0):
    """ Build a minimal ELF64 executable with PT_LOAD program headers only.

        segments: iterable of (flags, offset, vaddr, filesz, memsz, align)
    """
    segments = list(segments)
    ident = b'\x7fELF' + bytes([2, 1, 1, osabi]) + bytes(8)
    ehdr = struct.pack(
        '<16sHHIQQQIHHHHHH',
        ident,          # e_ident
        2,              # e_type = ET_EXEC
        0x3E,           # e_machine = EM_X86_64
        1,              # e_version
        0,              # e_entry
        64,             # e_phoff
        0,              # e_shoff (no sections at all)
        0,              # e_flags
        64,             # e_ehsize
        56,             # e_phentsize
        len(segments),  # e_phnum
        64,             # e_shentsize
        0,              # e_shnum
        0,              # e_shstrndx
    )
    phdrs = b''.join(
        struct.pack('<IIQQQQQQ', 1, flags, offset, vaddr, vaddr,
                    filesz, memsz, align)
        for flags, offset, vaddr, filesz, memsz, align in segments
    )
    return ehdr + phdrs


def analyze(data, page_size=PAGE, policy=MappingPolicy.PAGE_UNION):
    return analyze_load_permissions(ELFFile(io.BytesIO(data)), page_size, policy)


class TestLoadPerms(unittest.TestCase):
    def test_separate_pages_no_wx(self):
        # RX and RW segments on disjoint pages: no W+X under any policy.
        data = build_elf64([
            (RX, 0x1000, 0x1000, 0x400, 0x400, PAGE),
            (RW, 0x2000, 0x2000, 0x400, 0x400, PAGE),
        ])
        for policy in (MappingPolicy.PAGE_UNION, MappingPolicy.SEGMENT_ONLY):
            report = analyze(data, policy=policy)
            self.assertTrue(report.ok)
            self.assertEqual(report.wx_conflicts, [])

    def test_overlap_creates_wx_only_under_page_union(self):
        # RX and RW segments share page 0x1000. Viewed per segment there is
        # no W+X; the page union creates it.
        data = build_elf64([
            (RX, 0x1000, 0x1000, 0x800, 0x800, PAGE),
            (RW, 0x2800, 0x1800, 0x1000, 0x1000, PAGE),
        ])
        merged = analyze(data, policy=MappingPolicy.PAGE_UNION)
        self.assertEqual(len(merged.wx_conflicts), 1)
        conflict = merged.wx_conflicts[0]
        # Minimal conflict interval: exactly the shared page.
        self.assertEqual(conflict.vaddr_range, (0x1000, 0x2000))
        self.assertEqual(conflict.segment_indices, (0, 1))
        self.assertIn('PT_LOAD[0]', conflict.explanation)
        self.assertIn('PT_LOAD[1]', conflict.explanation)
        self.assertIn('union', conflict.explanation)
        # Page 0x2000 is written by segment 1 alone and stays RW.
        perms = {p.page_range[0]: p.perms for p in merged.pages}
        self.assertEqual(perms[0x1000], RWX)
        self.assertEqual(perms[0x2000], RW)

        split = analyze(data, policy=MappingPolicy.SEGMENT_ONLY)
        self.assertEqual(split.wx_conflicts, [])

    def test_readonly_shared_page_is_legal(self):
        # Two read-only segments sharing one page: overlap without W+X.
        data = build_elf64([
            (R, 0x1000, 0x1000, 0x800, 0x800, PAGE),
            (R, 0x2800, 0x1800, 0x800, 0x800, PAGE),
        ])
        report = analyze(data)
        self.assertTrue(report.ok)
        self.assertEqual(report.wx_conflicts, [])
        shared = [p for p in report.pages if p.page_range == (0x1000, 0x2000)]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0].perms, R)
        self.assertEqual(shared[0].segment_indices, (0, 1))

    def test_file_bytes_and_zero_fill(self):
        # memsz > filesz: the tail of the segment is zero-filled.
        data = build_elf64([
            (RW, 0x2000, 0x4000, 0x100, 0x300, PAGE),
        ])
        report = analyze(data)
        self.assertTrue(report.ok)
        seg = report.segments[0]
        self.assertEqual(seg.file_range, (0x2000, 0x2100))
        self.assertEqual(seg.vaddr_range, (0x4000, 0x4300))
        self.assertEqual(seg.zero_fill_range, (0x4100, 0x4300))
        self.assertEqual(seg.page_range, (0x4000, 0x5000))

    def test_diagnostics_are_independent(self):
        # One file with three independent problems plus one healthy segment:
        # all three diagnostics must be reported, and the healthy segment
        # must still be analyzed.
        data = build_elf64([
            # 0: vaddr + memsz wraps the 64-bit address space.
            (RX, 0x000, 0xFFFFFFFFFFFFF000, 0x2000, 0x2000, PAGE),
            # 1: p_vaddr and p_offset not congruent modulo p_align.
            (RW, 0x180, 0x5000, 0x100, 0x100, PAGE),
            # 2: healthy segment.
            (R, 0x000, 0x6000, 0x100, 0x100, PAGE),
        ], osabi=0xFF)
        report = analyze(data)
        self.assertFalse(report.ok)

        overflow = report.diagnostics_of(DiagnosticKind.ADDRESS_OVERFLOW)
        self.assertEqual([d.segment_index for d in overflow], [0])

        align = report.diagnostics_of(DiagnosticKind.ALIGNMENT_CONTRADICTION)
        self.assertEqual([d.segment_index for d in align], [1])

        abi = report.diagnostics_of(DiagnosticKind.UNSUPPORTED_ABI)
        self.assertEqual(len(abi), 1)
        self.assertIsNone(abi[0].segment_index)

        # All three kinds coexist in one report.
        self.assertEqual(len(report.diagnostics), 3)

        # The healthy segment still contributes pages; the overflowing one
        # does not.
        self.assertEqual(len(report.segments), 3)
        self.assertEqual([p.page_range for p in report.pages],
                         [(0x5000, 0x6000), (0x6000, 0x7000)])

    def test_invalid_arguments(self):
        data = build_elf64([(R, 0, 0x1000, 0x10, 0x10, PAGE)])
        for bad_page_size in (0, -1, 0x1001, 0x1800):
            with self.assertRaises(ValueError):
                analyze(data, page_size=bad_page_size)
        with self.assertRaises(ValueError):
            analyze(data, policy='page_union')


if __name__ == '__main__':
    unittest.main()
