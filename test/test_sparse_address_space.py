"""Sparse address space tests on hand-built synthetic ELF core files.

The cores are generated in memory (nothing reads live process memory) and
exercise cross-segment reads, partially captured pages, zero fill versus
missing memory, identical and disagreeing overlaps, bounded pointer-chain
walks and independent replay of the same evidence.
"""
import struct
import unittest
from io import BytesIO

from elftools.elf.elffile import ELFFile
from elftools.elf.sparse import SpanKind, SparseAddressSpace

import examples.elf_sparse_pointer_chain as pointer_chain


ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56


def build_core(specs, *, truncate_last=0):
    """ Assemble a minimal little-endian ELF64 ET_CORE from PT_LOAD specs.

        Each spec is (vaddr, file_data, memsz); p_filesz is len(file_data)
        unless truncate_last is positive, in which case the last segment
        claims that many extra file bytes that the core never contains,
        modelling a truncated capture. Returns the core as bytes.
    """
    count = len(specs)
    phoff = ELF_HEADER_SIZE
    data_offset = phoff + count * PROGRAM_HEADER_SIZE
    regions = []
    program_headers = b''
    cursor = data_offset
    for index, (vaddr, file_data, memsz) in enumerate(specs):
        filesz = len(file_data)
        if index == count - 1 and truncate_last:
            filesz += truncate_last
        regions.append(file_data)
        program_headers += struct.pack(
            '<IIQQQQQQ',
            1,            # p_type = PT_LOAD
            4,            # p_flags = PF_R
            cursor,       # p_offset
            vaddr,        # p_vaddr
            vaddr,        # p_paddr
            filesz,       # p_filesz
            memsz,        # p_memsz
            8)            # p_align
        cursor += len(file_data)
    ehdr = struct.pack(
        '<16sHHIQQQIHHHHHH',
        b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8,
        4,             # e_type = ET_CORE
        62,            # e_machine = EM_X86_64
        1,             # e_version
        0,             # e_entry
        phoff,         # e_phoff
        0,             # e_shoff (no section headers)
        0,             # e_flags
        ELF_HEADER_SIZE,
        PROGRAM_HEADER_SIZE,
        count,
        0, 0, 0)
    return ehdr + program_headers + b''.join(regions)


def open_elf(core):
    return ELFFile(BytesIO(core))


def kinds(result):
    return [span.kind for span in result.spans]


class TestSparseAddressSpace(unittest.TestCase):
    def test_cross_segment_read_with_unmapped_gap(self):
        core = build_core([
            (0x1000, b"AAAA", 4),
            (0x2000, b"BBBB", 4),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            result = space.read(0x1000, 0x1004)
            self.assertEqual(kinds(result), [
                SpanKind.KNOWN, SpanKind.MISSING, SpanKind.KNOWN])
            self.assertEqual(result.data,
                             b"AAAA" + bytes(0xffc) + b"BBBB")
            self.assertEqual(result.missing_ranges(),
                             ((0x1004, 0x2000),))
            self.assertFalse(result.is_complete)
            self.assertEqual(result.spans[0].sources[0].file_offset,
                             space.segments[0].file_offset)
            self.assertEqual(result.spans[2].sources[0].file_offset,
                             space.segments[1].file_offset)

    def test_zero_fill_is_distinct_from_missing(self):
        core = build_core([
            (0x3000, b"CC", 0x10),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            inside = space.read(0x3000, 0x10)
            beyond = space.read(0x3000, 0x20)
            zero_span = inside.spans[1]
        self.assertEqual(kinds(inside),
                         [SpanKind.KNOWN, SpanKind.ZERO_FILL])
        self.assertTrue(inside.is_complete)
        self.assertFalse(zero_span.file_backed)
        self.assertEqual(zero_span.value, bytes(14))
        self.assertEqual(
            kinds(beyond),
            [SpanKind.KNOWN, SpanKind.ZERO_FILL, SpanKind.MISSING])
        self.assertEqual(beyond.missing_ranges(), ((0x3010, 0x3020),))

    def test_partial_page_truncated_file_image(self):
        core = build_core([
            (0x4000, b"DDDD", 0x10),
        ], truncate_last=4)
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            result = space.read(0x4000, 0x10)
            self.assertEqual(kinds(result),
                             [SpanKind.KNOWN, SpanKind.MISSING,
                              SpanKind.ZERO_FILL])
            self.assertEqual(result.spans[0].value, b"DDDD")
            self.assertEqual(result.missing_ranges(),
                             ((0x4004, 0x4008),))
            self.assertFalse(result.is_complete)
    def test_identical_overlap_is_known_with_both_provenances(self):
        core = build_core([
            (0x5000, b"SAME-DATA", 0x10),
            (0x5004, b"-DATA", 0x0c),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            result = space.read(0x5000, 0x10)
            overlap = space.read(0x5004, 5)
            covering = space.provenance(0x5006)
        self.assertNotIn(SpanKind.CONFLICT, kinds(result))
        self.assertEqual(kinds(overlap), [SpanKind.KNOWN])
        self.assertEqual(overlap.data, b"-DATA")
        self.assertEqual(len(covering), 2)
        self.assertEqual({seg.segment_index for seg in covering}, {0, 1})
        offsets = {seg.segment_index: seg.file_offset for seg in covering}
        self.assertEqual(offsets[1] - offsets[0], len(b"SAME-DATA"))

    def test_conflicting_overlap_is_not_silently_resolved(self):
        core = build_core([
            (0x6000, b"ABCDEFGH", 0x10),
            (0x6004, b"XYZW", 0x08),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            result = space.read(0x6000, 0x10)
            clean = space.read(0x6000, 4)
        self.assertTrue(result.has_conflict)
        self.assertEqual(result.conflict_ranges(), ((0x6004, 0x6008),))
        conflict = next(span for span in result.spans
                        if span.kind is SpanKind.CONFLICT)
        self.assertEqual(set(conflict.alternatives), {b"EFGH", b"XYZW"})
        self.assertEqual(len(conflict.sources), 2)
        self.assertEqual(kinds(clean), [SpanKind.KNOWN])
        self.assertEqual(clean.data, b"ABCD")

    def test_segment_provenance_reports_original_file_offsets(self):
        core = build_core([
            (0x7000, b"1234", 0x8),
            (0x8000, b"5678", 0x8),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            first = space.read(0x7000, 4)
            second = space.read(0x8000, 4)
            segments = space.segments
            no_mapping = space.provenance(0x9000)
        self.assertEqual(first.spans[0].sources[0].file_offset,
                         segments[0].file_offset)
        self.assertEqual(second.spans[0].sources[0].file_offset,
                         segments[1].file_offset)
        self.assertTrue(segments[0].file_backed)
        self.assertEqual(segments[0].vaddr, 0x7000)
        self.assertEqual(segments[0].memsz, 0x8)
        self.assertEqual(no_mapping, ())

    def test_read_outside_any_segment_is_missing_not_zero(self):
        core = build_core([(0x9000, b"Q", 0x2)])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            result = space.read(0x100, 8)
        self.assertEqual(kinds(result), [SpanKind.MISSING])
        self.assertEqual(result.data, bytes(8))
        self.assertEqual(result.missing_ranges(), ((0x100, 0x108),))
        self.assertFalse(result.is_complete)

    def test_zero_size_read_is_empty(self):
        core = build_core([(0xa000, b"", 0x10)])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            result = space.read(0xa000, 0)
        self.assertEqual(result.spans, ())
        self.assertEqual(result.data, b"")
        self.assertTrue(result.is_complete)
    def chain_core(self):
        nodes = {
            0x1000: 0x1010,
            0x1010: 0x1020,
            0x1020: 0x0000,
        }
        image = bytearray(0x30)
        for address, value in nodes.items():
            offset = address - 0x1000
            image[offset:offset + 8] = value.to_bytes(8, "little")
        return build_core([(0x1000, bytes(image), 0x30)])

    def test_pointer_chain_null_termination(self):
        with open_elf(self.chain_core()) as elffile:
            space = elffile.sparse_address_space()
            chain = pointer_chain.walk_pointer_chain(space, 0x1000)
        self.assertEqual(chain.stop_reason, "null")
        self.assertEqual([node.value for node in chain.nodes],
                         [0x1010, 0x1020, 0])
        self.assertEqual([node.status for node in chain.nodes],
                         ["known", "known", "null"])

    def test_pointer_chain_unknown_pointer_keeps_prefix(self):
        with open_elf(self.chain_core()) as elffile:
            space = elffile.sparse_address_space()
            prefix = pointer_chain.walk_pointer_chain(space, 0x1000)
            unknown = pointer_chain.walk_pointer_chain(space, 0x1030)
        self.assertEqual(prefix.stop_reason, "null")
        self.assertEqual(unknown.stop_reason, "unknown")
        self.assertEqual(len(unknown.nodes), 1)
        self.assertIsNone(unknown.nodes[0].value)
        self.assertIn("missing", unknown.nodes[0].status)

    def test_pointer_chain_does_not_fabricate_empty_list(self):
        zero_fill_core = build_core([(0x1000, b"", 0x20)])
        with open_elf(zero_fill_core) as elffile:
            space = elffile.sparse_address_space()
            naive = space.read(0x1000, 8)
            zero_chain = pointer_chain.walk_pointer_chain(
                space, 0x1000)
            unmapped = pointer_chain.walk_pointer_chain(
                space, 0x4000)
        self.assertEqual(kinds(naive), [SpanKind.ZERO_FILL])
        self.assertEqual(naive.data, bytes(8))
        self.assertEqual(zero_chain.stop_reason, "null")
        self.assertEqual(unmapped.stop_reason, "unknown")
        self.assertIsNone(unmapped.nodes[0].value)

    def test_pointer_chain_cycle(self):
        first = 0x1010.to_bytes(8, "little")
        second = 0x1000.to_bytes(8, "little")
        core = build_core([
            (0x1000, first, 8),
            (0x1010, second, 8),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            chain = pointer_chain.walk_pointer_chain(space, 0x1000)
        self.assertEqual(chain.stop_reason, "cycle")
        self.assertEqual([node.address for node in chain.nodes],
                         [0x1000, 0x1010])

    def test_pointer_chain_hop_and_byte_bounds(self):
        image = b"".join((0x1008).to_bytes(8, "little")
                          for _ in range(4))
        core = build_core([(0x1000, image, 0x20)])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            limited = pointer_chain.walk_pointer_chain(
                space, 0x1000, max_hops=2)
            byte_limited = pointer_chain.walk_pointer_chain(
                space, 0x1000, max_hops=8, max_bytes=16)
        self.assertEqual(limited.stop_reason, "hop_limit")
        self.assertEqual(len(limited.nodes), 2)
        self.assertEqual(byte_limited.stop_reason, "byte_limit")
        self.assertEqual(len(byte_limited.nodes), 2)

    def test_pointer_chain_conflict_stops_with_prefix(self):
        first = 0x5008.to_bytes(8, "little")
        core = build_core([
            (0x5000, first + b"EFGH", 0x10),
            (0x5008, b"XYZW", 0x0c),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            chain = pointer_chain.walk_pointer_chain(space, 0x5000)
        self.assertEqual(chain.stop_reason, "conflict")
        self.assertEqual(len(chain.nodes), 2)
        self.assertEqual(chain.nodes[0].value, 0x5008)
        self.assertIsNone(chain.nodes[1].value)
        self.assertEqual(chain.nodes[1].status, "conflict")

    def test_pointer_chain_truncated_pointer(self):
        core = build_core([(0x1000, b"\x10\x10", 0x10)],
                          truncate_last=6)
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            chain = pointer_chain.walk_pointer_chain(space, 0x1000)
        self.assertEqual(chain.stop_reason, "unknown")
        self.assertEqual(len(chain.nodes), 1)
        self.assertIsNone(chain.nodes[0].value)
    def test_pointer_chain_crosses_segment_boundary(self):
        first = 0x2010.to_bytes(8, "little")
        second = (0).to_bytes(8, "little")
        core = build_core([
            (0x2000, first, 0x10),
            (0x2010, second, 0x10),
        ])
        with open_elf(core) as elffile:
            space = elffile.sparse_address_space()
            chain = pointer_chain.walk_pointer_chain(space, 0x2000)
        self.assertEqual(chain.stop_reason, "null")
        self.assertEqual([node.value for node in chain.nodes],
                         [0x2010, 0])

    def serialize_evidence(self, space):
        records = []
        for segment in space.segments:
            records.append((
                segment.segment_index, segment.vaddr, segment.memsz,
                segment.file_offset, segment.file_backed))
        for address in (0x1000, 0x1010, 0x1020, 0x1028, 0x4000):
            result = space.read(address, 8)
            records.append((
                address,
                [(span.kind.value, span.start, span.end,
                  span.value.hex(),
                  tuple(alt.hex() for alt in span.alternatives))
                 for span in result.spans]))
        return records

    def test_independent_replay_reaches_same_conclusion(self):
        core = self.chain_core()
        with open_elf(core) as first_elf:
            first_space = first_elf.sparse_address_space()
            first_chain = pointer_chain.walk_pointer_chain(
                first_space, 0x1000)
            first_records = self.serialize_evidence(first_space)
        with open_elf(core) as second_elf:
            second_space = second_elf.sparse_address_space()
            second_chain = pointer_chain.walk_pointer_chain(
                second_space, 0x1000)
            second_records = self.serialize_evidence(second_space)
            replay_unknown = pointer_chain.walk_pointer_chain(
                second_space, 0x4000)
        self.assertEqual(first_records, second_records)
        self.assertEqual(first_chain, second_chain)
        self.assertEqual(replay_unknown.stop_reason, "unknown")

    def test_filesz_larger_than_memsz_is_rejected(self):
        from elftools.common.exceptions import ELFError
        with self.assertRaises(ELFError):
            SparseAddressSpace(BytesIO(b""),
                               [(0x1000, 0x8, 0x10, 0)])


if __name__ == "__main__":
    unittest.main()
