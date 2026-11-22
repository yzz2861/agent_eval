#-------------------------------------------------------------------------------
# Tests for read-only address attribution (elftools.elf.attribution).
#
# The fixtures are synthetic: hand-built symbol entries and section headers,
# so the expected overlaps and undetermined boundaries can be asserted
# exactly without depending on a particular toolchain output.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import unittest
from io import BytesIO
from types import SimpleNamespace

from elftools.elf.attribution import (
    Coverage,
    REASON_UNBACKED,
    REASON_ZERO_LENGTH,
    attribute_address_range,
)
from elftools.elf.constants import SH_FLAGS, SHN_INDICES


class _Symbol:
    """ Mirror of elftools.elf.sections.Symbol for synthetic symbol data. """

    def __init__(self, value, size, name, *, bind="STB_GLOBAL",
                 symbol_type="STT_FUNC", visibility="STV_DEFAULT", shndx=1):
        self.name = name
        self._entry = SimpleNamespace(
            st_value=value,
            st_size=size,
            st_shndx=shndx,
            st_info={"bind": bind, "type": symbol_type},
            st_other={"visibility": visibility},
        )

    def __getitem__(self, key):
        return getattr(self._entry, key)


class _SymbolTable:
    def __init__(self, name, symbols):
        self.name = name
        self.kind = "SHT_DYNSYM" if name == ".dynsym" else "SHT_SYMTAB"
        self._symbols = symbols

    def iter_symbols(self):
        return iter(self._symbols)


class _NullSection:
    """ Section 0: no allocated address, so it claims no virtual bytes. """

    name = ""
    _header = SimpleNamespace(
        sh_addr=0, sh_size=0, sh_flags=0, sh_offset=0,
        sh_type="SHT_NULL",
    )

    def __getitem__(self, key):
        return getattr(self._header, key)


class _Section:
    def __init__(self, name, index, addr, size, *, allocated=True,
                 nobits=False, offset=None):
        self.name = name
        self._index = index
        self._header = SimpleNamespace(
            sh_addr=addr,
            sh_size=size,
            sh_flags=SH_FLAGS.SHF_ALLOC if allocated else 0,
            sh_offset=offset if offset is not None else addr,
            sh_type="SHT_NOBITS" if nobits else "SHT_PROGBITS",
        )

    def __getitem__(self, key):
        return getattr(self._header, key)


class _FakeELFFile:
    """ Minimal ELFFile surface consumed by the attribution module. """

    def __init__(self, sections, symbol_tables, stream_len=10**6):
        self._sections = sections
        self._symbol_tables = symbol_tables
        self.stream_len = stream_len
        self.stream = BytesIO(bytes(stream_len))

    def iter_sections(self, type=None):
        if type is None:
            return iter(self._sections)
        return iter(
            table for table in self._symbol_tables
            if table.kind == type
        )


class TestAttribution(unittest.TestCase):
    def _elf(self, symbols, sections=None, stream_len=10**6):
        if sections is None:
            # A null section at 0 and .text at 1 mirrors a real header table.
            sections = [_NullSection(), _Section(".text", 1, 0x1000, 0x100)]
        table = _SymbolTable(".symtab", symbols)
        return _FakeELFFile(sections, [table], stream_len=stream_len)

    def test_shared_address_two_sources_trace_same_range(self):
        # A global function and its weak alias share value and size. Both
        # must be reported, each pointing at the same attributable range.
        primary = _Symbol(0x1000, 0x10, "shared_fn", bind="STB_GLOBAL")
        alias = _Symbol(0x1000, 0x10, "shared_fn_alias", bind="STB_WEAK")
        elf = self._elf([primary, alias])

        result = attribute_address_range(elf, 0x1000, 0x10)
        self.assertEqual(len(result.symbols), 2)
        self.assertEqual(
            {(s.name, s.bind) for s in result.symbols},
            {("shared_fn", "STB_GLOBAL"),
             ("shared_fn_alias", "STB_WEAK")})
        self.assertEqual(
            {s.overlap for s in result.symbols},
            {(0x1000, 0x1010)})
        weak = next(s for s in result.symbols if s.name == "shared_fn_alias")
        self.assertFalse(weak.point)
        self.assertEqual(weak.coverage, Coverage.FILE_BACKED)
        self.assertEqual(weak.section_name, ".text")
        self.assertTrue(result.fully_attributed)

    def test_adjacent_zero_length_symbol_not_pushed_into_next_range(self):
        # A real function occupies [0x1010, 0x1020). A zero-length local
        # marker sits exactly at 0x1020, the start of the *next* segment.
        # Querying the function range must never attribute 0x1020 to it, and
        # the marker must stay a point rather than covering any bytes.
        func = _Symbol(0x1010, 0x10, "func_a", bind="STB_GLOBAL")
        marker = _Symbol(0x1020, 0, "$x", bind="STB_LOCAL",
                         symbol_type="STT_NOTYPE")
        elf = self._elf([func, marker])

        result = attribute_address_range(elf, 0x1010, 0x10)
        cited = {s.name: s for s in result.symbols}
        self.assertEqual(set(cited), {"func_a"})
        self.assertEqual(cited["func_a"].overlap, (0x1010, 0x1020))
        # The point at 0x1020 is outside the queried half-open range, so it
        # is neither cited nor turned into a boundary inside the range.
        point_boundaries = [b for b in result.undetermined if b.point]
        self.assertEqual(point_boundaries, [])
        self.assertTrue(result.fully_attributed)

    def test_zero_length_symbol_inside_range_is_a_point_boundary(self):
        # When the point itself is inside the query, it is cited as a point
        # symbol and separately flagged so nobody extends it to a byte.
        func = _Symbol(0x1000, 0x20, "func_b")
        marker = _Symbol(0x1010, 0, "$d", bind="STB_LOCAL",
                         symbol_type="STT_NOTYPE")
        elf = self._elf([func, marker])

        result = attribute_address_range(elf, 0x1000, 0x20)
        point = next(s for s in result.symbols if s.name == "$d")
        self.assertTrue(point.point)
        self.assertEqual(point.overlap, (0x1010, 0x1010))
        boundary = next(b for b in result.undetermined if b.point)
        self.assertEqual(boundary.start, 0x1010)
        self.assertEqual(boundary.end, 0x1010)
        self.assertEqual(boundary.reason, REASON_ZERO_LENGTH)
        # The surrounding function still covers every byte of the range.
        spans = [s.overlap for s in result.symbols if not s.point]
        self.assertIn((0x1000, 0x1020), spans)

    def test_unnamed_and_hidden_symbols_keep_their_properties(self):
        hidden = _Symbol(0x1000, 0x8, "", bind="STB_LOCAL",
                         visibility="STV_HIDDEN")
        public = _Symbol(0x1008, 0x8, "pub")
        elf = self._elf([hidden, public])

        result = attribute_address_range(elf, 0x1000, 0x10)
        unnamed = next(s for s in result.symbols if s.unnamed)
        self.assertEqual(unnamed.name, "")
        self.assertEqual(unnamed.visibility, "STV_HIDDEN")
        self.assertEqual(unnamed.bind, "STB_LOCAL")
        self.assertEqual(unnamed.overlap, (0x1000, 0x1008))
        self.assertTrue(all(not s.unnamed for s in result.symbols
                            if s.name == "pub"))

    def test_equal_symbol_from_two_tables_reports_each_source(self):
        sym = _Symbol(0x1000, 0x10, "exported")
        static_table = _SymbolTable(".symtab", [sym])
        dyn_table = _SymbolTable(".dynsym", [sym])
        sections = [_NullSection(), _Section(".text", 1, 0x1000, 0x100)]
        elf = _FakeELFFile(sections, [static_table, dyn_table])

        result = attribute_address_range(elf, 0x1000, 0x10)
        self.assertEqual(len(result.symbols), 2)
        self.assertEqual(
            sorted(s.source for s in result.symbols),
            [".dynsym", ".symtab"])
        self.assertTrue(all(s.name == "exported" for s in result.symbols))

        without_dyn = attribute_address_range(
            elf, 0x1000, 0x10, include_dynsym=False)
        self.assertEqual(len(without_dyn.symbols), 1)
        self.assertEqual(without_dyn.symbols[0].source, ".symtab")

    def test_nobits_section_is_not_file_backed(self):
        bss = _Section(".bss", 1, 0x2000, 0x40, nobits=True)
        sym = _Symbol(0x2000, 0x40, "counter", shndx=1)
        elf = self._elf([sym], sections=[_NullSection(), bss])

        result = attribute_address_range(elf, 0x2000, 0x40)
        self.assertEqual(result.coverage, (Coverage.NOBITS,))
        section = result.sections[0]
        self.assertTrue(section.nobits)
        self.assertFalse(section.file_backed)
        self.assertIsNone(section.file_overlap)
        unbacked = [b for b in result.undetermined
                    if b.reason == REASON_UNBACKED]
        self.assertTrue(unbacked)
        self.assertEqual((unbacked[0].start, unbacked[0].end),
                         (0x2000, 0x2040))

    def test_section_running_past_eof_is_partly_unbacked(self):
        # The section declares 0x100 bytes but the file ends after 0x80.
        text = _Section(".text", 1, 0x1000, 0x100, offset=0x1000)
        sym = _Symbol(0x1000, 0x100, "big_fn")
        elf = self._elf([sym], sections=[_NullSection(), text],
                        stream_len=0x1000 + 0x80)

        result = attribute_address_range(elf, 0x1000, 0x100)
        section = result.sections[0]
        self.assertTrue(section.file_backed)
        self.assertEqual(section.file_overlap, (0x1000, 0x1080))
        unbacked = next(b for b in result.undetermined
                        if b.reason == REASON_UNBACKED)
        self.assertEqual((unbacked.start, unbacked.end),
                         (0x1080, 0x1100))

    def test_unallocated_section_reports_not_allocated(self):
        debug = _Section(".debug_info", 1, 0x3000, 0x20,
                         allocated=False)
        sym = _Symbol(0x3000, 0x20, "dbg", shndx=1)
        elf = self._elf([sym], sections=[_NullSection(), debug])

        result = attribute_address_range(elf, 0x3000, 0x20)
        self.assertEqual(result.coverage, (Coverage.NOT_ALLOCATED,))
        self.assertFalse(result.sections[0].allocated)

    def test_uncovered_gap_is_reported_as_undetermined(self):
        # One symbol covers the first half; no section or symbol declares
        # the second half of the queried range.
        text = _Section(".text", 1, 0x1000, 0x10)
        sym = _Symbol(0x1000, 0x10, "half")
        elf = self._elf([sym], sections=[_NullSection(), text])

        result = attribute_address_range(elf, 0x1000, 0x20)
        gaps = [b for b in result.undetermined if not b.point]
        self.assertEqual(len(gaps), 1)
        self.assertEqual((gaps[0].start, gaps[0].end), (0x1010, 0x1020))
        self.assertFalse(result.fully_attributed)

    def test_reserved_shndx_kept_and_section_name_none(self):
        absolute = _Symbol(0x4000, 0x4, "kAbs", shndx=SHN_INDICES.SHN_ABS)
        elf = self._elf([absolute], sections=[])

        result = attribute_address_range(elf, 0x4000, 0x4)
        attribution = result.symbols[0]
        self.assertEqual(attribution.section_index, SHN_INDICES.SHN_ABS)
        self.assertIsNone(attribution.section_name)
        self.assertEqual(attribution.coverage, Coverage.UNCOVERED)

    def test_partial_overlap_returns_only_intersection(self):
        sym = _Symbol(0x1000, 0x20, "wide")
        elf = self._elf([sym])

        result = attribute_address_range(elf, 0x1010, 0x20)
        self.assertEqual(result.symbols[0].overlap, (0x1010, 0x1020))
        self.assertEqual(result.query_range, (0x1010, 0x1030))

    def test_query_preserves_stream_position(self):
        stream = BytesIO(bytes(0x2000))
        stream.seek(0x1234)
        elf = self._elf([_Symbol(0x1000, 0x10, "fn")])
        elf.stream = stream
        attribute_address_range(elf, 0x1000, 0x10)
        self.assertEqual(stream.tell(), 0x1234)

    def test_invalid_arguments_raise(self):
        elf = self._elf([])
        with self.assertRaises(ValueError):
            attribute_address_range(elf, 0x1000, -1)
        with self.assertRaises(ValueError):
            attribute_address_range(elf, -1, 4)

    def test_undefined_and_null_symbols_are_skipped(self):
        undefined = _Symbol(0, 0, "", shndx=SHN_INDICES.SHN_UNDEF)
        defined = _Symbol(0x1000, 0x8, "real")
        elf = self._elf([undefined, defined])

        result = attribute_address_range(elf, 0x1000, 0x8)
        self.assertEqual([s.name for s in result.symbols], ["real"])


    def test_repeated_point_markers_share_one_boundary(self):
        # Two zero-length entries at the same address (as happens across
        # tables) stay two symbols but yield a single point boundary.
        func = _Symbol(0x1000, 0x20, "fn")
        marker_a = _Symbol(0x1010, 0, "$a", bind="STB_LOCAL")
        marker_b = _Symbol(0x1010, 0, "$a2", bind="STB_LOCAL")
        elf = self._elf([func, marker_a, marker_b])

        result = attribute_address_range(elf, 0x1000, 0x20)
        points = [s for s in result.symbols if s.point]
        self.assertEqual({s.name for s in points}, {"$a", "$a2"})
        point_boundaries = [b for b in result.undetermined if b.point]
        self.assertEqual(len(point_boundaries), 1)
        self.assertEqual(point_boundaries[0].start, 0x1010)


if __name__ == '__main__':
    unittest.main()
