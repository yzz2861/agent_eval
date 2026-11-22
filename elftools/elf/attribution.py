#-------------------------------------------------------------------------------
# elftools: elf/attribution.py
#
# Read-only attribution of an address range to the symbols and sections that
# cover it. A symbol table alone is not enough to decide which name a reviewer
# may cite for an address: local symbols, weak aliases and zero-length entries
# can share an address, and a declared section range is only trustworthy where
# the file actually carries bytes. This module cross-checks symbol visibility,
# section declarations and the real file coverage, never mutating the parsed
# ELF and never stretching an entry beyond what its header proves.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from ..common.utils import preserve_stream_pos
from .constants import SH_FLAGS, SHN_INDICES

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from .elffile import ELFFile
    from .sections import Symbol, SymbolTableSection


class Coverage(str, Enum):
    """ How convincingly an address is backed by the file on disk.
    """

    #: An allocated, non-NOBITS section declares the address and its bytes are
    #: present inside the file.
    FILE_BACKED = "file-backed"
    #: An allocated SHT_NOBITS section (e.g. .bss) owns the address, but the
    #: bytes exist only at run time, so nothing can be read back.
    NOBITS = "nobits"
    #: The address belongs to a section without SHF_ALLOC (debug/metadata), so
    #: it is not part of the loadable memory image.
    NOT_ALLOCATED = "not-allocated"
    #: No section header declares the address.
    UNCOVERED = "uncovered"


@dataclass(frozen=True, slots=True)
class SymbolAttribution:
    """ A single symbol entry that can be cited for the queried range.

        Entries are reported per source table, so a global and its weak alias,
        or the same name exported by both .symtab and .dynsym, all appear as
        separate attributions instead of being deduplicated away.
    """

    name: str
    """ Symbol name as stored in the linked string table. """

    value: int
    """ st_value: the first (or sole) address of the symbol. """

    size: int
    """ st_size; zero marks a point symbol with no declared extent. """

    point: bool
    """ True for zero-length symbols, which only own their exact address. """

    bind: str
    """ st_info bind, e.g. STB_LOCAL / STB_GLOBAL / STB_WEAK. """

    symbol_type: str
    """ st_info type, e.g. STT_FUNC / STT_OBJECT / STT_NOTYPE. """

    visibility: str
    """ st_other visibility, e.g. STV_DEFAULT / STV_HIDDEN. """

    section_index: int
    """ st_shndx; may be a reserved value such as SHN_ABS or SHN_COMMON. """

    section_name: str | None
    """ Name of the referenced section, or None for a reserved/absent index. """

    source: str
    """ Name of the symbol table section this entry came from. """

    symbol_index: int
    """ Index of the entry inside its source symbol table. """

    overlap: tuple[int, int]
    """ Intersection with the queried range, half-open. It is (v, v) for a
        point symbol that lands inside the range. """

    coverage: Coverage
    """ Section/file backing of the symbol's own starting address. """

    unnamed: bool
    """ True when the string table holds an empty name for the entry. """


@dataclass(frozen=True, slots=True)
class SectionAttribution:
    """ A section header whose declared range overlaps the queried range. """

    name: str
    """ Section name (the empty string for the null section). """

    section_index: int
    """ Index of the section in the section header table. """

    address: int
    """ sh_addr of the section. """

    declared_size: int
    """ sh_size: the extent the section claims to occupy. """

    overlap: tuple[int, int]
    """ Intersection of the declared section range with the queried range. """

    allocated: bool
    """ True when SHF_ALLOC is set, i.e. the section occupies address space. """

    nobits: bool
    """ True for SHT_NOBITS sections, which have no bytes in the file. """

    file_backed: bool
    """ True when at least part of the overlap has real bytes in the file. """

    file_overlap: tuple[int, int] | None
    """ Sub-range of the overlap backed by real file bytes, when present. """


@dataclass(frozen=True, slots=True)
class UndeterminedBoundary:
    """ An address or sub-range whose owner cannot be proven from the file.

        ``point`` marks a zero-width boundary (a single address). Point
        boundaries are used for zero-length symbols, which may mark an address
        but must never be expanded into the following byte range.
    """

    start: int
    end: int
    reason: str
    point: bool = False


@dataclass(frozen=True, slots=True)
class AttributionResult:
    """ The reviewable answer for one half-open queried address range.

        ``query_range`` is the requested interval [start, end). ``symbols``
        lists every symbol touching the range, keeping each source of equal
        symbols. ``sections`` lists the declaring sections and their file
        backing. ``undetermined`` lists what the file cannot attribute and
        why. ``coverage`` summarises the section backing across the range.
    """

    query_range: tuple[int, int]
    symbols: tuple[SymbolAttribution, ...]
    sections: tuple[SectionAttribution, ...]
    undetermined: tuple[UndeterminedBoundary, ...]
    coverage: tuple[Coverage, ...]

    @property
    def fully_attributed(self) -> bool:
        """ True when no part of the range lacks a firm attribution. """
        return not self.undetermined


# Machine-stable reason strings, so callers can branch without parsing text.
REASON_ZERO_LENGTH = "zero-length symbol marks an address but has no extent"
REASON_NO_SYMBOL = "no symbol entry claims this range"
REASON_UNBACKED = "declared range is not backed by bytes in the file"
REASON_OUTSIDE_SECTIONS = "range falls outside every declared section"
@dataclass(frozen=True, slots=True)
class _SectionInfo:
    index: int
    name: str
    start: int
    end: int
    allocated: bool
    nobits: bool
    file_backed_end: int


@dataclass(frozen=True, slots=True)
class _SymbolRecord:
    value: int
    size: int
    point: bool
    name: str
    bind: str
    symbol_type: str
    visibility: str
    shndx: int
    source: str
    index: int


@dataclass(slots=True)
class _CoverageMap:
    sections: tuple[_SectionInfo, ...]

    def covering(self, address: int) -> tuple[_SectionInfo, ...]:
        return tuple(
            section
            for section in self.sections
            if section.start <= address < section.end
        )

    def classify(self, address: int) -> Coverage:
        covering = self.covering(address)
        if not covering:
            return Coverage.UNCOVERED
        if any(section.allocated for section in covering):
            if any(not section.nobits for section in covering):
                return Coverage.FILE_BACKED
            return Coverage.NOBITS
        return Coverage.NOT_ALLOCATED

    def section(self, index: int) -> _SectionInfo | None:
        for section in self.sections:
            if section.index == index:
                return section
        return None


def attribute_address_range(
    elffile: ELFFile,
    start: int,
    size: int,
    *,
    include_dynsym: bool = True,
) -> AttributionResult:
    """ Attribute the half-open range [start, start + size) of ``elffile``.

        The query is strictly read-only: it only reads existing symbol and
        section headers and never writes to or re-parses the stream. It
        combines three independent pieces of evidence:

        * symbol binding, type and visibility, keeping local symbols, weak
          aliases and zero-length names as distinct entries;
        * the section header declaring each symbol (allocated, NOBITS or
          metadata);
        * the bytes actually present in the file (SHT_NOBITS and unallocated
          sections cannot be read back).

        Every symbol touching the range is returned with the precise
        intersection that can be attributed to it. Bytes no symbol can claim,
        and zero-length symbols that only mark a point, are returned as
        UndeterminedBoundary entries instead of being guessed. Set
        ``include_dynsym`` to False to ignore .dynsym.
    """
    if start < 0:
        raise ValueError(f"start must be non-negative, got {start}")
    if size < 0:
        raise ValueError(f"size must be non-negative, got {size}")
    end = start + size

    # The query is read-only; keep the shared stream where the caller left it
    # so reviewing an address never disturbs subsequent parsing.
    with preserve_stream_pos(elffile.stream):
        coverage_map = _build_coverage_map(elffile)
        records = _collect_symbol_records(elffile, include_dynsym)

        symbols = tuple(
            _collect_attributions(start, end, records, coverage_map))
        sections = tuple(_collect_sections(start, end, coverage_map))
        undetermined = tuple(
            _collect_undetermined(start, end, records, symbols, coverage_map))
        coverage = tuple(_range_coverage(start, end, coverage_map))

    return AttributionResult(
        query_range=(start, end),
        symbols=symbols,
        sections=sections,
        undetermined=undetermined,
        coverage=coverage,
    )


def _build_coverage_map(elffile: ELFFile) -> _CoverageMap:
    sections: list[_SectionInfo] = []
    file_size = elffile.stream_len
    for index, section in enumerate(elffile.iter_sections()):
        address = int(section["sh_addr"])
        declared_size = int(section["sh_size"])
        if address == 0 or declared_size == 0:
            # Sections without an allocated address do not claim virtual bytes.
            continue
        flags = int(section["sh_flags"])
        nobits = str(section["sh_type"]) == "SHT_NOBITS"
        offset = int(section["sh_offset"])
        # Highest virtual address whose byte is physically present. NOBITS
        # sections and ranges truncated by the file size are caught here.
        if nobits:
            file_backed_end = address
        else:
            available = max(0, file_size - offset)
            file_backed_end = address + min(declared_size, available)
        sections.append(
            _SectionInfo(
                index=index,
                name=section.name,
                start=address,
                end=address + declared_size,
                allocated=bool(flags & SH_FLAGS.SHF_ALLOC),
                nobits=nobits,
                file_backed_end=file_backed_end,
            )
        )
    return _CoverageMap(sections=tuple(sections))


def _collect_symbol_records(
    elffile: ELFFile,
    include_dynsym: bool,
) -> list[_SymbolRecord]:
    records: list[_SymbolRecord] = []
    for table in _symbol_tables(elffile, include_dynsym):
        for index, symbol in enumerate(table.iter_symbols()):
            record = _record_from_symbol(symbol, table.name, index)
            if record is not None:
                records.append(record)
    return records


def _symbol_tables(
    elffile: ELFFile,
    include_dynsym: bool,
) -> Iterator[SymbolTableSection]:
    for section in elffile.iter_sections(type="SHT_SYMTAB"):
        yield section
    if include_dynsym:
        for section in elffile.iter_sections(type="SHT_DYNSYM"):
            yield section


def _record_from_symbol(
    symbol: Symbol,
    source: str,
    index: int,
) -> _SymbolRecord | None:
    value = int(symbol["st_value"])
    if value == 0:
        # The null symbol and undefined entries carry no attributable address.
        return None
    shndx = _symbol_shndx(symbol)
    if shndx == SHN_INDICES.SHN_UNDEF:
        return None
    size = int(symbol["st_size"])
    return _SymbolRecord(
        value=value,
        size=size,
        point=size == 0,
        name=symbol.name,
        bind=str(symbol["st_info"]["bind"]),
        symbol_type=str(symbol["st_info"]["type"]),
        visibility=str(symbol["st_other"]["visibility"]),
        shndx=shndx,
        source=source,
        index=index,
    )


_RESERVED_SHNDX_NAME_TO_VALUE = {
    "SHN_ABS": SHN_INDICES.SHN_ABS,
    "SHN_COMMON": SHN_INDICES.SHN_COMMON,
    "SHN_XINDEX": SHN_INDICES.SHN_XINDEX,
}


def _symbol_shndx(symbol: Symbol) -> int:
    # pyelftools renders known reserved indices as strings (e.g. "SHN_ABS"),
    # while ordinary section numbers stay integers.
    shndx = symbol["st_shndx"]
    if isinstance(shndx, str):
        named = _RESERVED_SHNDX_NAME_TO_VALUE.get(shndx)
        if named is not None:
            return named
        return SHN_INDICES.SHN_UNDEF
    return int(shndx)


def _collect_attributions(
    start: int,
    end: int,
    records: Sequence[_SymbolRecord],
    coverage_map: _CoverageMap,
) -> Iterator[SymbolAttribution]:
    for record in records:
        if record.point:
            # A zero-length entry only owns its exact address: include it
            # when the point is inside the range, but never expand it into
            # the following byte range or push it into the next segment.
            if not (start <= record.value < end):
                continue
            overlap = (record.value, record.value)
        else:
            overlap = _intersect((record.value, record.value + record.size),
                                 (start, end))
            if overlap is None:
                continue

        section = coverage_map.section(record.shndx)
        yield SymbolAttribution(
            name=record.name,
            value=record.value,
            size=record.size,
            point=record.point,
            bind=record.bind,
            symbol_type=record.symbol_type,
            visibility=record.visibility,
            section_index=record.shndx,
            section_name=section.name if section is not None else None,
            source=record.source,
            symbol_index=record.index,
            overlap=overlap,
            coverage=coverage_map.classify(record.value),
            unnamed=record.name == "",
        )


def _collect_sections(
    start: int,
    end: int,
    coverage_map: _CoverageMap,
) -> Iterator[SectionAttribution]:
    for section in coverage_map.sections:
        overlap = _intersect((section.start, section.end), (start, end))
        if overlap is None:
            continue
        file_overlap = _intersect((section.start, section.file_backed_end),
                                  overlap)
        yield SectionAttribution(
            name=section.name,
            section_index=section.index,
            address=section.start,
            declared_size=section.end - section.start,
            overlap=overlap,
            allocated=section.allocated,
            nobits=section.nobits,
            file_backed=file_overlap is not None,
            file_overlap=file_overlap,
        )


def _collect_undetermined(
    start: int,
    end: int,
    records: Sequence[_SymbolRecord],
    symbols: Sequence[SymbolAttribution],
    coverage_map: _CoverageMap,
) -> Iterator[UndeterminedBoundary]:
    # Bytes covered by symbols that have a real extent. Point symbols mark an
    # address but contribute no bytes, so they cannot fill a gap.
    covered = [
        symbol.overlap
        for symbol in symbols
        if not symbol.point
    ]
    # Allocated sections also make their bytes attributable, even without a
    # symbol: NOBITS bytes simply do not exist in the file, while PROGBITS
    # bytes are physically present.
    for section in coverage_map.sections:
        if not section.allocated:
            continue
        section_overlap = _intersect((section.start, section.end),
                                     (start, end))
        if section_overlap is not None:
            covered.append(section_overlap)

    for gap_start, gap_end in _gaps(start, end, covered):
        yield UndeterminedBoundary(
            start=gap_start,
            end=gap_end,
            reason=_gap_reason(gap_start, coverage_map),
        )

    # Zero-length entries are reported as point boundaries so reviewers know
    # the address is marked but the next byte is unattributed. The boundary is
    # a property of the address, so several entries (or tables) marking the
    # same point produce a single boundary, even though each symbol is still
    # reported separately above.
    seen_points: set[int] = set()
    for record in records:
        if record.point and start <= record.value < end:
            if record.value in seen_points:
                continue
            seen_points.add(record.value)
            yield UndeterminedBoundary(
                start=record.value,
                end=record.value,
                reason=REASON_ZERO_LENGTH,
                point=True,
            )

    # Flag declared bytes that the file does not actually carry (NOBITS or a
    # declaration running past EOF), independently of symbol coverage. A
    # matching (start, end, reason) is reported once even when two sections
    # happen to declare the same unbacked bytes.
    seen_unbacked: set[tuple[int, int]] = set()
    for section in coverage_map.sections:
        overlap = _intersect((section.start, section.end), (start, end))
        if overlap is None:
            continue
        unbacked = _intersect((section.file_backed_end, section.end), overlap)
        if unbacked is not None and unbacked not in seen_unbacked:
            seen_unbacked.add(unbacked)
            yield UndeterminedBoundary(
                start=unbacked[0],
                end=unbacked[1],
                reason=REASON_UNBACKED,
            )


def _gap_reason(address: int, coverage_map: _CoverageMap) -> str:
    coverage = coverage_map.classify(address)
    if coverage is Coverage.UNCOVERED:
        return REASON_OUTSIDE_SECTIONS
    return REASON_NO_SYMBOL


def _range_coverage(
    start: int,
    end: int,
    coverage_map: _CoverageMap,
) -> Sequence[Coverage]:
    if start == end:
        return ()
    seen: set[Coverage] = set()
    ordered: list[Coverage] = []
    for address in range(start, end):
        coverage = coverage_map.classify(address)
        if coverage not in seen:
            seen.add(coverage)
            ordered.append(coverage)
    return ordered


def _intersect(
    left: tuple[int, int],
    right: tuple[int, int],
) -> tuple[int, int] | None:
    lo = max(left[0], right[0])
    hi = min(left[1], right[1])
    return (lo, hi) if lo < hi else None


def _gaps(
    start: int,
    end: int,
    ranges: Sequence[tuple[int, int]],
) -> Iterator[tuple[int, int]]:
    if start == end:
        return
    cursor = start
    for range_start, range_end in sorted(ranges):
        range_start = max(range_start, start)
        range_end = min(range_end, end)
        if range_start > cursor:
            yield cursor, range_start
        if range_end > cursor:
            cursor = range_end
    if cursor < end:
        yield cursor, end
