#-------------------------------------------------------------------------------
# elftools: elf/sparse.py
#
# Sparse virtual address space for offline forensic analysis of core dumps.
#
# A core dump only captures the pages that were resident when it was written.
# The bytes not present in the file fall into two very different categories:
#   - zero fill: bytes past p_filesz but inside p_memsz, which the loader
#     guarantees to be zero;
#   - missing: bytes the dump did not capture, whose value is unknown.
# Treating the latter as zero, as a plain byte view of the file would, lets a
# wild pointer be "explained" as a valid pointer to an empty list. The classes
# in this module keep the two categories apart, retain the original file
# offset of every known byte, and refuse to silently pick a winner when
# overlapping PT_LOAD segments disagree.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field
from enum import Enum
from typing import IO, TYPE_CHECKING

from ..common.exceptions import ELFError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .elffile import ELFFile


class SpanKind(Enum):
    """ How the bytes of an address span were obtained.
    """

    #: Read from a PT_LOAD file image (content is evidence, not inference).
    KNOWN = 'known'
    #: Inside p_memsz but past p_filesz: loader-guaranteed zero fill.
    ZERO_FILL = 'zero_fill'
    #: The dump did not capture this range; its contents are unknown.
    MISSING = 'missing'
    #: Several segments map the range and their file images disagree.
    CONFLICT = 'conflict'


@dataclass(frozen=True, order=True)
class Provenance:
    """ Origin of a byte range, in both virtual and file coordinates.

        For file-backed bytes, file_backed is True and file_offset is the
        offset inside the original core file. For zero fill and for ranges
        the dump failed to capture, file_backed is False and file_offset is
        None.
    """

    segment_index: int
    vaddr: int
    memsz: int
    file_offset: int | None
    file_backed: bool


@dataclass(frozen=True)
class AddressSpan:
    """ A homogeneous run of addresses returned by a sparse read.

        value holds the bytes represented by the span:
          - KNOWN: the bytes read from the segment file image;
          - ZERO_FILL: an actual run of zero bytes;
          - MISSING: zero-length placeholder, the byte values are unknown;
          - CONFLICT: the bytes from the first conflicting segment; every
            alternative is listed in alternatives and must be resolved by the
            caller rather than guessed.
    """

    start: int
    end: int
    kind: SpanKind
    value: bytes = b''
    sources: tuple[Provenance, ...] = ()
    alternatives: tuple[bytes, ...] = ()
    #: True when value was read from a file image; False for zero fill,
    #: not-captured ranges and conflicts that must be resolved explicitly.
    file_backed: bool = False

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class SparseRead:
    """ Result of reading a virtual address range.

        data contains the known bytes of the range, with zero bytes in place
        of both zero fill and missing runs. The two must not be conflated:
        consult spans, is_complete and missing_ranges before trusting data.
    """

    start: int
    size: int
    data: bytes
    spans: tuple[AddressSpan, ...]

    @property
    def end(self) -> int:
        return self.start + self.size

    @property
    def is_complete(self) -> bool:
        """ True only when every byte is known or loader-guaranteed zero.
        """
        return all(span.kind in (SpanKind.KNOWN, SpanKind.ZERO_FILL)
                   for span in self.spans)

    @property
    def has_conflict(self) -> bool:
        return any(span.kind is SpanKind.CONFLICT for span in self.spans)

    def missing_ranges(self) -> tuple[tuple[int, int], ...]:
        """ Virtual address ranges [start, end) the dump did not capture.
        """
        return tuple((span.start, span.end) for span in self.spans
                     if span.kind is SpanKind.MISSING)

    def conflict_ranges(self) -> tuple[tuple[int, int], ...]:
        """ Virtual address ranges [start, end) with disagreeing overlaps.
        """
        return tuple((span.start, span.end) for span in self.spans
                     if span.kind is SpanKind.CONFLICT)


@dataclass(frozen=True)
class _Source:
    """ One PT_LOAD contribution to the address space (internal).
    """

    index: int
    vaddr: int
    filesz_end: int
    memsz_end: int
    file_offset: int
    #: Largest file offset actually available in the dump for this segment.
    captured_end: int
    provenance: Provenance


@dataclass
class _Atom:
    """ A maximal range on which the set of covering sources is constant.
    """

    start: int
    end: int
    sources: list[_Source] = field(default_factory=list)


class SparseAddressSpace:
    """ Sparse view of the virtual memory described by PT_LOAD segments.

        The space is built from the p_vaddr/p_filesz/p_memsz/p_offset fields
        of PT_LOAD segments and reads bytes lazily from the underlying core
        file stream. Addresses outside every segment and bytes the dump did
        not capture are reported as MISSING rather than read as zero.

        Instances are normally created with SparseAddressSpace.from_elf();
        the raw constructor accepts explicit segment descriptors, which is
        useful for tests and for replaying evidence without an ELF file.
    """

    def __init__(
        self,
        stream: IO[bytes],
        segments: list[tuple[int, int, int, int]],
        file_size: int | None = None,
    ) -> None:
        """ Build a space from (vaddr, memsz, filesz, offset) descriptors.

            The descriptors mirror the PT_LOAD header fields in program
            header order. file_size, when given, marks the end of the data
            actually present in the stream; file image bytes past it are
            treated as not captured. When omitted, the stream is measured by
            seeking to its end.
        """
        self.stream = stream
        self._sources: list[_Source] = []
        for index, (vaddr, memsz, filesz, offset) in enumerate(segments):
            if vaddr < 0 or memsz < 0 or filesz < 0 or offset < 0:
                raise ELFError(
                    f'PT_LOAD segment #{index} has negative header fields')
            if filesz > memsz:
                raise ELFError(
                    f'PT_LOAD segment #{index} has p_filesz ({filesz}) '
                    f'larger than p_memsz ({memsz})')
            if memsz == 0:
                continue
            if file_size is None:
                stream.seek(0, 2)
                file_size = stream.tell()
            file_end = offset + filesz
            captured_end = min(file_end, max(offset, file_size))
            self._sources.append(_Source(
                index=index,
                vaddr=vaddr,
                filesz_end=vaddr + filesz,
                memsz_end=vaddr + memsz,
                file_offset=offset,
                captured_end=captured_end,
                provenance=Provenance(
                    segment_index=index,
                    vaddr=vaddr,
                    memsz=memsz,
                    file_offset=offset,
                    file_backed=filesz > 0)))
        self._atoms: list[_Atom] = self._build_atoms()

    @classmethod
    def from_elf(cls, elffile: ELFFile) -> SparseAddressSpace:
        """ Build the sparse address space of an ELFFile from PT_LOADs.

            Works on core dumps and on any other ELF file; only the program
            headers and the file stream are used, never host process memory.
        """
        descriptors = [
            (segment['p_vaddr'], segment['p_memsz'],
             segment['p_filesz'], segment['p_offset'])
            for segment in elffile.iter_segments(type='PT_LOAD')
        ]
        return cls(elffile.stream, descriptors, file_size=elffile.stream_len)

    @property
    def segments(self) -> tuple[Provenance, ...]:
        """ Provenance of every PT_LOAD segment, in program header order.
        """
        return tuple(source.provenance for source in self._sources)

    def min_vaddr(self) -> int | None:
        """ Lowest address mapped by a PT_LOAD segment, if any.
        """
        return self._atoms[0].start if self._atoms else None

    def max_vaddr(self) -> int | None:
        """ One past the highest mapped address, if any.
        """
        return self._atoms[-1].end if self._atoms else None

    def read(self, vaddr: int, size: int) -> SparseRead:
        """ Read [vaddr, vaddr + size), classifying every run of addresses.
        """
        if vaddr < 0 or size < 0:
            raise ELFError(
                f'Invalid read request: vaddr={vaddr}, size={size}')
        spans: list[AddressSpan] = []
        data = bytearray(size)
        if size == 0:
            return SparseRead(vaddr, 0, b'', ())
        end = vaddr + size
        atom_index = self._find_atom(vaddr)
        cursor = vaddr
        while cursor < end:
            if atom_index >= len(self._atoms):
                spans.append(self._make_missing_span(cursor, end))
                break
            atom = self._atoms[atom_index]
            if not (atom.start <= cursor < atom.end):
                gap_end = min(atom.start, end) if atom.start > cursor else end
                spans.append(self._make_missing_span(cursor, gap_end))
                cursor = gap_end
                if atom.start > cursor:
                    atom_index += 1
                continue
            part_end = min(atom.end, end)
            span = self._classify(atom, cursor, part_end, data, vaddr)
            spans.append(span)
            cursor = part_end
            atom_index += 1
        return SparseRead(vaddr, size, bytes(data), tuple(spans))

    def iter_spans(self, vaddr: int, size: int) -> Iterator[AddressSpan]:
        """ Yield the classified spans covering [vaddr, vaddr + size).
        """
        return iter(self.read(vaddr, size).spans)

    def provenance(self, vaddr: int) -> tuple[Provenance, ...]:
        """ Segment provenance for one address, empty if no segment maps it.
        """
        atom_index = self._find_atom(vaddr)
        if atom_index >= len(self._atoms):
            return ()
        atom = self._atoms[atom_index]
        if not (atom.start <= vaddr < atom.end):
            return ()
        return tuple(source.provenance for source in atom.sources)

    def _build_atoms(self) -> list[_Atom]:
        boundaries = {source.vaddr for source in self._sources}
        for source in self._sources:
            boundaries.add(source.filesz_end)
            boundaries.add(source.memsz_end)
            # A truncated file image ends here: past this virtual address the
            # segment's file bytes were not captured even though p_filesz
            # claims them.
            if source.captured_end > source.file_offset:
                boundaries.add(
                    source.vaddr + source.captured_end - source.file_offset)
        cuts = sorted(boundaries)
        atoms: list[_Atom] = []
        for start, end in zip(cuts, cuts[1:]):
            if start == end:
                continue
            covering = [source for source in self._sources
                        if source.vaddr <= start and end <= source.memsz_end]
            if covering:
                atoms.append(_Atom(start, end, covering))
        return atoms

    def _find_atom(self, vaddr: int) -> int:
        starts = [atom.start for atom in self._atoms]
        index = bisect_left(starts, vaddr)
        if index < len(starts) and starts[index] == vaddr:
            return index
        return max(0, index - 1)

    def _classify(
        self,
        atom: _Atom,
        start: int,
        end: int,
        data: bytearray,
        read_start: int,
    ) -> AddressSpan:
        images: list[tuple[_Source, bytes]] = []
        zero_sources: list[_Source] = []
        missing_sources: list[_Source] = []
        for source in atom.sources:
            kind = self._source_kind(source, start)
            if kind == 'file':
                images.append((source, self._read_source(source, start, end)))
            elif kind == 'zero':
                zero_sources.append(source)
            else:
                missing_sources.append(source)

        sources = tuple(source.provenance for source in atom.sources)
        if images:
            first_value = images[0][1]
            disagree = [value for _, value in images[1:] if value != first_value]
            if disagree:
                return AddressSpan(
                    start, end, SpanKind.CONFLICT,
                    value=first_value,
                    sources=sources,
                    alternatives=tuple(
                        [first_value, *disagree]))
            data[start - read_start:end - read_start] = first_value
            return AddressSpan(start, end, SpanKind.KNOWN,
                               value=first_value, sources=sources,
                               file_backed=True)
        if zero_sources and not missing_sources:
            size = end - start
            value = bytes(size)
            data[start - read_start:end - read_start] = value
            return AddressSpan(start, end, SpanKind.ZERO_FILL,
                               value=value, sources=sources)
        return AddressSpan(start, end, SpanKind.MISSING, sources=sources)

    @staticmethod
    def _source_kind(source: _Source, vaddr: int) -> str:
        if vaddr < source.filesz_end:
            file_pos = source.file_offset + (vaddr - source.vaddr)
            if file_pos < source.captured_end:
                return 'file'
            return 'missing'
        return 'zero'

    def _read_source(
        self, source: _Source, start: int, end: int
    ) -> bytes:
        offset = source.file_offset + (start - source.vaddr)
        size = end - start
        self.stream.seek(offset)
        value = self.stream.read(size)
        if len(value) != size:
            raise ELFError(
                f'Short read of segment #{source.index} at file offset '
                f'{offset}: wanted {size} bytes, got {len(value)}')
        return value

    @staticmethod
    def _make_missing_span(start: int, end: int) -> AddressSpan:
        return AddressSpan(start, end, SpanKind.MISSING)
