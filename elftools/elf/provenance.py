#-------------------------------------------------------------------------------
# elftools: elf/provenance.py
#
# Read-only address provenance for board/device address ranges.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
"""Resolve board addresses to bytes in an ELF image.

An ELF file describes the image loaded by a program loader, usually in terms
of virtual addresses.  A live device may expose the same storage through a
different "board" address, and that view can change with the hardware state.
This module lets a caller describe those views with :class:`StorageWindow`
objects and asks an :class:`ELFFile` to classify a board address range
without guessing:

* ``FILE_BYTES`` - the range is backed by bytes at a known file offset;
* ``ZERO_FILL`` - the range is the zero-filled tail of a PT_LOAD segment;
* ``UNATTESTED`` - a window attests that the address is mapped, but no
  PT_LOAD segment describes the mapped ELF address;
* ``UNMAPPED`` - no supplied window covers the board address.

If a window is conditional on hardware state and the caller does not supply a
state, every matching window is returned as a parallel source for the
affected span.  The result is deliberately split at both window and segment
boundaries so each source can be audited independently against its original
file offset.
"""
from __future__ import annotations

from collections.abc import Hashable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import IO, TYPE_CHECKING, Any, TypeAlias

from ..common.exceptions import ELFError

if TYPE_CHECKING:
    from .elffile import ELFFile


_UNSET = object()


class ProvenanceKind(StrEnum):
    """How a piece of an address range is backed."""

    FILE_BYTES = 'file_bytes'
    ZERO_FILL = 'zero_fill'
    UNATTESTED = 'unattested'
    UNMAPPED = 'unmapped'

    # Short aliases for callers that use the broader terms.
    FILE = 'file_bytes'
    ZERO = 'zero_fill'


class WindowMappingError(ELFError, ValueError):
    """The supplied windows overlap inconsistently in one hardware state."""


def _as_address(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f'{what} must be an int, got {type(value).__name__}')
    if value < 0:
        raise ValueError(f'{what} must be non-negative')
    return value


def _as_size(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f'{what} must be an int, got {type(value).__name__}')
    if value < 0:
        raise ValueError(f'{what} must be non-negative')
    return value


@dataclass(frozen=True, slots=True, init=False)
class StorageWindow:
    """A linear view of an ELF address range at a board address range.

    The window maps the half-open board interval
    ``[start, start + size)`` to the half-open ELF interval
    ``[elf_start, elf_start + size)``.  A window with ``state=None`` is
    unconditional.  A non-``None`` state identifies the hardware state in
    which the window is valid.

    ``end`` and ``target`` are accepted as keyword aliases for an exclusive
    end and ``elf_start``, respectively.  Use :meth:`from_mapping` for
    vendor tables represented as dictionaries.
    """

    start: int
    size: int
    elf_start: int
    state: Hashable | None
    name: str | None

    def __init__(
        self,
        start: int,
        size: int | None = None,
        elf_start: int | None = None,
        *,
        end: int | None = None,
        state: Hashable | None = None,
        condition: Hashable | None = None,
        name: str | None = None,
        target: int | None = None,
    ) -> None:
        start = _as_address(start, 'window start')

        if size is not None and end is not None:
            raise TypeError('pass either size or end, not both')
        if size is None:
            if end is None:
                raise TypeError('window size or end is required')
            end = _as_address(end, 'window end')
            if end <= start:
                raise ValueError('window end must be greater than start')
            size = end - start
        else:
            size = _as_size(size, 'window size')
            if size == 0:
                raise ValueError('window size must be greater than zero')

        if elf_start is not None and target is not None and elf_start != target:
            raise ValueError('elf_start and target disagree')
        if elf_start is None:
            elf_start = target
        if elf_start is None:
            raise TypeError('window elf_start (or target) is required')
        elf_start = _as_address(elf_start, 'window elf_start')

        if condition is not None:
            if state is not None and state != condition:
                raise ValueError('state and condition disagree')
            state = condition
        if state is not None:
            try:
                hash(state)
            except TypeError as exc:
                raise TypeError('window state must be hashable') from exc
        if name is not None and not isinstance(name, str):
            raise TypeError('window name must be a str')

        object.__setattr__(self, 'start', start)
        object.__setattr__(self, 'size', size)
        object.__setattr__(self, 'elf_start', elf_start)
        object.__setattr__(self, 'state', state)
        object.__setattr__(self, 'name', name)

    @property
    def end(self) -> int:
        """Exclusive end of the board-address interval."""
        return self.start + self.size

    @property
    def board_start(self) -> int:
        """Alias for :attr:`start`."""
        return self.start

    @property
    def board_end(self) -> int:
        """Alias for :attr:`end`."""
        return self.end

    @property
    def elf_end(self) -> int:
        """Exclusive end of the corresponding ELF-address interval."""
        return self.elf_start + self.size

    @property
    def condition(self) -> Hashable | None:
        """Alias for :attr:`state`."""
        return self.state

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> StorageWindow:
        """Create a window from a vendor-style dictionary.

        Accepted keys are:

        * board start: ``start``, ``board_start``, ``address`` or ``base``;
        * board size: ``size`` or ``length`` (alternatively ``end`` or
          ``board_end``);
        * ELF start: ``elf_start``, ``elf_address``, ``target``, ``vaddr``
          or ``p_vaddr``;
        * state: ``state``, ``condition`` or ``mode``;
        * label: ``name`` or ``label``.
        """

        start = _mapping_value(
            mapping, 'start', 'board_start', 'address', 'base')
        if start is _UNSET:
            raise TypeError('window mapping needs a start/board_start/address')

        size = _mapping_value(mapping, 'size', 'length')
        end = _mapping_value(mapping, 'end', 'board_end')
        if size is _UNSET and end is _UNSET:
            raise TypeError('window mapping needs size/length or end')
        if size is not _UNSET and end is not _UNSET:
            raise TypeError('window mapping must not specify both size and end')

        elf_start = _mapping_value(
            mapping, 'elf_start', 'elf_address', 'target', 'vaddr', 'p_vaddr')
        if elf_start is _UNSET:
            raise TypeError('window mapping needs an ELF start address')

        state = _mapping_value(mapping, 'state', 'condition', 'mode')
        name = _mapping_value(mapping, 'name', 'label')

        return cls(
            start,
            None if size is _UNSET else size,
            elf_start,
            end=None if end is _UNSET else end,
            state=None if state is _UNSET else state,
            name=None if name is _UNSET else name,
        )

    def __repr__(self) -> str:
        state = '' if self.state is None else f' state={self.state!r}'
        return (
            f'<StorageWindow board={self.start:#x}..{self.end:#x} '
            f'elf={self.elf_start:#x}{state}>'
        )


def _mapping_value(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return _UNSET


WindowEntry: TypeAlias = (
    StorageWindow | Mapping[str, Any] | Sequence[Any]
)
WindowInput: TypeAlias = (
    StorageWindow | Mapping[str, Any] | Iterable[WindowEntry] | None
)


def normalize_storage_windows(windows: WindowInput) -> tuple[StorageWindow, ...]:
    """Normalize a caller-supplied window table.

    A window table may be a single :class:`StorageWindow`, a mapping, or an
    iterable of either.  Sequence entries of length 3 or 4 are interpreted
    as ``(start, end, elf_start[, state])``; a mapping is the least
    ambiguous representation for persisted vendor tables.
    """

    if windows is None:
        return ()
    if isinstance(windows, StorageWindow):
        return (windows,)
    if isinstance(windows, Mapping):
        return (StorageWindow.from_mapping(windows),)
    if isinstance(windows, (str, bytes, bytearray)):
        raise TypeError('windows must be a window table, not a string')

    result: list[StorageWindow] = []
    for entry in windows:
        if isinstance(entry, StorageWindow):
            result.append(entry)
        elif isinstance(entry, Mapping):
            result.append(StorageWindow.from_mapping(entry))
        elif isinstance(entry, Sequence) and not isinstance(
                entry, (str, bytes, bytearray)):
            if len(entry) not in (3, 4):
                raise TypeError(
                    'window sequence entries must have 3 or 4 items')
            state = entry[3] if len(entry) == 4 else None
            result.append(StorageWindow(
                entry[0], None, entry[2], end=entry[1], state=state))
        else:
            raise TypeError(
                'window entries must be StorageWindow, mapping or sequence')
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ProvenanceSegment:
    """One candidate source for a contiguous board-address span."""

    board_address: int
    size: int
    kind: ProvenanceKind
    elf_address: int | None = None
    file_offset: int | None = None
    segment_index: int | None = None
    window_index: int | None = None
    window: StorageWindow | None = None
    state: Hashable | None = None

    @property
    def address(self) -> int:
        """Alias for :attr:`board_address`."""
        return self.board_address

    @property
    def start(self) -> int:
        """Inclusive start of the board-address span."""
        return self.board_address

    @property
    def end(self) -> int:
        """Exclusive end of the board-address span."""
        return self.board_address + self.size

    @property
    def length(self) -> int:
        """Alias for :attr:`size`."""
        return self.size

    @property
    def vaddr(self) -> int | None:
        """Alias for :attr:`elf_address`."""
        return self.elf_address

    @property
    def file_bytes(self) -> bool:
        """Whether this source is backed by actual bytes in the ELF file."""
        return self.kind is ProvenanceKind.FILE_BYTES

    @property
    def zero_fill(self) -> bool:
        """Whether this source is backed by a zero-fill ELF range."""
        return self.kind is ProvenanceKind.ZERO_FILL

    @property
    def attested(self) -> bool:
        """Whether an ELF PT_LOAD segment describes this source."""
        return self.kind in (
            ProvenanceKind.FILE_BYTES, ProvenanceKind.ZERO_FILL)

    def read_data(self, stream: IO[bytes]) -> bytes:
        """Read file-backed bytes, leaving the stream position unchanged.

        This is intentionally the only operation that touches the ELF data;
        source resolution itself never reads segment payloads.
        """

        if not self.file_bytes or self.file_offset is None:
            raise ELFError(
                f'cannot read {self.kind.value} provenance as file bytes')
        position = stream.tell()
        try:
            stream.seek(self.file_offset)
            data = stream.read(self.size)
        finally:
            stream.seek(position)
        if len(data) != self.size:
            raise ELFError(
                f'truncated ELF bytes at file offset {self.file_offset:#x}: '
                f'wanted {self.size}, got {len(data)}')
        return data

    # A convenient alias for callers that think in terms of streams.
    read = read_data

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of this source."""
        return {
            'address': self.board_address,
            'size': self.size,
            'kind': self.kind.value,
            'elf_address': self.elf_address,
            'file_offset': self.file_offset,
            'segment_index': self.segment_index,
            'window_index': self.window_index,
            'state': self.state,
            'name': None if self.window is None else self.window.name,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceSpan:
    """A board interval with one or more parallel source candidates."""

    board_address: int
    size: int
    sources: tuple[ProvenanceSegment, ...]

    @property
    def address(self) -> int:
        """Alias for :attr:`board_address`."""
        return self.board_address

    @property
    def start(self) -> int:
        """Inclusive start of the span."""
        return self.board_address

    @property
    def end(self) -> int:
        """Exclusive end of the span."""
        return self.board_address + self.size

    @property
    def length(self) -> int:
        """Alias for :attr:`size`."""
        return self.size

    @property
    def segments(self) -> tuple[ProvenanceSegment, ...]:
        """Alias for :attr:`sources`."""
        return self.sources

    @property
    def ambiguous(self) -> bool:
        """Whether this span has parallel sources."""
        return len(self.sources) > 1

    @property
    def kinds(self) -> tuple[ProvenanceKind, ...]:
        """Distinct source kinds in source order."""
        return tuple(dict.fromkeys(source.kind for source in self.sources))

    @property
    def kind(self) -> ProvenanceKind | None:
        """The sole source kind, or ``None`` for mixed parallel sources."""
        kinds = self.kinds
        return kinds[0] if len(kinds) == 1 else None

    @property
    def state(self) -> Hashable | None:
        """The sole source state, or ``None`` if sources differ."""
        states = tuple(dict.fromkeys(
            source.state for source in self.sources))
        return states[0] if len(states) == 1 else None

    @property
    def file_offset(self) -> int | None:
        """File offset when this span has exactly one file-backed source."""
        if len(self.sources) == 1:
            return self.sources[0].file_offset
        return None

    @property
    def attested(self) -> bool:
        """Whether every candidate is backed by an ELF PT_LOAD segment."""
        return all(source.attested for source in self.sources)

    def read_data(self, stream: IO[bytes]) -> bytes:
        """Read this span's bytes when it has exactly one file source."""
        if len(self.sources) != 1:
            raise ELFError(
                'cannot read an ambiguous provenance span; select a source')
        return self.sources[0].read_data(stream)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of this span."""
        return {
            'address': self.board_address,
            'size': self.size,
            'sources': [source.as_dict() for source in self.sources],
        }


@dataclass(frozen=True, slots=True)
class ProvenanceReport:
    """The result of :func:`query_address_provenance`."""

    start: int
    size: int
    windows: tuple[StorageWindow, ...]
    state: Hashable | None
    spans: tuple[ProvenanceSpan, ...]

    @property
    def address(self) -> int:
        """Alias for :attr:`start`."""
        return self.start

    @property
    def end(self) -> int:
        """Exclusive end of the queried board range."""
        return self.start + self.size

    @property
    def segments(self) -> tuple[ProvenanceSegment, ...]:
        """All candidate sources, flattened in span order."""
        return tuple(
            source for span in self.spans for source in span.sources)

    @property
    def sources(self) -> tuple[ProvenanceSegment, ...]:
        """Alias for :attr:`segments`."""
        return self.segments

    @property
    def ambiguous(self) -> bool:
        """Whether any span has parallel sources."""
        return any(span.ambiguous for span in self.spans)

    def __iter__(self) -> Iterator[ProvenanceSpan]:
        return iter(self.spans)

    def __len__(self) -> int:
        return len(self.spans)

    def at(self, address: int) -> ProvenanceSpan:
        """Return the span containing a board address."""
        if address < self.start or address >= self.end:
            raise ValueError(
                f'address {address:#x} is outside the queried range')
        for span in self.spans:
            if span.start <= address < span.end:
                return span
        raise AssertionError('provenance report has a coverage hole')

    def iter_segments(
        self,
        kind: ProvenanceKind | str | None = None,
    ) -> Iterator[ProvenanceSegment]:
        """Yield candidate sources, optionally filtered by kind."""
        expected = None if kind is None else ProvenanceKind(kind)
        for source in self.segments:
            if expected is None or source.kind is expected:
                yield source

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the report."""
        return {
            'start': self.start,
            'size': self.size,
            'end': self.end,
            'state': self.state,
            'spans': [span.as_dict() for span in self.spans],
        }


@dataclass(frozen=True, slots=True)
class _LoadSegment:
    index: int
    vaddr: int
    offset: int
    file_size: int
    mem_size: int

    @property
    def file_end(self) -> int:
        return self.vaddr + self.file_size

    @property
    def mem_end(self) -> int:
        return self.vaddr + self.mem_size


def _load_segments(elf: ELFFile) -> tuple[_LoadSegment, ...]:
    segments: list[_LoadSegment] = []
    for index in range(elf.num_segments()):
        segment = elf.get_segment(index)
        if segment['p_type'] != 'PT_LOAD':
            continue
        vaddr = int(segment['p_vaddr'])
        mem_size = int(segment['p_memsz'])
        # Bytes beyond p_memsz are not part of the loaded image.
        file_size = min(int(segment['p_filesz']), mem_size)
        segments.append(_LoadSegment(
            index=index,
            vaddr=vaddr,
            offset=int(segment['p_offset']),
            file_size=file_size,
            mem_size=mem_size,
        ))
    return tuple(segments)


def _same_state(left: Hashable | None, right: Hashable | None) -> bool:
    return left is right or left == right


def _validate_window_conflicts(
    windows: Sequence[StorageWindow],
) -> None:
    for left_index, left in enumerate(windows):
        for right_index in range(left_index + 1, len(windows)):
            right = windows[right_index]
            if left.end <= right.start or right.end <= left.start:
                continue
            if not _same_state(left.state, right.state):
                continue
            if left.elf_start - left.start != right.elf_start - right.start:
                raise WindowMappingError(
                    'storage windows {} and {} overlap in state {!r} with '
                    'different ELF targets'.format(
                        left_index, right_index, left.state))


def _active_windows(
    windows: Sequence[StorageWindow],
    state: Hashable | None,
) -> tuple[StorageWindow, ...]:
    if state is not None:
        return tuple(
            window for window in windows
            if window.state is None or _same_state(window.state, state))
    return tuple(windows)


def _span_boundaries(
    start: int,
    size: int,
    windows: Sequence[StorageWindow],
    segments: Sequence[_LoadSegment],
) -> tuple[int, ...]:
    end = start + size
    points = {start, end}
    for window in windows:
        overlap_start = max(start, window.start)
        overlap_end = min(end, window.end)
        if overlap_start >= overlap_end:
            continue
        points.add(overlap_start)
        points.add(overlap_end)

        for segment in segments:
            elf_start = max(window.elf_start, segment.vaddr)
            elf_end = min(window.elf_end, segment.mem_end)
            if elf_start >= elf_end:
                continue

            for elf_edge in (elf_start, elf_end):
                board_edge = window.start + (elf_edge - window.elf_start)
                if start < board_edge < end:
                    points.add(board_edge)

            if elf_start < segment.file_end < elf_end:
                board_edge = (
                    window.start + (segment.file_end - window.elf_start))
                if start < board_edge < end:
                    points.add(board_edge)
    return tuple(sorted(points))


def _unmapped_source(start: int, size: int) -> ProvenanceSegment:
    return ProvenanceSegment(
        board_address=start,
        size=size,
        kind=ProvenanceKind.UNMAPPED,
    )


def _sources_for_span(
    start: int,
    size: int,
    windows: Sequence[StorageWindow],
    segments: Sequence[_LoadSegment],
    state: Hashable | None,
) -> tuple[ProvenanceSegment, ...]:
    end = start + size
    overlapping = tuple(
        (index, window) for index, window in enumerate(windows)
        if window.start < end and start < window.end
        and (state is None
             or window.state is None
             or _same_state(window.state, state)))
    if not overlapping:
        return (_unmapped_source(start, size),)

    candidates: list[ProvenanceSegment] = []
    seen: set[tuple[Any, ...]] = set()
    for window_index, window in overlapping:
        elf_address = window.elf_start + (start - window.start)
        elf_end = elf_address + size
        covering = tuple(
            segment for segment in segments
            if segment.vaddr <= elf_address
            and elf_end <= segment.mem_end)

        if not covering:
            candidates.append(ProvenanceSegment(
                board_address=start,
                size=size,
                kind=ProvenanceKind.UNATTESTED,
                elf_address=elf_address,
                window_index=window_index,
                window=window,
                state=window.state,
            ))
            continue

        for segment in covering:
            if elf_end <= segment.file_end:
                kind = ProvenanceKind.FILE_BYTES
                file_offset = segment.offset + (elf_address - segment.vaddr)
            elif elf_address >= segment.file_end:
                kind = ProvenanceKind.ZERO_FILL
                file_offset = None
            else:
                # Every file/memory boundary is a span boundary, so a span
                # must never straddle the two backing kinds.
                raise AssertionError(
                    'provenance span straddles a segment backing boundary')

            key = (
                kind, elf_address, file_offset, segment.index, window.state)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(ProvenanceSegment(
                board_address=start,
                size=size,
                kind=kind,
                elf_address=elf_address,
                file_offset=file_offset,
                segment_index=segment.index,
                window_index=window_index,
                window=window,
                state=window.state,
            ))

    if not candidates:
        return (_unmapped_source(start, size),)
    return tuple(candidates)


def query_address_provenance(
    elf: ELFFile,
    start: int,
    size: int,
    windows: WindowInput,
    state: Hashable | None = None,
) -> ProvenanceReport:
    """Split a board-address range into auditable ELF sources.

    :param elf: The offline ELF image to consult.
    :param start: Inclusive board address to query.
    :param size: Number of board bytes to query.
    :param windows: A :class:`StorageWindow` table supplied by the caller.
    :param state: The known hardware state, or ``None`` when it is unknown.
        With an unknown state, conditional windows that cover the same span
        are returned together as parallel sources.

    Only ``PT_LOAD`` program headers are used.  The resolver never reads or
    modifies segment payloads; file offsets are reported for later review.
    """

    start = _as_address(start, 'range start')
    size = _as_size(size, 'range size')
    normalized = normalize_storage_windows(windows)

    if state is not None:
        try:
            hash(state)
        except TypeError as exc:
            raise TypeError('state must be hashable') from exc
        _validate_window_conflicts(_active_windows(normalized, state))
    else:
        _validate_window_conflicts(normalized)

    if size == 0:
        return ProvenanceReport(start, size, normalized, state, ())

    segments = _load_segments(elf)
    boundaries = _span_boundaries(start, size, normalized, segments)
    spans: list[ProvenanceSpan] = []
    for span_start, span_end in zip(boundaries, boundaries[1:]):
        if span_start == span_end:
            continue
        span_size = span_end - span_start
        spans.append(ProvenanceSpan(
            board_address=span_start,
            size=span_size,
            sources=_sources_for_span(
                span_start, span_size, normalized, segments, state),
        ))
    return ProvenanceReport(start, size, normalized, state, tuple(spans))


# Short, intention-revealing aliases.
resolve_address_range = query_address_provenance
address_provenance = query_address_provenance


__all__ = [
    'ProvenanceKind',
    'ProvenanceSegment',
    'ProvenanceSpan',
    'ProvenanceReport',
    'StorageWindow',
    'WindowMappingError',
    'address_provenance',
    'normalize_storage_windows',
    'query_address_provenance',
    'resolve_address_range',
]
