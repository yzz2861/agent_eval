from __future__ import annotations

import bisect
import io
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from dissect.cstruct.exception import AccessDenied, MappingError, MissingPage, SegmentConflict

if TYPE_CHECKING:
    from collections.abc import Iterable

    from typing_extensions import Self

    from dissect.cstruct.types.base import BaseType


def _to_bytes(data: Any) -> bytes:
    """Return an immutable copy of a fragment's bytes."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("latin-1")
    if hasattr(data, "read"):
        return bytes(data.read())
    return bytes(data)


class Segment:
    """A read-only logical address range backed by a bytes-like value.

    A segment may be explicitly marked as unreadable. Such a range is still
    mapped, but accessing it raises :class:`AccessDenied` instead of
    :class:`MissingPage`.

    Args:
        address: Logical start address of the segment.
        data: Bytes contained in the segment. An integer is accepted as a
            shorthand for a zero-filled segment of that size.
        size: Optional size when ``data`` is empty.
        readable: Whether the segment may be read.
        label: Optional human-readable source label.
        name: Alias for ``label``.
        source: Alias for ``label``.
        permissions: Optional permission description. A leading ``-`` or
            ``no``/``none`` marks the segment unreadable.
    """

    __slots__ = ("address", "data", "label", "readable")

    def __init__(
        self,
        address: int | None = None,
        data: bytes | bytearray | memoryview | int | str | None = b"",
        *,
        base: int | None = None,
        start: int | None = None,
        offset: int | None = None,
        size: int | None = None,
        readable: bool = True,
        label: str | None = None,
        name: str | None = None,
        source: str | None = None,
        permissions: str | None = None,
    ):
        if address is None:
            address = base if base is not None else start if start is not None else offset
        if address is None:
            raise TypeError("Segment requires an address")
        if address < 0:
            raise ValueError("Segment address must be non-negative")

        if data is None:
            data = b""

        if isinstance(data, int) and size is None:
            size = data
            data = b""

        if permissions is not None:
            permission_text = str(permissions).lower()
            readable = not (
                permission_text.startswith("-")
                or permission_text in {"no", "none", "forbidden", "denied"}
                or "r" not in permission_text
            )

        if size is not None:
            if size < 0:
                raise ValueError("Segment size must be non-negative")
            if data:
                data = _to_bytes(data)
                if len(data) > size:
                    data = data[:size]
                elif len(data) < size:
                    data = data + b"\x00" * (size - len(data))
            else:
                data = b"\x00" * size
        else:
            data = _to_bytes(data)

        self.address = address
        self.data = data
        self.readable = bool(readable)
        self.label = label if label is not None else name if name is not None else source

    @classmethod
    def forbidden(
        cls,
        address: int,
        size: int,
        *,
        label: str | None = None,
        name: str | None = None,
        source: str | None = None,
    ) -> Self:
        """Create an explicitly unreadable range."""
        return cls(address, size, readable=False, label=label, name=name, source=source)

    @property
    def base(self) -> int:
        return self.address

    @property
    def start(self) -> int:
        return self.address

    @property
    def end(self) -> int:
        return self.address + len(self.data)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def length(self) -> int:
        return len(self.data)

    @property
    def name(self) -> str | None:
        return self.label

    @property
    def readonly(self) -> bool:
        return True

    def __contains__(self, address: int) -> bool:
        return self.address <= address < self.end

    def overlaps(self, other: Segment) -> bool:
        return self.address < other.end and other.address < self.end

    def __repr__(self) -> str:
        access = "r" if self.readable else "-"
        label = f" {self.label!r}" if self.label is not None else ""
        return f"<Segment {self.start:#x}-{self.end:#x} {access} {self.size} bytes{label}>"


Fragment = Segment
Region = Segment


@dataclass(frozen=True, slots=True)
class _Run:
    start: int
    data: bytes
    readable: bool
    label: str | None

    @property
    def end(self) -> int:
        return self.start + len(self.data)


class _Mapping:
    """Validated, immutable runs derived from a collection of segments."""

    __slots__ = ("max_address", "min_address", "runs", "segments", "starts")

    def __init__(self, segments: Iterable[Segment]):
        # Copy the metadata as well as the bytes. An existing view is a snapshot of
        # its evidence and can not be changed by mutating the caller's Segment objects.
        self.segments = tuple(
            Segment(segment.address, segment.data, readable=segment.readable, label=segment.label)
            for segment in segments
        )
        self.runs = self._build_runs()
        self.starts = tuple(run.start for run in self.runs)
        self.min_address = self.runs[0].start if self.runs else 0
        self.max_address = self.runs[-1].end if self.runs else 0

    def _build_runs(self) -> tuple[_Run, ...]:
        ordered = sorted(self.segments, key=lambda segment: (segment.start, segment.end))

        for index, left in enumerate(ordered):
            if not left.data:
                continue
            for right in ordered[index + 1 :]:
                if right.start >= left.end:
                    break
                if not right.data:
                    continue

                overlap_end = min(left.end, right.end)
                overlap_size = overlap_end - right.start
                if overlap_size <= 0:
                    continue

                if left.readable != right.readable:
                    raise SegmentConflict(
                        right.start,
                        overlap_size,
                        "Overlapping segments disagree on readability",
                        label=right.label or left.label,
                    )

                if left.data[right.start - left.start : overlap_end - left.start] != right.data[:overlap_size]:
                    raise SegmentConflict(
                        right.start,
                        overlap_size,
                        "Overlapping segments contain different bytes",
                        label=right.label or left.label,
                    )

        runs: list[_Run] = []
        for segment in ordered:
            if not segment.data:
                continue

            if runs and segment.start <= runs[-1].end and segment.readable == runs[-1].readable:
                current = runs[-1]
                # Validation above guarantees overlapping bytes are identical.
                tail_start = max(current.end - segment.start, 0)
                runs[-1] = _Run(
                    current.start,
                    current.data + segment.data[tail_start:],
                    current.readable,
                    current.label,
                )
            else:
                runs.append(_Run(segment.start, segment.data, segment.readable, segment.label))

        return tuple(runs)

    def find(self, address: int) -> _Run | None:
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0:
            return None

        run = self.runs[index]
        return run if address < run.end else None

    def read(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("Read size must be non-negative")
        if size == 0:
            return b""

        end = address + size
        cursor = address
        parts: list[bytes] = []

        while cursor < end:
            run = self.find(cursor)
            if run is None:
                raise MissingPage(cursor, end - cursor)
            if not run.readable:
                raise AccessDenied(cursor, min(run.end, end) - cursor, label=run.label)

            count = min(run.end, end) - cursor
            offset = cursor - run.start
            parts.append(run.data[offset : offset + count])
            cursor += count

        return b"".join(parts)

    def read_some(self, address: int, size: int) -> bytes:
        """Read up to the next hole or unreadable run."""
        if size <= 0:
            return b""
        if address >= self.max_address:
            return b""

        run = self.find(address)
        if run is None:
            raise MissingPage(address, size)
        if not run.readable:
            raise AccessDenied(address, min(run.end, address + size) - address, label=run.label)

        count = min(run.end, address + size) - address
        offset = address - run.start
        return run.data[offset : offset + count]


class MappedStream(io.RawIOBase):
    """A seekable, immutable, read-only view of logical address segments.

    This is the entry point for parsing a physically fragmented dump by logical
    address. Segments are snapshotted on construction, adjacent logical segments
    are read as one contiguous range even when they came from different regions,
    and pointers keep the view that was active when they were parsed.

    The view distinguishes four outcomes:

    * a legal read, including reads that cross segment boundaries;
    * :class:`MissingPage` when a logical address has no backing segment;
    * :class:`AccessDenied` when a mapped segment is explicitly not readable;
    * :class:`SegmentConflict` when overlapping segments disagree.

    Args:
        segments: Mapping of logical addresses to bytes, or an iterable of
            :class:`Segment` objects or ``(address, data)`` pairs.
        position: Initial logical cursor position.
        partial: Read structures on a best-effort basis, retaining fields that
            could not be confirmed as :class:`Unresolved` values.
        strict_bounds: Raise :class:`MissingPage` for reads at or beyond the
            highest mapped address instead of returning an empty result.
    """

    __mapped__ = True

    def __init__(
        self,
        segments: Mapping[int, Any] | Iterable[Any] = (),
        *,
        position: int = 0,
        partial: bool = False,
        strict_bounds: bool = True,
        cs: Any = None,
    ):
        super().__init__()
        self._mapping = _Mapping(self._coerce_segments(segments))
        self._position = position
        self._partial = partial
        self._strict_bounds = strict_bounds
        self._cs = cs
        self._last_fault: MappingError | None = None

    @staticmethod
    def _coerce_segments(segments: Mapping[int, Any] | Iterable[Any]) -> list[Segment]:
        if isinstance(segments, MappedStream):
            return list(segments.segments)
        if isinstance(segments, Segment):
            return [segments]
        if isinstance(segments, (bytes, bytearray, memoryview, str)):
            return [Segment(0, segments)]
        if isinstance(segments, Mapping):
            result = []
            for address, value in segments.items():
                if isinstance(value, Segment):
                    if value.address != address:
                        raise ValueError("Mapping key does not match Segment address")
                    result.append(value)
                else:
                    result.append(Segment(address, value))
            return result

        result = []
        for value in segments:
            if isinstance(value, Segment):
                result.append(value)
            elif isinstance(value, (tuple, list)) and len(value) == 2:
                result.append(Segment(value[0], value[1]))
            elif isinstance(value, (tuple, list)) and len(value) == 3:
                address, data, readable = value
                result.append(Segment(address, data, readable=readable))
            else:
                raise TypeError(f"Invalid segment: {value!r}")
        return result

    @classmethod
    def from_segments(
        cls,
        *segments: Segment,
        position: int = 0,
        partial: bool = False,
        strict_bounds: bool = True,
    ) -> Self:
        """Create a view from positional :class:`Segment` objects."""
        return cls(segments, position=position, partial=partial, strict_bounds=strict_bounds)

    from_fragments = from_segments

    @property
    def segments(self) -> tuple[Segment, ...]:
        return self._mapping.segments

    @property
    def fragments(self) -> tuple[Segment, ...]:
        return self._mapping.segments

    @property
    def mapping(self) -> dict[int, bytes]:
        """A snapshot of the mapped logical addresses and their bytes."""
        return {segment.address: segment.data for segment in self._mapping.segments}

    @property
    def min_address(self) -> int:
        return self._mapping.min_address

    @property
    def max_address(self) -> int:
        return self._mapping.max_address

    @property
    def partial(self) -> bool:
        return self._partial

    @property
    def strict_bounds(self) -> bool:
        return self._strict_bounds

    @property
    def position(self) -> int:
        return self._position

    @property
    def readonly(self) -> bool:
        return True

    @property
    def cs(self) -> Any:
        """The cstruct instance this view resolves type names with, if any."""
        return self._cs

    @property
    def last_fault(self) -> MappingError | None:
        return self._last_fault

    def at(self, address: int) -> Self:
        """Return an independent cursor over the same immutable mapping."""
        return self._clone(position=address)

    def fork(self, address: int | None = None) -> Self:
        return self._clone(position=self._position if address is None else address)

    @property
    def open(self) -> Self:
        """Alias for :meth:`at`, useful as a parsing entry point."""
        return self.at

    def dereference_view(self, address: int) -> Self:
        """Return a strict cursor for a pointer dereference."""
        return self._clone(position=address, partial=False, strict_bounds=True)

    def partial_view(self) -> Self:
        """Return a cursor that retains unconfirmed structure fields on faults."""
        return self._clone(partial=True)

    def strict_view(self) -> Self:
        """Return a cursor that raises immediately on mapping faults."""
        return self._clone(partial=False, strict_bounds=True)

    def remap(
        self,
        segments: Mapping[int, Any] | Iterable[Any],
        *,
        position: int | None = None,
    ) -> Self:
        """Return a new view with a new mapping, leaving this view and its pointers untouched."""
        return type(self)(
            segments,
            position=self._position if position is None else position,
            partial=self._partial,
            strict_bounds=self._strict_bounds,
            cs=self._cs,
        )

    switch = remap
    map = remap
    update = remap
    bind = remap
    with_segments = remap

    def extend(
        self,
        segments: Mapping[int, Any] | Iterable[Any],
        *,
        position: int | None = None,
    ) -> Self:
        """Return a new view with the current and given segments."""
        return self.remap([*self._mapping.segments, *self._coerce_segments(segments)], position=position)

    add_segment = extend
    map_segment = extend

    def parse(
        self,
        type_: type[BaseType] | str,
        address: int | None = None,
        *,
        endian: str | None = None,
        partial: bool | None = None,
        context: dict[str, Any] | None = None,
        cs: Any = None,
    ) -> Any:
        """Parse a cstruct type at a logical address.

        The caller's cursor is restored even if parsing raises. With
        ``partial=True`` fields that hit a mapping fault are kept as
        :class:`Unresolved` values and later independent fields can still be
        confirmed.
        """
        if isinstance(type_, str):
            base_type = cs or self._cs
            if base_type is None:
                raise TypeError("A type name needs a bound cstruct instance; pass cs=")
            type_ = base_type.resolve(type_)

        stream = self
        if partial is not None and partial != self._partial:
            stream = self._clone(partial=partial)

        position = stream.tell()
        try:
            if address is not None:
                stream.seek(address)
            stream._last_fault = None
            try:
                return stream._read_type(type_, context=context, endian=endian)
            except EOFError as error:
                # Generated fixed-size readers turn a short read into EOFError.
                # For a mapped stream the underlying fault is more precise.
                if stream._last_fault is not None and not isinstance(error, MappingError):
                    raise stream._last_fault from error
                raise
        finally:
            stream.seek(position)

    parse_at = parse

    def read_struct(
        self,
        type_: type[BaseType] | int,
        address: int | type[BaseType] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Alias for :meth:`parse`, accepting either type or address first."""
        if isinstance(type_, int) and address is not None:
            type_, address = address, type_
        return self.parse(type_, address, **kwargs)

    read_type = read_struct
    parse_type = read_struct
    parse_struct = read_struct
    read_structure = read_struct
    struct_at = read_struct

    def parse_partial(
        self,
        type_: type[BaseType],
        address: int | None = None,
        *,
        endian: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> Any:
        """Parse a structure, retaining fields that could not be confirmed."""
        return self.parse(type_, address, endian=endian, partial=True, context=context)

    def _read_type(
        self,
        type_: type[BaseType],
        *,
        context: dict[str, Any] | None = None,
        endian: str | None = None,
    ) -> Any:
        """Read a type through this view, using the shared interpreted constraints when needed."""
        if endian is None:
            endian = type_.__cs__.endian
        elif endian in {"little", "big", "network"}:
            endian = {"little": "<", "big": ">", "network": "!"}[endian]

        if self._partial:
            from dissect.cstruct.types.structure import Structure

            if isinstance(type_, type) and issubclass(type_, Structure):
                meta = type(type_)
                # The generic metaclass reader has the per-field fault handling.
                # Using it for both compiled and interpreted classes keeps the
                # partial-read semantics identical on both paths.
                reader = meta.__dict__.get("_read")
                if reader is not None:
                    return reader(type_, self, context=context, endian=endian)

        return type_._read(self, context=context, endian=endian)

    def read_at(self, address: int, size: int = -1) -> bytes:
        """Read without changing the current cursor position."""
        if size < 0:
            size = max(0, self._mapping.max_address - address)
        return self._mapping.read(address, size)

    read_bytes = read_at

    def segment_at(self, address: int) -> Segment | None:
        """Return the segment backing ``address``, without reading it."""
        for segment in self._mapping.segments:
            if address in segment:
                return segment
        return None

    def is_mapped(self, address: int) -> bool:
        """Return whether ``address`` is backed by a mapped segment."""
        return self._mapping.find(address) is not None

    def sources_at(self, address: int, size: int) -> tuple[str | None, ...]:
        """Return the labels of segments needed for a read, without reading them."""
        end = address + size
        labels: list[str | None] = []
        for segment in self._mapping.segments:
            if segment.end <= address or segment.start >= end:
                continue
            if segment.label not in labels:
                labels.append(segment.label)
        return tuple(labels)

    def __getitem__(self, item: int | slice) -> bytes:
        if isinstance(item, slice):
            if item.step not in (None, 1):
                raise ValueError("MappedStream slices do not support a step")
            start = 0 if item.start is None else item.start
            stop = self._mapping.max_address if item.stop is None else item.stop
            return self.read_at(start, max(0, stop - start))
        return self.read_at(item, 1)

    def read_some(self, size: int = -1) -> bytes:
        """Read up to the next hole, returning ``b""`` only at the mapped end."""
        if size < 0:
            size = max(0, self._mapping.max_address - self._position)
        data = self._mapping.read_some(self._position, size)
        self._position += len(data)
        return data

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            position = offset
        elif whence == io.SEEK_CUR:
            position = self._position + offset
        elif whence == io.SEEK_END:
            position = self._mapping.max_address + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")

        if position < 0:
            raise ValueError("Negative seek position")

        self._position = position
        return position

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""

        self._last_fault = None
        try:
            if size < 0:
                if self._position >= self._mapping.max_address:
                    return b""
                size = self._mapping.max_address - self._position
            elif self._strict_bounds and self._position >= self._mapping.max_address:
                raise MissingPage(self._position, size)

            data = self._mapping.read(self._position, size)
        except MappingError as error:
            self._last_fault = error
            raise

        self._position += len(data)
        return data

    def readinto(self, buffer: bytearray | memoryview) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def write(self, data: bytes | bytearray | memoryview) -> int:
        raise io.UnsupportedOperation("MappedStream is read-only")

    def truncate(self, size: int | None = None) -> int:
        raise io.UnsupportedOperation("MappedStream is read-only")

    def _clone(
        self,
        *,
        position: int | None = None,
        partial: bool | None = None,
        strict_bounds: bool | None = None,
    ) -> Self:
        clone = object.__new__(type(self))
        io.RawIOBase.__init__(clone)
        clone._mapping = self._mapping
        clone._position = self._position if position is None else position
        clone._partial = self._partial if partial is None else partial
        clone._strict_bounds = self._strict_bounds if strict_bounds is None else strict_bounds
        clone._cs = self._cs
        clone._last_fault = None
        return clone

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} {self._mapping.min_address:#x}-{self._mapping.max_address:#x} "
            f"{len(self._mapping.segments)} segments @ {self._position:#x}>"
        )


@dataclass(frozen=True, slots=True, eq=False)
class Unresolved:
    """Placeholder for a field whose backing bytes could not be confirmed."""

    address: int | None = None
    size: int | None = None
    reason: str = "unconfirmed"
    error: MappingError | None = field(default=None, compare=False, repr=False)

    @property
    def confirmed(self) -> bool:
        return False

    @property
    def unconfirmed(self) -> bool:
        return True

    def __bool__(self) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        # All unresolved placeholders represent the same absence of confirmation,
        # while still carrying their individual address and fault for reports.
        return isinstance(other, Unresolved)

    def __hash__(self) -> int:
        return hash(Unresolved)

    def __repr__(self) -> str:
        address = "unknown" if self.address is None else f"{self.address:#x}"
        size = "unknown" if self.size is None else str(self.size)
        return f"<unconfirmed {self.reason} @ {address} size={size}>"


UNCONFIRMED = Unresolved()
Unconfirmed = Unresolved
UnconfirmedValue = Unresolved

# Common names for the same read-only logical view.
MappedView = MappedStream
MappedMemory = MappedStream
MemoryView = MappedStream
AddressSpace = MappedStream
SegmentMap = MappedStream
FragmentView = MappedStream
AddressMap = MappedStream
LogicalView = MappedStream
MappedIO = MappedStream
MemoryMapping = MappedStream
ReadOnlyView = MappedStream
MemorySegment = Segment
