from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from typing import BinaryIO

from dissect.cstruct.discriminator.exceptions import TruncatedRead


class ByteWindow:
    """Read-only view over the bytes currently available for one record.

    A window never pads missing bytes with zeroes. Reading outside the readable
    region raises :class:`TruncatedRead`, so "byte not available yet" can never
    be confused with "byte decoded to zero". Windows are immutable and safe to
    share between candidates.
    """

    def __init__(self, source: bytes | BinaryIO, window_size: int | None = None) -> None:
        if hasattr(source, "read"):
            seek = getattr(source, "seek", None)
            if seek is not None:
                seek(0)
            data = source.read()
        else:
            data = source
        if not isinstance(data, bytes):
            data = bytes(data)
        if window_size is not None:
            if window_size < 0:
                raise ValueError("window_size must be non-negative")
            data = data[:window_size]
        self._data = data

    @property
    def readable_length(self) -> int:
        return len(self._data)

    def contains(self, offset: int, size: int) -> bool:
        if size < 0 or offset < 0:
            raise ValueError("offset and size must be non-negative")
        return offset + size <= len(self._data)

    def read(self, offset: int, size: int) -> bytes:
        if size < 0 or offset < 0:
            raise ValueError("offset and size must be non-negative")
        if not self.contains(offset, size):
            raise TruncatedRead(offset, size, len(self._data))
        return self._data[offset : offset + size]


@dataclass(slots=True)
class CacheStats:
    """Counters showing how much byte fetching was shared between candidates."""

    source_reads: int = 0
    cache_hits: int = 0
    bytes_from_source: int = 0
    bytes_served_from_cache: int = 0


@dataclass(slots=True)
class ReadCache:
    """Shared, append-only byte cache used by every candidate evaluation.

    Successful source reads are merged into contiguous chunks, so a shared
    header prefix is fetched exactly once even when many candidates request it.
    A failed (truncated) read stores nothing: missing bytes can never poison
    another candidate. The cache only ever holds raw bytes; parsed field state
    stays inside each candidate's own context.
    """

    window: ByteWindow
    _chunks: dict[int, bytes] = field(default_factory=dict)
    _starts: list[int] = field(default_factory=list)
    _stats: CacheStats = field(default_factory=CacheStats)
    _readable_length: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self._readable_length = self.window.readable_length

    @property
    def readable_length(self) -> int:
        return self._readable_length

    def stats(self) -> CacheStats:
        return self._stats

    def cached_ranges(self) -> tuple[tuple[int, int], ...]:
        return tuple((start, start + len(chunk)) for start, chunk in sorted(self._chunks.items()))

    def read(self, offset: int, size: int) -> bytes:
        if size == 0:
            return b""
        end = offset + size

        insertion = bisect_right(self._starts, offset)
        if insertion:
            chunk_start = self._starts[insertion - 1]
            chunk = self._chunks[chunk_start]
            if chunk_start + len(chunk) >= end:
                self._stats.cache_hits += 1
                self._stats.bytes_served_from_cache += size
                local = offset - chunk_start
                return chunk[local : local + size]

        payload = self.window.read(offset, size)
        self._store(offset, payload)
        self._stats.source_reads += 1
        self._stats.bytes_from_source += size
        return payload

    def missing(self, offset: int, size: int) -> tuple[tuple[int, int], ...]:
        """Return the un-cached sub-ranges of the full request.

        Ranges past the readable window stay included: the caller uses
        :meth:`readable` to learn which gaps can currently be fetched.
        """
        if size < 0 or offset < 0:
            raise ValueError("offset and size must be non-negative")
        end = offset + size
        covered: list[tuple[int, int]] = []
        for chunk_start, chunk in self._chunks.items():
            chunk_end = chunk_start + len(chunk)
            overlap_start = max(chunk_start, offset)
            overlap_end = min(chunk_end, end)
            if overlap_start < overlap_end:
                covered.append((overlap_start, overlap_end))

        missing_ranges: list[tuple[int, int]] = []
        cursor = offset
        for cover_start, cover_end in sorted(covered):
            if cursor < cover_start:
                missing_ranges.append((cursor, cover_start))
            cursor = max(cursor, cover_end)
        if cursor < end:
            missing_ranges.append((cursor, end))
        return tuple(missing_ranges)

    def readable(self, offset: int, size: int) -> bool:
        """Return whether the whole request lies inside the readable window."""
        return offset >= 0 and offset + size <= self._readable_length

    def _store(self, offset: int, payload: bytes) -> None:
        start = offset
        end = offset + len(payload)
        merged: dict[int, bytes] = {}
        for chunk_start, chunk in self._chunks.items():
            chunk_end = chunk_start + len(chunk)
            if chunk_end < start or chunk_start > end:
                merged[chunk_start] = chunk
                continue
            start = min(start, chunk_start)
            end = max(end, chunk_end)
        merged[start] = self.window.read(start, end - start)
        self._chunks = merged
        self._starts = sorted(merged)
