"""Window assignment for offline quota reconciliation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone


class WindowSpec(ABC):
    """Maps an event time to the quota windows it belongs to."""

    @abstractmethod
    def windows_for(self, timestamp: datetime) -> list[tuple[datetime, datetime]]:
        """Return half-open ``[start, end)`` windows covering ``timestamp``."""

    @abstractmethod
    def all_windows_between(
        self, start: datetime, end: datetime
    ) -> list[tuple[datetime, datetime]]:
        """Return every window whose interval intersects ``[start, end)``."""

    @property
    @abstractmethod
    def size(self) -> timedelta:
        """Length of a single quota window."""


class TumblingWindow(WindowSpec):
    """Fixed, non-overlapping windows aligned to an absolute epoch."""

    def __init__(self, size: timedelta, epoch: datetime | None = None) -> None:
        if size <= timedelta(0):
            raise ValueError("window size must be positive")
        self._size = size
        if epoch is None:
            epoch = datetime.fromtimestamp(0, tz=timezone.utc)
        self._epoch = epoch

    @property
    def size(self) -> timedelta:
        return self._size

    def windows_for(self, timestamp: datetime) -> list[tuple[datetime, datetime]]:
        offset = timestamp - self._epoch
        index = int(offset // self._size)
        start = self._epoch + index * self._size
        return [(start, start + self._size)]

    def all_windows_between(
        self, start: datetime, end: datetime
    ) -> list[tuple[datetime, datetime]]:
        if end <= start:
            return []
        first = self.windows_for(start)[0][0]
        windows: list[tuple[datetime, datetime]] = []
        cursor = first
        while cursor < end:
            windows.append((cursor, cursor + self._size))
            cursor += self._size
        return windows


class SlidingWindow(WindowSpec):
    """Fixed-size windows advanced by a shorter slide, so windows overlap."""

    def __init__(
        self, size: timedelta, slide: timedelta, epoch: datetime | None = None
    ) -> None:
        if size <= timedelta(0):
            raise ValueError("window size must be positive")
        if slide <= timedelta(0):
            raise ValueError("slide must be positive")
        if slide > size:
            raise ValueError("slide must not exceed window size")
        self._size = size
        self._slide = slide
        if epoch is None:
            epoch = datetime.fromtimestamp(0, tz=timezone.utc)
        self._epoch = epoch

    @property
    def size(self) -> timedelta:
        return self._size

    def windows_for(self, timestamp: datetime) -> list[tuple[datetime, datetime]]:
        offset = timestamp - self._epoch
        last_index = int(offset // self._slide)
        first_index = int((offset - self._size) // self._slide) + 1
        windows: list[tuple[datetime, datetime]] = []
        for index in range(first_index, last_index + 1):
            start = self._epoch + index * self._slide
            windows.append((start, start + self._size))
        return windows

    def all_windows_between(
        self, start: datetime, end: datetime
    ) -> list[tuple[datetime, datetime]]:
        if end <= start:
            return []
        first_index = int((start - self._size - self._epoch) // self._slide) + 1
        last_index = int((end - self._epoch) // self._slide)
        windows: list[tuple[datetime, datetime]] = []
        for index in range(first_index, last_index + 1):
            window_start = self._epoch + index * self._slide
            windows.append((window_start, window_start + self._size))
        return windows
