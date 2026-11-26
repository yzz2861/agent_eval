"""Approved maintenance windows and the observation clock derived from them.

A maintenance window is a period in which the monitoring clock is stopped while
the collection pipeline keeps running.  Events received in such a window are
still present in the raw data, but they must not count towards rule evaluation.
Time without data outside an approved window is a genuine observation gap.

Two time coordinates are therefore tracked:

* wall time -- the timestamp carried by an event;
* observation time -- wall time with every *approved* maintenance interval
  removed, i.e. the amount of time the monitor was expected to be watching.

The schedule is immutable.  Replacing maintenance records creates a new
schedule object, leaving earlier replay snapshots and their explanations intact.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator


@dataclass(frozen=True)
class MaintenanceWindow:
    """An approved maintenance interval with half-open ``[start, end)`` bounds.

    ``reason`` and ``reference`` carry the human-readable justification and the
    approval record identifier.  ``approved`` is normally ``True``; an
    unapproved window is retained for audit purposes but does not pause the
    observation clock.
    """

    start: datetime
    end: datetime
    reason: str | None = None
    reference: str | None = None
    approved: bool = True

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("maintenance window bounds must be timezone-aware")
        if self.end <= self.start:
            raise ValueError("maintenance window end must be after its start")

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    @property
    def wall_span(self) -> timedelta:
        return self.duration

    @property
    def maintenance_span(self) -> timedelta:
        return self.duration if self.approved else timedelta()

    def contains(self, instant: datetime) -> bool:
        _require_aware(instant, "instant")
        return self.start <= instant < self.end

    def overlaps(self, other: MaintenanceWindow) -> bool:
        return self.start < other.end and other.start < self.end

    def intersection(self, other: MaintenanceWindow) -> MaintenanceWindow | None:
        start = max(self.start, other.start)
        end = min(self.end, other.end)
        if end <= start:
            return None
        return MaintenanceWindow(start=start, end=end)


class MaintenanceSchedule:
    """An immutable set of maintenance records with observation-clock helpers.

    The original segments are preserved in :attr:`windows` so that overlapping
    approval records remain individually auditable.  Clock arithmetic uses
    :attr:`intervals`, a coalesced view of the approved segments, to make sure
    overlapping windows are never subtracted twice.
    """

    def __init__(self, windows: Iterable[MaintenanceWindow] | None = None) -> None:
        self._windows: tuple[MaintenanceWindow, ...] = tuple(
            sorted(windows or (), key=lambda window: (window.start, window.end))
        )
        approved = tuple(window for window in self._windows if window.approved)
        self._approved_windows: tuple[MaintenanceWindow, ...] = approved
        self._intervals: tuple[MaintenanceWindow, ...] = self._coalesce(approved)

    @staticmethod
    def _coalesce(
        windows: tuple[MaintenanceWindow, ...]
    ) -> tuple[MaintenanceWindow, ...]:
        merged: list[MaintenanceWindow] = []
        for window in windows:
            if not merged or window.start > merged[-1].end:
                merged.append(MaintenanceWindow(start=window.start, end=window.end))
                continue
            previous = merged[-1]
            merged[-1] = MaintenanceWindow(
                start=previous.start,
                end=max(previous.end, window.end),
            )
        return tuple(merged)

    @property
    def windows(self) -> tuple[MaintenanceWindow, ...]:
        """All maintenance records in chronological order, including repeats."""

        return self._windows

    @property
    def approved_windows(self) -> tuple[MaintenanceWindow, ...]:
        return self._approved_windows

    @property
    def intervals(self) -> tuple[MaintenanceWindow, ...]:
        """Coalesced approved intervals used for clock arithmetic."""

        return self._intervals

    def __iter__(self) -> Iterator[MaintenanceWindow]:
        return iter(self._windows)

    def __len__(self) -> int:
        return len(self._windows)

    def __bool__(self) -> bool:
        return bool(self._windows)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MaintenanceSchedule) and other._windows == self._windows

    def __repr__(self) -> str:
        return f"MaintenanceSchedule(windows={self._windows!r})"

    def replace(
        self, windows: Iterable[MaintenanceWindow] | None = None
    ) -> MaintenanceSchedule:
        """Return a new schedule, leaving every existing snapshot untouched."""

        return MaintenanceSchedule(windows)

    def containing(self, instant: datetime) -> MaintenanceWindow | None:
        """Return the approved maintenance record containing ``instant``, if any."""

        _require_aware(instant, "instant")
        for window in self._approved_windows:
            if instant < window.start:
                break
            if instant < window.end:
                return window
        return None

    def is_maintenance(self, instant: datetime) -> bool:
        return self.containing(instant) is not None

    def overlapping(self, start: datetime, end: datetime) -> tuple[MaintenanceWindow, ...]:
        """Return every maintenance record that overlaps ``[start, end)``."""

        _require_aware(start, "start")
        _require_aware(end, "end")
        if end < start:
            raise ValueError("end must not be before start")
        return tuple(
            window
            for window in self._windows
            if window.start < end and start < window.end
        )

    def maintenance_before(self, instant: datetime) -> timedelta:
        """Total approved maintenance time elapsed at or before ``instant``."""

        _require_aware(instant, "instant")
        total = timedelta()
        for interval in self._intervals:
            if instant >= interval.end:
                total += interval.duration
            elif instant > interval.start:
                total += instant - interval.start
                break
            else:
                break
        return total

    def maintenance_between(self, start: datetime, end: datetime) -> timedelta:
        """Approved maintenance time inside the half-open interval ``[start, end)``."""

        _require_aware(start, "start")
        _require_aware(end, "end")
        if end < start:
            raise ValueError("end must not be before start")
        return self.maintenance_before(end) - self.maintenance_before(start)

    def to_observed_time(self, instant: datetime) -> datetime:
        """Map wall time onto the monitoring clock by removing maintenance time."""

        _require_aware(instant, "instant")
        return instant - self.maintenance_before(instant)

    def observed_span(self, start: datetime, end: datetime) -> timedelta:
        """Wall-clock span minus approved maintenance time inside the span."""

        _require_aware(start, "start")
        _require_aware(end, "end")
        if end < start:
            raise ValueError("end must not be before start")
        return (end - start) - self.maintenance_between(start, end)

    def observation_span(self, start: datetime, end: datetime) -> timedelta:
        """Alias for :meth:`observed_span`."""

        return self.observed_span(start, end)

    def uncovered_intervals(
        self, start: datetime, end: datetime
    ) -> tuple[tuple[datetime, datetime], ...]:
        """Return the parts of ``[start, end)`` not covered by approved maintenance."""

        _require_aware(start, "start")
        _require_aware(end, "end")
        if end < start:
            raise ValueError("end must not be before start")

        pieces: list[tuple[datetime, datetime]] = []
        cursor = start
        for interval in self._intervals:
            if interval.end <= cursor:
                continue
            if interval.start >= end:
                break
            segment_start = max(interval.start, start)
            segment_end = min(interval.end, end)
            if cursor < segment_start:
                pieces.append((cursor, segment_start))
            cursor = max(cursor, segment_end)
        if cursor < end:
            pieces.append((cursor, end))
        return tuple(pieces)


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")


MaintenanceSegment = MaintenanceWindow
