from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable


@dataclass(frozen=True)
class HandoverInterval:
    """Signed time interval in which two receiver groups may carry event copies."""

    interval_id: str
    start: datetime
    end: datetime
    source_receiver: str
    target_receiver: str
    acknowledged: bool = True

    def contains(self, timestamp: datetime) -> bool:
        return self.start <= timestamp <= self.end


@dataclass(frozen=True)
class HandoverUndeterminableRange:
    """Handover interval whose coverage cannot be proven from observed receivers."""

    interval_id: str
    start: datetime
    end: datetime
    missing_receivers: frozenset[str]


@dataclass
class HandoverTracker:
    """Tracks signed handover intervals and evidence of receiver participation."""

    _intervals: dict[str, HandoverInterval] = field(default_factory=dict)
    _observed_receivers: dict[str, set[str]] = field(default_factory=dict)
    _closed_interval_ids: set[str] = field(default_factory=set)

    @property
    def intervals(self) -> list[HandoverInterval]:
        return list(self._intervals.values())

    def add_intervals(
        self, intervals: HandoverInterval | Iterable[HandoverInterval] | None
    ) -> None:
        if intervals is None:
            return
        if isinstance(intervals, HandoverInterval):
            intervals = [intervals]
        for interval in intervals:
            self._intervals[interval.interval_id] = interval
            self._observed_receivers.setdefault(interval.interval_id, set())

    def add_interval(self, interval: HandoverInterval) -> None:
        self.add_intervals(interval)

    def record_event(self, timestamp: datetime, receiver_id: str | None) -> None:
        if receiver_id is None:
            return
        for interval in self._intervals.values():
            if interval.contains(timestamp):
                self._observed_receivers.setdefault(interval.interval_id, set()).add(receiver_id)

    def flush(self, now: datetime) -> list[HandoverUndeterminableRange]:
        ranges: list[HandoverUndeterminableRange] = []
        for interval in self._intervals.values():
            if interval.end > now or interval.interval_id in self._closed_interval_ids:
                continue
            self._closed_interval_ids.add(interval.interval_id)
            if not interval.acknowledged:
                continue
            observed = self._observed_receivers.get(interval.interval_id, set())
            required = {interval.source_receiver, interval.target_receiver}
            missing = frozenset(required - observed)
            if missing:
                ranges.append(
                    HandoverUndeterminableRange(
                        interval_id=interval.interval_id,
                        start=interval.start,
                        end=interval.end,
                        missing_receivers=missing,
                    )
                )
        return ranges

    def allows_content_dedup(self, timestamp: datetime) -> bool:
        return any(
            interval.acknowledged and interval.contains(timestamp)
            for interval in self._intervals.values()
        )

    def snapshot(self) -> dict[str, object]:
        return {
            "intervals": dict(self._intervals),
            "observed_receivers": {
                interval_id: set(receivers)
                for interval_id, receivers in self._observed_receivers.items()
            },
            "closed_interval_ids": set(self._closed_interval_ids),
        }

    def restore(self, state: dict[str, object]) -> None:
        intervals = state["intervals"]
        observed = state["observed_receivers"]
        closed = state["closed_interval_ids"]
        self._intervals = dict(intervals)  # type: ignore[arg-type]
        self._observed_receivers = {
            interval_id: set(receivers)  # type: ignore[arg-type]
            for interval_id, receivers in observed.items()
        }
        self._closed_interval_ids = set(closed)  # type: ignore[arg-type]
