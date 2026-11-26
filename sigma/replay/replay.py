"""Local dual-clock replay for Sigma rule evaluation.

The replay keeps two time coordinates side by side:

* wall time records when an event actually happened;
* observation time removes every approved maintenance interval and therefore
  only advances while the monitor was expected to be watching.

Real events are partitioned into countable events that feed the Sigma matcher
and maintenance events that carry data but cannot count.  Time without data
outside an approved maintenance window is reported as an unobservable gap.
Synthetic markers are emitted at both ends of every maintenance window, and
each marker carries the event-time bucket it lands in as well as its observation
clock reading.  Snapshots retain the schedule that was in force when a match was
produced, so replacing maintenance records does not erase the explanation of an
earlier hit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Iterable, Sequence

from sigma.replay.maintenance import MaintenanceSchedule, MaintenanceWindow

if TYPE_CHECKING:
    from sigma.matching.event import Event
    from sigma.matching.match import SigmaMatch
    from sigma.matching.matcher import SigmaMatcher


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ReplayEventKind(Enum):
    """Origin of a replay entry."""

    OBSERVED = "observed"
    EVENT = "observed"
    MAINTENANCE = "maintenance"
    WINDOW_START = "window_start"
    WINDOW_END = "window_end"


class ObservationStatus(Enum):
    """How an entry, bucket, or gap is treated when evaluating rules."""

    OBSERVABLE = "observable"
    SUPPRESSED_MAINTENANCE = "suppressed_maintenance"
    BOUNDARY = "boundary"
    UNOBSERVABLE = "unobservable"
    PARTIAL = "partial"

    @property
    def countable(self) -> bool:
        return self is ObservationStatus.OBSERVABLE


@dataclass(frozen=True)
class ReplayEvent:
    """An event placed on both clocks and in an event-time landing bucket.

    ``wall_time`` is the event timestamp.  ``observed_time`` is the same instant
    after approved maintenance time has been removed.  Synthetic boundary
    markers carry no source event and are never matched.
    """

    kind: ReplayEventKind
    status: ObservationStatus
    wall_time: datetime
    observed_time: datetime
    event: Event | None = None
    window: MaintenanceWindow | None = None
    matches: tuple[SigmaMatch, ...] = ()
    bucket_start: datetime | None = None
    bucket_end: datetime | None = None

    @property
    def is_synthetic(self) -> bool:
        return self.event is None

    @property
    def is_countable(self) -> bool:
        return self.status is ObservationStatus.OBSERVABLE

    @property
    def landing_point(self) -> datetime:
        """The event-time bucket start used as this entry's landing point."""

        return self.bucket_start if self.bucket_start is not None else self.wall_time

    @property
    def bucket(self) -> tuple[datetime, datetime] | None:
        if self.bucket_start is None or self.bucket_end is None:
            return None
        return (self.bucket_start, self.bucket_end)


@dataclass(frozen=True)
class ReplayBucket:
    """An event-time landing bucket with its dual-clock accounting."""

    start: datetime
    end: datetime
    observed_start: datetime
    observed_end: datetime
    wall_span: timedelta
    maintenance_span: timedelta
    observed_span: timedelta
    entries: tuple[ReplayEvent, ...] = ()
    matches: tuple[SigmaMatch, ...] = ()
    missing_span: timedelta = timedelta()
    status: ObservationStatus = ObservationStatus.OBSERVABLE

    @property
    def landing_point(self) -> datetime:
        return self.start

    @property
    def counted_events(self) -> tuple[ReplayEvent, ...]:
        return tuple(entry for entry in self.entries if entry.is_countable)

    @property
    def suppressed_events(self) -> tuple[ReplayEvent, ...]:
        return tuple(
            entry
            for entry in self.entries
            if entry.status is ObservationStatus.SUPPRESSED_MAINTENANCE
        )

    @property
    def synthetic_events(self) -> tuple[ReplayEvent, ...]:
        return tuple(entry for entry in self.entries if entry.is_synthetic)

    @property
    def has_data(self) -> bool:
        return any(not entry.is_synthetic for entry in self.entries)

    @property
    def has_counted_data(self) -> bool:
        return bool(self.counted_events)

    @property
    def has_suppressed_data(self) -> bool:
        return bool(self.suppressed_events)


@dataclass(frozen=True)
class ObservationGap:
    """A wall-clock interval without data that is not explained by maintenance.

    ``start`` and ``end`` delimit only the genuinely unobservable part of the
    silence.  ``silent_start`` and ``silent_end`` retain the surrounding interval
    between real events, including any maintenance inside it, so both views stay
    available for a review.  ``maintenance_duration`` is the approved maintenance
    inside that surrounding interval, not inside ``[start, end)``.
    """

    start: datetime
    end: datetime
    observed_start: datetime
    observed_end: datetime
    duration: timedelta
    maintenance_duration: timedelta
    windows: tuple[MaintenanceWindow, ...]
    status: ObservationStatus = ObservationStatus.UNOBSERVABLE
    silent_start: datetime | None = None
    silent_end: datetime | None = None

    @property
    def wall_span(self) -> timedelta:
        return self.duration

    @property
    def observed_span(self) -> timedelta:
        return self.duration

    @property
    def is_empty(self) -> bool:
        return self.duration <= timedelta()


@dataclass(frozen=True)
class WindowReport:
    """How a single maintenance record behaved during the replay."""

    window: MaintenanceWindow
    suppressed_events: tuple[ReplayEvent, ...]
    start_marker: ReplayEvent
    end_marker: ReplayEvent
    counted_events: tuple[ReplayEvent, ...] = ()

    @property
    def has_data(self) -> bool:
        return bool(self.suppressed_events or self.counted_events)

    @property
    def had_data(self) -> bool:
        return self.has_data

    @property
    def wall_span(self) -> timedelta:
        return self.window.duration

    @property
    def maintenance_span(self) -> timedelta:
        return self.window.maintenance_span

    @property
    def observed_span(self) -> timedelta:
        return timedelta() if self.window.approved else self.window.duration


@dataclass(frozen=True)
class MatchExplanation:
    """Why a rule matched under the schedule captured by a replay snapshot."""

    rule_identifier: str
    matches: tuple[SigmaMatch, ...]
    contributing_events: tuple[ReplayEvent, ...]
    suppressed_events: tuple[ReplayEvent, ...]
    maintenance_windows: tuple[MaintenanceWindow, ...]
    buckets: tuple[ReplayBucket, ...] = ()
    reason: str | None = None

    @property
    def is_empty(self) -> bool:
        return not self.matches


@dataclass(frozen=True)
class ReplaySnapshot:
    """Frozen replay state tied to the maintenance schedule used at the time."""

    label: str | None
    schedule: MaintenanceSchedule
    windows: tuple[MaintenanceWindow, ...]
    result: ReplayResult
    captured_at: datetime

    @property
    def entries(self) -> tuple[ReplayEvent, ...]:
        return self.result.entries

    @property
    def buckets(self) -> tuple[ReplayBucket, ...]:
        return self.result.buckets

    @property
    def gaps(self) -> tuple[ObservationGap, ...]:
        return self.result.gaps

    @property
    def matches(self) -> tuple[SigmaMatch, ...]:
        return self.result.matches

    def explain_rule(self, rule_identifier: str) -> MatchExplanation:
        return self.result.explain_rule(rule_identifier)


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of a dual-clock replay."""

    schedule: MaintenanceSchedule
    entries: tuple[ReplayEvent, ...]
    gaps: tuple[ObservationGap, ...]
    real_events: tuple[ReplayEvent, ...]
    matches: tuple[SigmaMatch, ...]
    buckets: tuple[ReplayBucket, ...] = ()
    window_start: datetime | None = None
    window_end: datetime | None = None

    @property
    def observed_events(self) -> tuple[ReplayEvent, ...]:
        return tuple(
            entry for entry in self.entries if entry.status is ObservationStatus.OBSERVABLE
        )

    @property
    def counted_events(self) -> tuple[ReplayEvent, ...]:
        return self.observed_events

    @property
    def normal_events(self) -> tuple[ReplayEvent, ...]:
        return self.observed_events

    @property
    def maintenance_events(self) -> tuple[ReplayEvent, ...]:
        return self.suppressed_events

    @property
    def maintenance_windows(self) -> tuple[MaintenanceWindow, ...]:
        return self.schedule.windows

    @property
    def missing_segments(self) -> tuple[ObservationGap, ...]:
        return self.gaps

    @property
    def suppressed_events(self) -> tuple[ReplayEvent, ...]:
        return tuple(
            entry
            for entry in self.entries
            if entry.status is ObservationStatus.SUPPRESSED_MAINTENANCE
        )

    @property
    def synthetic_events(self) -> tuple[ReplayEvent, ...]:
        return tuple(entry for entry in self.entries if entry.is_synthetic)

    @property
    def boundary_events(self) -> tuple[ReplayEvent, ...]:
        return self.synthetic_events

    def _range(self) -> tuple[datetime, datetime] | None:
        if self.window_start is not None and self.window_end is not None:
            return (self.window_start, self.window_end)

        values: list[datetime] = [entry.wall_time for entry in self.real_events]
        for window in self.schedule.approved_windows:
            values.extend((window.start, window.end))
        if not values:
            return None
        start = self.window_start if self.window_start is not None else min(values)
        end = self.window_end if self.window_end is not None else max(values)
        return (start, end)

    @property
    def wall_span(self) -> timedelta:
        bounds = self._range()
        return bounds[1] - bounds[0] if bounds is not None else timedelta()

    @property
    def maintenance_span(self) -> timedelta:
        bounds = self._range()
        if bounds is None:
            return timedelta()
        return self.schedule.maintenance_between(bounds[0], bounds[1])

    @property
    def observation_span(self) -> timedelta:
        """Time the observation clock was running (wall span minus maintenance)."""

        return max(self.wall_span - self.maintenance_span, timedelta())

    @property
    def observed_span(self) -> timedelta:
        return self.observation_span

    @property
    def unobservable_span(self) -> timedelta:
        return sum((gap.duration for gap in self.gaps), timedelta())

    @property
    def data_span(self) -> timedelta:
        """Observation-clock time that is not part of an actual data gap."""

        return max(self.observation_span - self.unobservable_span, timedelta())

    @property
    def counted_span(self) -> timedelta:
        return self.data_span

    @property
    def observed_data_span(self) -> timedelta:
        return self.data_span

    def bucket_at(self, instant: datetime) -> ReplayBucket | None:
        _require_aware(instant, "instant")
        for bucket in self.buckets:
            if bucket.start <= instant < bucket.end:
                return bucket
        return None

    def matches_for(self, rule_identifier: str) -> tuple[SigmaMatch, ...]:
        return tuple(
            match
            for match in self.matches
            if rule_identifier in _rule_identifiers(match)
        )

    def window_reports(self) -> tuple[WindowReport, ...]:
        markers: dict[MaintenanceWindow, dict[str, ReplayEvent]] = {}
        suppressed: dict[MaintenanceWindow, list[ReplayEvent]] = {}
        counted: dict[MaintenanceWindow, list[ReplayEvent]] = {}

        for entry in self.entries:
            if entry.is_synthetic:
                if entry.window is not None:
                    side = "start" if entry.kind is ReplayEventKind.WINDOW_START else "end"
                    markers.setdefault(entry.window, {})[side] = entry
                continue
            if entry.status is ObservationStatus.SUPPRESSED_MAINTENANCE:
                if entry.window is not None:
                    suppressed.setdefault(entry.window, []).append(entry)
                continue
            if entry.is_countable:
                for window in self.schedule.windows:
                    if window.contains(entry.wall_time):
                        counted.setdefault(window, []).append(entry)

        reports: list[WindowReport] = []
        for window in self.schedule.windows:
            boundary = markers.get(window)
            if boundary is None or "start" not in boundary or "end" not in boundary:
                continue
            reports.append(
                WindowReport(
                    window=window,
                    suppressed_events=tuple(suppressed.get(window, ())),
                    start_marker=boundary["start"],
                    end_marker=boundary["end"],
                    counted_events=tuple(counted.get(window, ())),
                )
            )
        return tuple(reports)

    def explain_rule(self, rule_identifier: str) -> MatchExplanation:
        matches = self.matches_for(rule_identifier)
        match_ids = {id(match) for match in matches}
        matched_events = {id(event) for match in matches for event in match.events}

        contributing: list[ReplayEvent] = []
        for entry in self.entries:
            entry_matches = {id(match) for match in entry.matches}
            if entry_matches & match_ids or (
                entry.event is not None and id(entry.event) in matched_events
            ):
                contributing.append(entry)

        contributing_ids = {id(entry) for entry in contributing}
        buckets = tuple(
            bucket
            for bucket in self.buckets
            if any(id(entry) in contributing_ids for entry in bucket.entries)
        )
        reason = (
            f"{len(matches)} match(es) for {rule_identifier!r} under "
            f"{len(self.schedule.approved_windows)} approved maintenance record(s); "
            f"{len(contributing)} contributing replay entrie(s), "
            f"{len(self.suppressed_events)} maintenance suppression(s)."
        )
        return MatchExplanation(
            rule_identifier=rule_identifier,
            matches=matches,
            contributing_events=tuple(contributing),
            suppressed_events=self.suppressed_events,
            maintenance_windows=self.schedule.windows,
            buckets=buckets,
            reason=reason,
        )


class DualClockReplay:
    """Replay events locally while maintaining wall and observation clocks.

    ``window`` (or its alias ``bucket_size``) controls the event-time landing
    bucket.  Buckets are half-open ``[start, end)`` intervals; an event exactly
    on a boundary lands in the following bucket.  The observation-clock reading
    of the same event is independent of the landing bucket.
    """

    def __init__(
        self,
        schedule: MaintenanceSchedule | Iterable[MaintenanceWindow] | None = None,
        matcher: SigmaMatcher | None = None,
        *,
        window: timedelta | None = None,
        bucket_size: timedelta | None = None,
        bucket_origin: datetime | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> None:
        if window is not None and bucket_size is not None and window != bucket_size:
            raise ValueError("window and bucket_size must agree when both are supplied")
        size = bucket_size if bucket_size is not None else window
        if size is None:
            size = timedelta(hours=1)
        if size <= timedelta():
            raise ValueError("replay window must be positive")

        if window_start is not None:
            _require_aware(window_start, "window_start")
        if window_end is not None:
            _require_aware(window_end, "window_end")
        if window_start is not None and window_end is not None and window_end <= window_start:
            raise ValueError("window_end must be after window_start")

        if bucket_origin is not None:
            _require_aware(bucket_origin, "bucket_origin")
        self._origin = bucket_origin if bucket_origin is not None else _EPOCH
        self.bucket_size = size
        self.window_start = window_start
        self.window_end = window_end
        self.schedule = (
            schedule if isinstance(schedule, MaintenanceSchedule) else MaintenanceSchedule(schedule)
        )
        self._matcher = matcher
        self._entries: list[ReplayEvent] = []
        self._matches: list[SigmaMatch] = []
        self._results: ReplayResult | None = None
        self._history: list[ReplaySnapshot] = []

    @property
    def history(self) -> tuple[ReplaySnapshot, ...]:
        """Snapshots automatically retained when the maintenance record changes."""

        return tuple(self._history)

    @property
    def entries(self) -> tuple[ReplayEvent, ...]:
        return tuple(self._entries)

    def bucket_bounds(self, instant: datetime) -> tuple[datetime, datetime]:
        """Return the half-open event-time bucket containing ``instant``."""

        _require_aware(instant, "instant")
        instant_utc = instant.astimezone(timezone.utc)
        delta = instant_utc - self._origin.astimezone(timezone.utc)
        index = delta // self.bucket_size
        start = self._origin.astimezone(timezone.utc) + index * self.bucket_size
        end = start + self.bucket_size
        return (start.astimezone(instant.tzinfo), end.astimezone(instant.tzinfo))

    def feed(self, event: Event) -> list[SigmaMatch]:
        """Place one event on both clocks and match it only when countable."""

        wall_time = event.timestamp
        _require_aware(wall_time, "event timestamp")
        if self.window_start is not None and wall_time < self.window_start:
            raise ValueError("event timestamp is before the replay window")
        if self.window_end is not None and wall_time >= self.window_end:
            raise ValueError("event timestamp is outside the replay window")
        observed_time = self.schedule.to_observed_time(wall_time)
        bucket_start, bucket_end = self.bucket_bounds(wall_time)
        window = self.schedule.containing(wall_time)

        matches: list[SigmaMatch] = []
        if window is None:
            kind = ReplayEventKind.OBSERVED
            status = ObservationStatus.OBSERVABLE
            if self._matcher is not None:
                matches = self._matcher.match(event)
                self._matches.extend(matches)
        else:
            kind = ReplayEventKind.MAINTENANCE
            status = ObservationStatus.SUPPRESSED_MAINTENANCE

        self._entries.append(
            ReplayEvent(
                kind=kind,
                status=status,
                wall_time=wall_time,
                observed_time=observed_time,
                event=event,
                window=window,
                matches=tuple(matches),
                bucket_start=bucket_start,
                bucket_end=bucket_end,
            )
        )
        self._results = None
        return matches

    def add(self, event: Event) -> list[SigmaMatch]:
        """Alias for :meth:`feed`."""

        return self.feed(event)

    def run(self, events: Iterable[Event]) -> ReplayResult:
        """Replay a batch in event-time order and return the finished result."""

        self.reset()
        ordered = sorted(events, key=lambda event: event.timestamp)
        for event in ordered:
            self.feed(event)
        return self.finish()

    def finish(self) -> ReplayResult:
        if self._results is not None:
            return self._results

        real = sorted(self._entries, key=lambda entry: entry.wall_time)
        markers = self._build_boundary_markers()
        entries = sorted(
            [*real, *markers],
            key=lambda entry: (entry.wall_time, self._entry_order(entry)),
        )

        bounds = self._resolve_range(real)
        gaps = self._build_gaps(real, bounds)
        buckets = self._build_buckets(entries, gaps)
        self._results = ReplayResult(
            schedule=self.schedule,
            entries=tuple(entries),
            gaps=tuple(gaps),
            real_events=tuple(real),
            matches=tuple(self._matches),
            buckets=tuple(buckets),
            window_start=bounds[0] if bounds is not None else None,
            window_end=bounds[1] if bounds is not None else None,
        )
        return self._results

    def reset(self) -> None:
        """Discard replayed events and matches, keeping the current schedule."""

        self._entries.clear()
        self._matches.clear()
        self._results = None

    def clear(self) -> None:
        """Alias for :meth:`reset`."""

        self.reset()

    def snapshot(
        self,
        label: str | None = None,
        captured_at: datetime | None = None,
    ) -> ReplaySnapshot:
        """Freeze the current result together with the active maintenance record."""

        if captured_at is None:
            captured_at = datetime.now(tz=timezone.utc)
        else:
            _require_aware(captured_at, "captured_at")
        return ReplaySnapshot(
            label=label,
            schedule=self.schedule,
            windows=self.schedule.windows,
            result=self.finish(),
            captured_at=captured_at,
        )

    def replace_schedule(
        self,
        schedule: MaintenanceSchedule | Iterable[MaintenanceWindow] | None,
        label: str | None = None,
    ) -> ReplaySnapshot | None:
        """Swap in a new maintenance record and start a fresh replay epoch.

        If events have already been replayed, the previous state is retained as a
        snapshot and returned.  It remains explainable against the schedule that
        was in force when its matches were produced.
        """

        previous = self.snapshot(label=label) if self._entries else None
        if previous is not None:
            self._history.append(previous)
        self.schedule = (
            schedule if isinstance(schedule, MaintenanceSchedule) else MaintenanceSchedule(schedule)
        )
        self.reset()
        return previous

    def replace_maintenance(
        self,
        schedule: MaintenanceSchedule | Iterable[MaintenanceWindow] | None,
        label: str | None = None,
    ) -> ReplaySnapshot | None:
        """Alias for :meth:`replace_schedule`."""

        return self.replace_schedule(schedule, label=label)

    def explain_rule(
        self,
        rule_identifier: str,
        snapshot: ReplaySnapshot | None = None,
    ) -> MatchExplanation:
        """Explain a hit from the current state or from a frozen snapshot."""

        if snapshot is not None:
            return snapshot.explain_rule(rule_identifier)
        return self.finish().explain_rule(rule_identifier)

    def _resolve_range(
        self, real: Sequence[ReplayEvent]
    ) -> tuple[datetime, datetime] | None:
        if self.window_start is not None and self.window_end is not None:
            return (self.window_start, self.window_end)

        values: list[datetime] = [entry.wall_time for entry in real]
        for window in self.schedule.approved_windows:
            values.extend((window.start, window.end))
        if not values:
            return None
        start = self.window_start if self.window_start is not None else min(values)
        end = self.window_end if self.window_end is not None else max(values)
        if end <= start:
            return None
        return (start, end)

    def _build_boundary_markers(self) -> list[ReplayEvent]:
        markers: list[ReplayEvent] = []
        for window in self.schedule.windows:
            for instant, kind in (
                (window.start, ReplayEventKind.WINDOW_START),
                (window.end, ReplayEventKind.WINDOW_END),
            ):
                bucket_start, bucket_end = self.bucket_bounds(instant)
                markers.append(
                    ReplayEvent(
                        kind=kind,
                        status=ObservationStatus.BOUNDARY,
                        wall_time=instant,
                        observed_time=self.schedule.to_observed_time(instant),
                        window=window,
                        bucket_start=bucket_start,
                        bucket_end=bucket_end,
                    )
                )
        return markers

    def _build_gaps(
        self,
        real: Sequence[ReplayEvent],
        bounds: tuple[datetime, datetime] | None,
    ) -> list[ObservationGap]:
        if bounds is None:
            return []

        range_start, range_end = bounds
        anchors = sorted(
            {
                range_start,
                *(entry.wall_time for entry in real if range_start <= entry.wall_time <= range_end),
                range_end,
            }
        )
        gaps: list[ObservationGap] = []
        for silent_start, silent_end in zip(anchors, anchors[1:]):
            if silent_end <= silent_start:
                continue
            maintenance_duration = self.schedule.maintenance_between(
                silent_start, silent_end
            )
            windows = tuple(
                window
                for window in self.schedule.overlapping(silent_start, silent_end)
                if window.approved
            )
            for gap_start, gap_end in self.schedule.uncovered_intervals(
                silent_start, silent_end
            ):
                if gap_end <= gap_start:
                    continue
                gaps.append(
                    ObservationGap(
                        start=gap_start,
                        end=gap_end,
                        observed_start=self.schedule.to_observed_time(gap_start),
                        observed_end=self.schedule.to_observed_time(gap_end),
                        duration=gap_end - gap_start,
                        maintenance_duration=maintenance_duration,
                        windows=windows,
                        silent_start=silent_start,
                        silent_end=silent_end,
                    )
                )
        return gaps

    def _build_buckets(
        self, entries: Sequence[ReplayEvent], gaps: Sequence[ObservationGap]
    ) -> list[ReplayBucket]:
        starts: set[datetime] = set()
        for entry in entries:
            starts.add(entry.landing_point)
        for gap in gaps:
            cursor, _ = self.bucket_bounds(gap.start)
            while cursor < gap.end:
                starts.add(cursor)
                cursor += self.bucket_size

        buckets: list[ReplayBucket] = []
        for start in sorted(starts):
            end = start + self.bucket_size
            bucket_entries = tuple(
                entry for entry in entries if entry.landing_point == start
            )
            bucket_gaps = tuple(
                gap for gap in gaps if gap.start < end and start < gap.end
            )
            missing_span = sum(
                (
                    min(gap.end, end) - max(gap.start, start)
                    for gap in bucket_gaps
                ),
                timedelta(),
            )
            counted = any(entry.is_countable for entry in bucket_entries)
            suppressed = any(
                entry.status is ObservationStatus.SUPPRESSED_MAINTENANCE
                for entry in bucket_entries
            )
            synthetic = any(entry.is_synthetic for entry in bucket_entries)
            missing = missing_span > timedelta()
            if counted and (suppressed or missing):
                status = ObservationStatus.PARTIAL
            elif counted:
                status = ObservationStatus.OBSERVABLE
            elif suppressed:
                status = ObservationStatus.SUPPRESSED_MAINTENANCE
            elif missing:
                status = ObservationStatus.UNOBSERVABLE
            elif synthetic:
                status = ObservationStatus.BOUNDARY
            else:
                status = ObservationStatus.OBSERVABLE

            wall_span = end - start
            maintenance_span = self.schedule.maintenance_between(start, end)
            matches: list[SigmaMatch] = []
            for entry in bucket_entries:
                for match in entry.matches:
                    if all(match is not existing for existing in matches):
                        matches.append(match)

            buckets.append(
                ReplayBucket(
                    start=start,
                    end=end,
                    observed_start=self.schedule.to_observed_time(start),
                    observed_end=self.schedule.to_observed_time(end),
                    wall_span=wall_span,
                    maintenance_span=maintenance_span,
                    observed_span=max(wall_span - maintenance_span, timedelta()),
                    entries=bucket_entries,
                    matches=tuple(matches),
                    missing_span=missing_span,
                    status=status,
                )
            )
        return buckets

    @staticmethod
    def _entry_order(entry: ReplayEvent) -> int:
        if entry.kind is ReplayEventKind.WINDOW_START:
            return 0
        if entry.kind is ReplayEventKind.WINDOW_END:
            return 2
        return 1


def _rule_identifiers(match: SigmaMatch) -> set[str]:
    rule = match.rule
    identifiers = {
        getattr(rule, "name", None),
        getattr(rule, "title", None),
        getattr(rule, "id", None),
    }
    return {str(identifier) for identifier in identifiers if identifier is not None}


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")


LocalReplay = DualClockReplay
ReplayEngine = DualClockReplay
Replay = DualClockReplay
ReplayEntry = ReplayEvent
