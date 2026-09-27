from __future__ import annotations

from collections.abc import Iterable
from datetime import date, datetime, time, tzinfo
from typing import Any

import attrs
from attr.validators import instance_of

from .._converters import as_date, as_timezone
from .._exceptions import MaxIterationsReached
from .._marshalling import marshal_object, unmarshal_object
from .._utils import require_state_version, timezone_repr
from ..abc import Trigger


def as_time(value: time | str) -> time:
    if isinstance(value, str):
        return time.fromisoformat(value)

    return value


def _as_exclude_dates(value: Iterable[date | str]) -> frozenset[date]:
    return frozenset(as_date(item) for item in value)


def _as_exclude_time_ranges(
    value: Iterable[tuple[time | str, time | str]],
) -> tuple[tuple[time, time], ...]:
    return tuple((as_time(start), as_time(end)) for start, end in value)


@attrs.define(kw_only=True)
class ExclusionCalendarTrigger(Trigger):
    """
    Wraps another trigger and skips any fire times that fall within an exclusion
    calendar (holidays, maintenance windows, etc).

    The exclusion rules are always evaluated against the wall clock of the
    calendar's time zone (``timezone``), regardless of the time zone of the
    wrapped trigger:

    * ``exclude_dates`` excludes entire local dates (midnight to midnight)
    * ``exclude_time_ranges`` excludes recurring daily windows, where the start
      time is inclusive and the end time is exclusive. A range whose start time
      is later than its end time crosses midnight (for example,
      ``(time(22), time(6))`` excludes 22:00:00 up to, but not including,
      06:00:00 the next day)

    Daylight saving time semantics follow directly from the wall clock
    comparison:

    * On a forward DST shift, the skipped wall clock times never occur, so the
      part of an exclusion range falling into the gap simply excludes nothing
      on that date
    * On a backward DST shift, ambiguous wall clock times occur twice, and
      **both** occurrences are excluded if they fall within an exclusion range

    Excluded fire times are *skipped*, never moved: the wrapped trigger is
    asked for its own next fire time, so no extra executions are created at the
    end of an exclusion window. If the wrapped trigger is exhausted (produces
    no more fire times), ``None`` is returned. If too many consecutive fire
    times are excluded, :class:`~apscheduler.MaxIterationsReached` is raised
    instead, so a search that gave up due to the iteration limit can be told
    apart from an exhausted trigger.

    :param trigger: the trigger to wrap
    :param exclude_dates: local dates (in ``timezone``) on which no fire time
        is allowed
    :param exclude_time_ranges: daily time ranges (as ``(start, end)`` pairs
        of :class:`~datetime.time` objects or ISO 8601 strings) during which
        no fire time is allowed
    :param timezone: time zone of the exclusion calendar (defaults to the
        local time zone)
    :param max_search_iterations: maximum number of candidate fire times to
        examine in a single :meth:`next` call before giving up
    """

    trigger: Trigger = attrs.field(validator=instance_of(Trigger))
    exclude_dates: frozenset[date] = attrs.field(
        converter=_as_exclude_dates, factory=frozenset
    )
    exclude_time_ranges: tuple[tuple[time, time], ...] = attrs.field(
        converter=_as_exclude_time_ranges, factory=tuple
    )
    timezone: tzinfo = attrs.field(
        converter=as_timezone, validator=instance_of(tzinfo), default="local"
    )
    max_search_iterations: int = 1000

    def __attrs_post_init__(self) -> None:
        for start, end in self.exclude_time_ranges:
            if start.tzinfo is not None or end.tzinfo is not None:
                raise ValueError("exclusion time ranges must use naive time objects")
            if start == end:
                raise ValueError(
                    "exclusion time ranges must not have equal start and end times"
                )

        if self.max_search_iterations < 1:
            raise ValueError("max_search_iterations must be at least 1")

    def _is_excluded(self, fire_time: datetime) -> bool:
        local_fire_time = fire_time.astimezone(self.timezone)
        if local_fire_time.date() in self.exclude_dates:
            return True

        wall_time = local_fire_time.time()
        for start, end in self.exclude_time_ranges:
            if start < end:
                if start <= wall_time < end:
                    return True
            elif wall_time >= start or wall_time < end:
                return True

        return False

    def next(self) -> datetime | None:
        for _ in range(self.max_search_iterations):
            fire_time = self.trigger.next()
            if fire_time is None:
                return None

            if not self._is_excluded(fire_time):
                return fire_time

        raise MaxIterationsReached(
            f"{self.__class__.__name__} could not find a fire time outside"
            f" the exclusion calendar within {self.max_search_iterations}"
            " iterations"
        )

    def __getstate__(self) -> dict[str, Any]:
        return {
            "version": 1,
            "trigger": marshal_object(self.trigger),
            "exclude_dates": sorted(self.exclude_dates),
            "exclude_time_ranges": [
                [start.isoformat(), end.isoformat()]
                for start, end in self.exclude_time_ranges
            ],
            "timezone": self.timezone,
            "max_search_iterations": self.max_search_iterations,
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        require_state_version(self, state, 1)
        self.trigger = unmarshal_object(*state["trigger"])
        self.exclude_dates = state["exclude_dates"]
        self.exclude_time_ranges = state["exclude_time_ranges"]
        self.timezone = state["timezone"]
        self.max_search_iterations = state["max_search_iterations"]

    def __repr__(self) -> str:
        fields = [repr(self.trigger)]
        if self.exclude_dates:
            fields.append(
                "exclude_dates="
                + str([d.isoformat() for d in sorted(self.exclude_dates)])
            )
        if self.exclude_time_ranges:
            fields.append(
                "exclude_time_ranges=["
                + ", ".join(
                    f"({start.isoformat()!r}, {end.isoformat()!r})"
                    for start, end in self.exclude_time_ranges
                )
                + "]"
            )

        fields.append(f"timezone={timezone_repr(self.timezone)!r}")
        fields.append(f"max_search_iterations={self.max_search_iterations}")
        return f"{self.__class__.__name__}({', '.join(fields)})"
