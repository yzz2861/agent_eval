from __future__ import annotations

from collections.abc import Iterable
from datetime import date, datetime, time, tzinfo
from typing import Any

import attrs
from attr.validators import instance_of

from .._converters import as_date, as_time, as_timezone
from .._exceptions import MaxIterationsReached
from .._marshalling import marshal_object, unmarshal_object
from .._utils import require_state_version, timezone_repr
from ..abc import Trigger


def _as_excluded_dates(value: Iterable[date | str]) -> tuple[date, ...]:
    return tuple(as_date(item) for item in value)


def _as_time_ranges(
    value: Iterable[tuple[time | str, time | str]],
) -> tuple[tuple[time, time], ...]:
    return tuple((as_time(start), as_time(end)) for start, end in value)


def _validate_time_ranges(
    instance: ExclusionCalendarTrigger,
    attribute: attrs.Attribute,
    value: tuple[tuple[time, time], ...],
) -> None:
    for start, end in value:
        if start == end:
            raise ValueError(
                "excluded time ranges must not have equal start and end times; "
                "use excluded_dates to exclude whole days"
            )


@attrs.define
class ExclusionCalendarTrigger(Trigger):
    """
    Wraps another trigger and skips any fire times that fall on excluded dates or
    within excluded time-of-day ranges, as evaluated in the given time zone.

    This is useful for preventing a schedule from running on holidays or inside
    recurring maintenance windows.

    All exclusion checks are performed against the local wall clock time of the fire
    time, converted to ``timezone``. This has the following consequences around
    daylight saving time shifts:

    * When the wall clock time is repeated (a backward shift), both occurrences of a
      fire time are excluded if the wall clock time matches an exclusion rule.
    * When the wall clock time is skipped (a forward shift), exclusion rules covering
      the nonexistent times simply never match real fire times on that date.

    A time range where ``start < end`` covers ``[start, end)`` on the same local date.
    A time range where ``start > end`` crosses midnight, covering ``[start, 24:00)``
    and ``[00:00, end)``. Ranges where ``start == end`` are not allowed; use
    ``excluded_dates`` to exclude entire days.

    Excluded fire times are never shifted to the end of an exclusion window (which
    could produce extra, unintended runs). Instead, the wrapped trigger is asked for
    its next fire time, and that one is checked in turn. Only fire times genuinely
    produced by the wrapped trigger are ever returned.

    If the wrapped trigger is exhausted (produces no more fire times), ``None`` is
    returned. If instead ``max_iterations`` consecutive fire times are excluded,
    :exc:`~apscheduler.MaxIterationsReached` is raised, so the two cases can be told
    apart.

    :param trigger: the trigger to wrap
    :param excluded_dates: local dates (or ISO 8601 date strings) on which no fire
        time is allowed
    :param excluded_time_ranges: time-of-day ranges, as ``(start, end)`` pairs of
        :class:`~datetime.time` objects or ISO 8601 time strings, during which no
        fire time is allowed (evaluated against the local wall clock in ``timezone``)
    :param timezone: time zone used to interpret ``excluded_dates`` and
        ``excluded_time_ranges``
    :param max_iterations: maximum number of consecutive excluded fire times to skip
        before giving up
    """

    trigger: Trigger
    excluded_dates: tuple[date, ...] = attrs.field(
        converter=_as_excluded_dates, factory=tuple
    )
    excluded_time_ranges: tuple[tuple[time, time], ...] = attrs.field(
        converter=_as_time_ranges, validator=_validate_time_ranges, factory=tuple
    )
    timezone: tzinfo = attrs.field(
        converter=as_timezone, validator=instance_of(tzinfo), default="local"
    )
    max_iterations: int = 1000

    def next(self) -> datetime | None:
        for _ in range(self.max_iterations):
            fire_time = self.trigger.next()
            if fire_time is None:
                return None

            if not self._is_excluded(fire_time):
                return fire_time

        raise MaxIterationsReached(
            f"{self.__class__.__name__} skipped {self.max_iterations} consecutive "
            f"excluded fire times without finding a valid one"
        )

    def _is_excluded(self, fire_time: datetime) -> bool:
        local_datetime = fire_time.astimezone(self.timezone)
        if local_datetime.date() in self.excluded_dates:
            return True

        local_time = local_datetime.time()
        for start, end in self.excluded_time_ranges:
            if start < end:
                if start <= local_time < end:
                    return True
            elif local_time >= start or local_time < end:
                return True

        return False

    def __getstate__(self) -> dict[str, Any]:
        return {
            "version": 1,
            "trigger": marshal_object(self.trigger),
            "excluded_dates": list(self.excluded_dates),
            "excluded_time_ranges": [
                [start.isoformat(), end.isoformat()]
                for start, end in self.excluded_time_ranges
            ],
            "timezone": self.timezone,
            "max_iterations": self.max_iterations,
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        require_state_version(self, state, 1)
        self.trigger = unmarshal_object(*state["trigger"])
        self.excluded_dates = state["excluded_dates"]
        self.excluded_time_ranges = state["excluded_time_ranges"]
        self.timezone = state["timezone"]
        self.max_iterations = state["max_iterations"]

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.trigger!r}, "
            f"excluded_dates={[d.isoformat() for d in self.excluded_dates]}, "
            f"excluded_time_ranges={self.excluded_time_ranges}, "
            f"timezone={timezone_repr(self.timezone)!r}, "
            f"max_iterations={self.max_iterations})"
        )
