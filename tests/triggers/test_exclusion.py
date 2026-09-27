from __future__ import annotations

from datetime import date, datetime, time
from zoneinfo import ZoneInfo

import pytest

from apscheduler import MaxIterationsReached
from apscheduler.triggers.combining import AndTrigger, OrTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.exclusion import ExclusionCalendarTrigger
from apscheduler.triggers.interval import IntervalTrigger

berlin = ZoneInfo("Europe/Berlin")
utc = ZoneInfo("UTC")


def test_exclude_date(serializer):
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(hour=9, start_time=datetime(2026, 3, 27), timezone=berlin),
        exclude_dates={date(2026, 3, 28), date(2026, 3, 29)},
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    assert trigger.next() == datetime(2026, 3, 27, 9, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 30, 9, tzinfo=berlin)


def test_exclude_time_range_same_day(serializer):
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(
            hour="8,9,10,11", start_time=datetime(2026, 3, 27), timezone=berlin
        ),
        exclude_time_ranges=[(time(9), time(11))],
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    assert trigger.next() == datetime(2026, 3, 27, 8, tzinfo=berlin)
    # 09:00 and 10:00 are excluded, and no fire time is created at the end of
    # the window (11:00 was already scheduled by the wrapped trigger anyway)
    assert trigger.next() == datetime(2026, 3, 27, 11, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 28, 8, tzinfo=berlin)


def test_exclude_time_range_crossing_midnight(serializer):
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(
            hour="21,22,23,5,6", start_time=datetime(2026, 3, 27), timezone=berlin
        ),
        exclude_time_ranges=[(time(22), time(6))],
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    # 22:00, 23:00 and 05:00 are excluded; the end of the range is exclusive
    assert trigger.next() == datetime(2026, 3, 27, 6, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 27, 21, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 28, 6, tzinfo=berlin)


def test_excluded_fire_time_is_skipped_not_moved(serializer):
    # The 09:00 fire time is excluded every day, so it must be skipped entirely
    # instead of being moved to the end of the exclusion window (10:00), which
    # would create an execution the wrapped trigger never scheduled
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(
            hour="9,12", start_time=datetime(2026, 3, 27), timezone=berlin
        ),
        exclude_time_ranges=[(time(8), time(10))],
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    assert trigger.next() == datetime(2026, 3, 27, 12, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 28, 12, tzinfo=berlin)


def test_calendar_timezone_differs_from_trigger_timezone(serializer):
    # The wrapped trigger fires at 23:30 UTC, which is 00:30/01:30 in Berlin
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(
            hour=23, minute=30, start_time=datetime(2026, 3, 27), timezone=utc
        ),
        exclude_time_ranges=[(time(0), time(3))],
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    # All the 23:30 UTC fire times are excluded in the Berlin calendar, so the
    # trigger keeps searching and hits the iteration limit
    trigger.max_search_iterations = 3
    pytest.raises(MaxIterationsReached, trigger.next)


def test_dst_forward_shift_gap_excludes_nothing(serializer):
    # On 2026-03-29, the wall clock times 02:00-02:59 do not exist in Berlin
    trigger = ExclusionCalendarTrigger(
        trigger=IntervalTrigger(
            hours=1, start_time=datetime(2026, 3, 29, 0, 0, tzinfo=berlin)
        ),
        exclude_time_ranges=[(time(2), time(3))],
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    assert trigger.next() == datetime(2026, 3, 29, 0, 0, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 29, 1, 0, tzinfo=berlin)
    # 02:00 does not exist; the next real fire time is 03:00 and is not excluded
    assert trigger.next() == datetime(2026, 3, 29, 3, 0, tzinfo=berlin)


def test_dst_backward_shift_excludes_both_folds(serializer):
    # On 2026-10-25, the wall clock times 02:00-02:59 occur twice in Berlin
    # (at 00:00 UTC and 01:00 UTC), and both occurrences must be excluded
    trigger = ExclusionCalendarTrigger(
        trigger=IntervalTrigger(
            hours=1, start_time=datetime(2026, 10, 24, 22, 0, tzinfo=utc)
        ),
        exclude_time_ranges=[(time(2), time(3))],
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    assert trigger.next() == datetime(2026, 10, 24, 22, 0, tzinfo=utc)
    assert trigger.next() == datetime(2026, 10, 24, 23, 0, tzinfo=utc)
    next_time = trigger.next()
    assert next_time == datetime(2026, 10, 25, 2, 0, tzinfo=utc)
    assert next_time.astimezone(berlin).utcoffset().total_seconds() == 3600


def test_exhausted_wrapped_trigger_returns_none(serializer):
    trigger = ExclusionCalendarTrigger(
        trigger=DateTrigger(datetime(2026, 3, 29, 9, tzinfo=berlin)),
        exclude_dates={date(2026, 3, 29)},
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    # The only fire time is excluded and the wrapped trigger is then exhausted
    assert trigger.next() is None


def test_max_search_iterations_exceeded(serializer):
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(start_time=datetime(2026, 3, 27), timezone=berlin),
        exclude_time_ranges=[(time(0), time(23, 59, 59, 999999))],
        timezone=berlin,
        max_search_iterations=5,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    pytest.raises(MaxIterationsReached, trigger.next)


def test_serialization_preserves_sequence(serializer):
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(
            hour="*/6", start_time=datetime(2026, 3, 27), timezone=berlin
        ),
        exclude_dates={date(2026, 3, 29)},
        exclude_time_ranges=[(time(22), time(6))],
        timezone=berlin,
    )
    expected = [trigger.next() for _ in range(3)]
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    expected += [trigger.next() for _ in range(3)]

    restored_trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(
            hour="*/6", start_time=datetime(2026, 3, 27), timezone=berlin
        ),
        exclude_dates={date(2026, 3, 29)},
        exclude_time_ranges=[(time(22), time(6))],
        timezone=berlin,
    )
    actual = [restored_trigger.next() for _ in range(6)]
    assert actual == expected


def test_or_trigger_composition(serializer):
    trigger = OrTrigger(
        [
            DateTrigger(datetime(2026, 3, 28, 12, tzinfo=berlin)),
            ExclusionCalendarTrigger(
                trigger=CronTrigger(
                    hour=9, start_time=datetime(2026, 3, 27), timezone=berlin
                ),
                exclude_dates={date(2026, 3, 28)},
                timezone=berlin,
            ),
        ]
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    assert trigger.next() == datetime(2026, 3, 27, 9, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 28, 12, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 29, 9, tzinfo=berlin)


def test_and_trigger_composition(serializer):
    trigger = AndTrigger(
        [
            ExclusionCalendarTrigger(
                trigger=CronTrigger(
                    hour=9, start_time=datetime(2026, 3, 27), timezone=berlin
                ),
                exclude_dates={date(2026, 3, 30)},
                timezone=berlin,
            ),
            CronTrigger(
                day_of_week="mon-fri",
                hour=9,
                start_time=datetime(2026, 3, 27),
                timezone=berlin,
            ),
        ]
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    # 2026-03-27 is a Friday; 2026-03-30 (Monday) is excluded by the calendar
    assert trigger.next() == datetime(2026, 3, 27, 9, tzinfo=berlin)
    assert trigger.next() == datetime(2026, 3, 31, 9, tzinfo=berlin)


def test_equal_range_start_and_end_rejected():
    exc = pytest.raises(
        ValueError,
        ExclusionCalendarTrigger,
        trigger=DateTrigger(datetime(2026, 3, 27, tzinfo=berlin)),
        exclude_time_ranges=[(time(9), time(9))],
    )
    exc.match("must not have equal start and end times")


def test_timezone_aware_range_rejected():
    exc = pytest.raises(
        ValueError,
        ExclusionCalendarTrigger,
        trigger=DateTrigger(datetime(2026, 3, 27, tzinfo=berlin)),
        exclude_time_ranges=[(time(9, tzinfo=berlin), time(10))],
    )
    exc.match("must use naive time objects")


def test_invalid_max_search_iterations():
    exc = pytest.raises(
        ValueError,
        ExclusionCalendarTrigger,
        trigger=DateTrigger(datetime(2026, 3, 27, tzinfo=berlin)),
        max_search_iterations=0,
    )
    exc.match("max_search_iterations must be at least 1")


def test_repr(serializer):
    trigger = ExclusionCalendarTrigger(
        trigger=CronTrigger(hour=9, start_time=datetime(2026, 3, 27), timezone=berlin),
        exclude_dates={date(2026, 3, 29)},
        exclude_time_ranges=[(time(22), time(6))],
        timezone=berlin,
    )
    if serializer:
        trigger = serializer.deserialize(serializer.serialize(trigger))

    assert repr(trigger) == (
        "ExclusionCalendarTrigger("
        "CronTrigger(year='*', month='*', day='*', week='*', day_of_week='*', "
        "hour='9', minute='0', second='0', "
        "start_time='2026-03-27T00:00:00+01:00', timezone='Europe/Berlin'), "
        "exclude_dates=['2026-03-29'], "
        "exclude_time_ranges=[('22:00:00', '06:00:00')], "
        "timezone='Europe/Berlin', max_search_iterations=1000)"
    )
