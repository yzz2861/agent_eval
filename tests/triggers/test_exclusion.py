from __future__ import annotations

from datetime import date, datetime, time

import pytest

from apscheduler import MaxIterationsReached
from apscheduler.triggers.combining import AndTrigger, OrTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.exclusion import ExclusionCalendarTrigger
from apscheduler.triggers.interval import IntervalTrigger


class TestExclusionCalendarTrigger:
    def test_excluded_date(self, timezone, serializer):
        trigger = ExclusionCalendarTrigger(
            CronTrigger(hour=9, start_time=datetime(2024, 5, 1), timezone=timezone),
            excluded_dates=[date(2024, 5, 2)],
            timezone=timezone,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() == datetime(2024, 5, 1, 9, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 5, 3, 9, tzinfo=timezone)

    def test_excluded_time_range(self, timezone, serializer):
        trigger = ExclusionCalendarTrigger(
            IntervalTrigger(
                hours=1, start_time=datetime(2024, 5, 1, 6, tzinfo=timezone)
            ),
            excluded_time_ranges=[(time(8), time(10))],
            timezone=timezone,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() == datetime(2024, 5, 1, 6, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 5, 1, 7, tzinfo=timezone)
        # 08:00 and 09:00 are excluded; the next fire time is the wrapped
        # trigger's next genuine fire time (10:00), not the end of the window
        assert trigger.next() == datetime(2024, 5, 1, 10, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 5, 1, 11, tzinfo=timezone)

    def test_cross_midnight_time_range(self, timezone, serializer):
        trigger = ExclusionCalendarTrigger(
            IntervalTrigger(
                hours=1, start_time=datetime(2024, 5, 1, 20, tzinfo=timezone)
            ),
            excluded_time_ranges=[(time(22), time(2))],
            timezone=timezone,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() == datetime(2024, 5, 1, 20, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 5, 1, 21, tzinfo=timezone)
        # 22:00 - 01:59 are excluded; 02:00 is the end of the window (exclusive)
        assert trigger.next() == datetime(2024, 5, 2, 2, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 5, 2, 3, tzinfo=timezone)

    def test_string_values(self, timezone, serializer):
        trigger = ExclusionCalendarTrigger(
            CronTrigger(hour=9, start_time=datetime(2024, 5, 1), timezone=timezone),
            excluded_dates=["2024-05-02"],
            excluded_time_ranges=[("08:00", "10:30:15")],
            timezone=timezone,
        )
        assert trigger.excluded_dates == (date(2024, 5, 2),)
        assert trigger.excluded_time_ranges == ((time(8), time(10, 30, 15)),)

    def test_equal_start_and_end_rejected(self, timezone):
        with pytest.raises(ValueError, match="must not have equal start and end"):
            ExclusionCalendarTrigger(
                CronTrigger(hour=9, timezone=timezone),
                excluded_time_ranges=[(time(2), time(2))],
                timezone=timezone,
            )

    def test_exhaustion_returns_none(self, timezone, serializer):
        # The wrapped trigger is exhausted after its only fire time is excluded,
        # so None is returned instead of raising MaxIterationsReached
        trigger = ExclusionCalendarTrigger(
            DateTrigger(datetime(2024, 5, 2, 9, tzinfo=timezone)),
            excluded_dates=[date(2024, 5, 2)],
            timezone=timezone,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() is None

    def test_max_iterations_reached(self, timezone, serializer):
        trigger = ExclusionCalendarTrigger(
            IntervalTrigger(hours=1, start_time=datetime(2024, 5, 1, tzinfo=timezone)),
            excluded_time_ranges=[(time(0), time(23, 59, 59, 999999))],
            timezone=timezone,
            max_iterations=5,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        pytest.raises(MaxIterationsReached, trigger.next)

    def test_dst_backward_shift(self, timezone, serializer):
        # On 2024-10-27, 02:30 occurs twice in Europe/Berlin; both occurrences
        # must be excluded since the window matches the local wall clock time
        trigger = ExclusionCalendarTrigger(
            CronTrigger(
                hour="2,4",
                minute=30,
                start_time=datetime(2024, 10, 26),
                timezone=timezone,
            ),
            excluded_time_ranges=[(time(2), time(3))],
            timezone=timezone,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() == datetime(2024, 10, 26, 4, 30, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 10, 27, 4, 30, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 10, 28, 4, 30, tzinfo=timezone)

    def test_dst_forward_shift(self, timezone, serializer):
        # On 2025-03-30, 02:30 does not exist in Europe/Berlin; the wrapped cron
        # trigger skips it and the window simply never matches anything that day
        trigger = ExclusionCalendarTrigger(
            CronTrigger(
                hour="2,4",
                minute=30,
                start_time=datetime(2025, 3, 29),
                timezone=timezone,
            ),
            excluded_time_ranges=[(time(2), time(3))],
            timezone=timezone,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() == datetime(2025, 3, 29, 4, 30, tzinfo=timezone)
        assert trigger.next() == datetime(2025, 3, 30, 4, 30, tzinfo=timezone)
        assert trigger.next() == datetime(2025, 3, 31, 4, 30, tzinfo=timezone)

    def test_serialization_round_trip_same_sequence(self, timezone, serializer):
        if not serializer:
            pytest.skip("serializer fixture required")

        def make_trigger():
            return ExclusionCalendarTrigger(
                CronTrigger(hour=9, start_time=datetime(2024, 5, 1), timezone=timezone),
                excluded_dates=[date(2024, 5, 3)],
                excluded_time_ranges=[(time(1), time(3))],
                timezone=timezone,
            )

        original = make_trigger()
        assert original.next() == datetime(2024, 5, 1, 9, tzinfo=timezone)

        # Restore from the serialized state mid-sequence; the restored trigger
        # must produce the exact same subsequent fire times
        restored = serializer.deserialize(serializer.serialize(original))
        for _ in range(4):
            assert restored.next() == original.next()

    def test_and_trigger_combination(self, timezone, serializer):
        start_time = datetime(2024, 5, 1, tzinfo=timezone)
        trigger = AndTrigger(
            [
                ExclusionCalendarTrigger(
                    CronTrigger(hour=10, start_time=start_time, timezone=timezone),
                    excluded_dates=[date(2024, 5, 2)],
                    timezone=timezone,
                ),
                CronTrigger(hour=10, start_time=start_time, timezone=timezone),
            ]
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() == datetime(2024, 5, 1, 10, tzinfo=timezone)
        assert trigger.next() == datetime(2024, 5, 3, 10, tzinfo=timezone)

    def test_or_trigger_combination(self, timezone, serializer):
        trigger = OrTrigger(
            [
                DateTrigger(datetime(2024, 5, 1, 12, tzinfo=timezone)),
                ExclusionCalendarTrigger(
                    DateTrigger(datetime(2024, 5, 2, 12, tzinfo=timezone)),
                    excluded_dates=[date(2024, 5, 2)],
                    timezone=timezone,
                ),
            ]
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert trigger.next() == datetime(2024, 5, 1, 12, tzinfo=timezone)
        assert trigger.next() is None

    def test_repr(self, timezone, serializer):
        trigger = ExclusionCalendarTrigger(
            CronTrigger(hour=9, start_time=datetime(2024, 5, 1), timezone=timezone),
            excluded_dates=[date(2024, 5, 2)],
            excluded_time_ranges=[(time(1), time(3))],
            timezone=timezone,
        )
        if serializer:
            trigger = serializer.deserialize(serializer.serialize(trigger))

        assert repr(trigger) == (
            "ExclusionCalendarTrigger(CronTrigger(year='*', month='*', day='*', "
            "week='*', day_of_week='*', hour='9', minute='0', second='0', "
            "start_time='2024-05-01T00:00:00+02:00', timezone='Europe/Berlin'), "
            "excluded_dates=['2024-05-02'], "
            "excluded_time_ranges=((datetime.time(1, 0), datetime.time(3, 0)),), "
            "timezone='Europe/Berlin', max_iterations=1000)"
        )
