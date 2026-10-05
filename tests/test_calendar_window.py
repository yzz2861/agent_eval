from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from limits.aio.storage import MemoryStorage as AsyncMemoryStorage
from limits.aio.strategies import CalendarWindowRateLimiter as AsyncCalendarLimiter
from limits.calendar import get_calendar_window
from limits.limits import (
    RateLimitItemPerDay,
    RateLimitItemPerHour,
    RateLimitItemPerMonth,
)
from limits.storage import MemoryStorage
from limits.strategies import CalendarWindowRateLimiter


class FrozenClock:
    def __init__(self, timestamp: float):
        self.timestamp = timestamp

    def __call__(self) -> float:
        return self.timestamp


class UnsupportedSyncStorage:
    pass


class UnsupportedAsyncStorage:
    pass


def test_calendar_boundaries_use_local_dst_and_calendar_length():
    new_york = ZoneInfo("America/New_York")
    shanghai = ZoneInfo("Asia/Shanghai")

    start, end = get_calendar_window(
        datetime(2024, 3, 10, 12, tzinfo=new_york).timestamp(),
        new_york,
        "day",
    )
    assert end - start == 23 * 60 * 60

    start, end = get_calendar_window(
        datetime(2024, 2, 10, tzinfo=shanghai).timestamp(),
        shanghai,
        "month",
    )
    assert end - start == 29 * 24 * 60 * 60


def test_day_window_includes_both_sides_of_dst_spring_forward():
    zone_name = "America/New_York"
    zone = ZoneInfo(zone_name)
    before_spring_forward = datetime(2024, 3, 10, 1, 59, 58, tzinfo=zone)
    after_spring_forward = datetime(2024, 3, 10, 3, 0, 2, fold=0, tzinfo=zone)
    clock = FrozenClock(before_spring_forward.timestamp())
    storage = MemoryStorage(clock=clock)
    limiter = CalendarWindowRateLimiter(storage, zone_name)
    limit = RateLimitItemPerDay(2)

    assert limiter.hit(limit)
    clock.timestamp = after_spring_forward.timestamp()
    assert limiter.hit(limit)
    assert not limiter.test(limit)
    stats = limiter.get_window_stats(limit)
    assert stats.remaining == 0
    assert stats.reset_time == datetime(2024, 3, 11, tzinfo=zone).timestamp()


def test_month_window_splits_last_second_from_first_next_second():
    zone_name = "Asia/Shanghai"
    zone = ZoneInfo(zone_name)
    february_last_second = datetime(2024, 2, 29, 23, 59, 59, tzinfo=zone)
    march_first_second = datetime(2024, 3, 1, 0, 0, 1, tzinfo=zone)
    clock = FrozenClock(february_last_second.timestamp())
    storage = MemoryStorage(clock=clock)
    limiter = CalendarWindowRateLimiter(storage, zone_name)
    limit = RateLimitItemPerMonth(1)

    assert limiter.hit(limit)
    assert not limiter.test(limit)
    clock.timestamp = march_first_second.timestamp()
    assert limiter.test(limit)
    assert limiter.hit(limit)
    stats = limiter.get_window_stats(limit)
    assert stats.remaining == 0
    assert stats.reset_time == datetime(2024, 4, 1, tzinfo=zone).timestamp()


def test_calendar_window_expires_at_window_end():
    zone_name = "UTC"
    clock = FrozenClock(1_704_067_199.0)
    storage = MemoryStorage(clock=clock)
    limiter = CalendarWindowRateLimiter(storage, zone_name)
    limit = RateLimitItemPerDay(1)

    assert limiter.hit(limit)
    clock.timestamp = 1_704_067_199.999
    assert not limiter.test(limit)
    clock.timestamp = 1_704_067_200.0
    assert limiter.test(limit)
    assert storage.get_calendar_window(
        limit.key_for(), "day", zone_name
    ) == (1_704_067_200.0, 1_704_153_600.0, 0)


def test_rejects_unsupported_granularity_and_multiples():
    storage = MemoryStorage(clock=FrozenClock(0))
    limiter = CalendarWindowRateLimiter(storage, "UTC")

    with pytest.raises(ValueError):
        limiter.hit(RateLimitItemPerHour(1))
    with pytest.raises(ValueError):
        limiter.hit(RateLimitItemPerDay(1, 2))


def test_rejects_unsupported_sync_storage():
    with pytest.raises(NotImplementedError):
        CalendarWindowRateLimiter(UnsupportedSyncStorage(), "UTC")


def test_rejects_invalid_timezone():
    with pytest.raises(ValueError):
        CalendarWindowRateLimiter(
            MemoryStorage(clock=FrozenClock(0)), "Mars/Olympus"
        )


def test_rejects_fixed_utc_offset_timezone():
    with pytest.raises(ValueError):
        CalendarWindowRateLimiter(
            MemoryStorage(clock=FrozenClock(0)), timezone.utc
        )


async def test_async_calendar_window_storage():
    zone_name = "America/New_York"
    before = 1_710_053_998.0
    after = 1_710_054_002.0
    clock = FrozenClock(before)
    storage = AsyncMemoryStorage(clock=clock)
    limiter = AsyncCalendarLimiter(storage, zone_name)
    limit = RateLimitItemPerDay(2)

    assert await limiter.hit(limit)
    clock.timestamp = after
    assert await limiter.hit(limit)
    assert not await limiter.test(limit)
    stats = await limiter.get_window_stats(limit)
    assert stats.reset_time == 1_710_129_600.0
    assert stats.remaining == 0

    clock.timestamp = 1_710_129_600.0
    assert await limiter.test(limit)


async def test_async_rejects_unsupported_storage():
    with pytest.raises(NotImplementedError):
        AsyncCalendarLimiter(UnsupportedAsyncStorage(), "UTC")


async def test_async_rejects_invalid_timezone():
    with pytest.raises(ValueError):
        AsyncCalendarLimiter(AsyncMemoryStorage(clock=FrozenClock(0)), "Mars/Olympus")


async def test_async_rejects_fixed_utc_offset_timezone():
    with pytest.raises(ValueError):
        AsyncCalendarLimiter(
            AsyncMemoryStorage(clock=FrozenClock(0)), timezone.utc
        )
