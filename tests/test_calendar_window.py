from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pytest

from limits.aio.storage import MemoryStorage as AsyncMemoryStorage
from limits.aio.storage.base import Storage as AsyncStorage
from limits.aio.strategies import (
    CalendarWindowRateLimiter as AsyncCalendarWindowRateLimiter,
)
from limits.calendar import calendar_window
from limits.limits import (
    RateLimitItemPerCalendarDay,
    RateLimitItemPerCalendarMonth,
    RateLimitItemPerDay,
)
from limits.storage import MemoryStorage
from limits.storage.base import Storage
from limits.strategies import CalendarWindowRateLimiter


def ts(local: str, timezone: str) -> float:
    """UTC epoch seconds for a naive local datetime string in a timezone"""
    return datetime.fromisoformat(local).replace(tzinfo=ZoneInfo(timezone)).timestamp()


class FakeClock:
    def __init__(self, now: float):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def set(self, now: float) -> None:
        self.now = now


class UnsupportedStorage(Storage):
    """A storage without calendar window support"""

    STORAGE_SCHEME = None

    @property
    def base_exceptions(self):
        return ValueError

    def incr(self, key, expiry, amount=1):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

    def get_expiry(self, key):
        raise NotImplementedError

    def check(self):
        return True

    def reset(self):
        return None

    def clear(self, key):
        pass


class UnsupportedAsyncStorage(AsyncStorage):
    """An async storage without calendar window support"""

    STORAGE_SCHEME = None

    @property
    def base_exceptions(self):
        return ValueError

    async def incr(self, key, expiry, amount=1):
        raise NotImplementedError

    async def get(self, key):
        raise NotImplementedError

    async def get_expiry(self, key):
        raise NotImplementedError

    async def check(self):
        return True

    async def reset(self):
        return None

    async def clear(self, key):
        pass


class TestCalendarWindowComputation:
    def test_day_window_utc(self):
        window = calendar_window(
            "day", ZoneInfo("UTC"), ts("2026-10-05T15:30:00", "UTC")
        )
        assert window.key == "2026-10-05"
        assert window.start == ts("2026-10-05T00:00:00", "UTC")
        assert window.end == ts("2026-10-06T00:00:00", "UTC")
        assert window.end - window.start == 24 * 3600

    def test_day_window_uses_local_date_not_utc(self):
        tz = ZoneInfo("America/New_York")
        # 2026-10-05 02:00 UTC is still 2026-10-04 22:00 in New York
        window = calendar_window("day", tz, ts("2026-10-05T02:00:00", "UTC"))
        assert window.key == "2026-10-04"
        assert window.start == ts("2026-10-04T00:00:00", "America/New_York")
        assert window.end == ts("2026-10-05T00:00:00", "America/New_York")

    def test_dst_spring_forward_same_bucket(self):
        tz = ZoneInfo("America/New_York")
        # 2026-03-08: clocks jump from 01:59:59 EST to 03:00:00 EDT
        before = calendar_window(
            "day", tz, ts("2026-03-08T01:59:59", "America/New_York")
        )
        after = calendar_window(
            "day", tz, ts("2026-03-08T03:00:01", "America/New_York")
        )
        assert before == after
        assert before.key == "2026-03-08"
        # the day only lasts 23 hours in UTC, not a fixed 86400 seconds
        assert before.end - before.start == 23 * 3600
        # the previous and next days are different buckets
        assert (
            calendar_window(
                "day", tz, ts("2026-03-07T23:59:59", "America/New_York")
            ).key
            == "2026-03-07"
        )
        assert (
            calendar_window(
                "day", tz, ts("2026-03-09T00:00:00", "America/New_York")
            ).key
            == "2026-03-09"
        )
        # windows are exactly adjacent
        assert (
            calendar_window(
                "day", tz, ts("2026-03-09T12:00:00", "America/New_York")
            ).start
            == before.end
        )

    def test_dst_fall_back_same_bucket(self):
        tz = ZoneInfo("America/New_York")
        # 2026-11-01: clocks fall back from 02:00 EDT to 01:00 EST
        before = calendar_window(
            "day", tz, ts("2026-11-01T00:30:00", "America/New_York")
        )
        after = calendar_window(
            "day", tz, ts("2026-11-01T23:30:00", "America/New_York")
        )
        assert before == after
        # the day lasts 25 hours in UTC
        assert before.end - before.start == 25 * 3600

    def test_dst_transition_at_midnight(self):
        tz = ZoneInfo("America/Santiago")
        # 2026-09-06: Chile springs forward at midnight, 00:00 does not exist
        window = calendar_window(
            "day", tz, ts("2026-09-06T12:00:00", "America/Santiago")
        )
        assert window.key == "2026-09-06"
        assert window.end - window.start == 23 * 3600
        assert (
            calendar_window(
                "day", tz, ts("2026-09-05T23:30:00", "America/Santiago")
            ).key
            == "2026-09-05"
        )
        assert (
            calendar_window(
                "day", tz, ts("2026-09-06T01:30:00", "America/Santiago")
            ).key
            == "2026-09-06"
        )

    def test_month_boundary_last_and_first_second(self):
        tz = ZoneInfo("Asia/Shanghai")
        last = calendar_window(
            "month", tz, ts("2026-01-31T23:59:59.999999", "Asia/Shanghai")
        )
        first = calendar_window("month", tz, ts("2026-02-01T00:00:00", "Asia/Shanghai"))
        assert last.key == "2026-01"
        assert first.key == "2026-02"
        assert last.end == first.start
        assert last.end == ts("2026-02-01T00:00:00", "Asia/Shanghai")

    def test_month_lengths_and_leap_years(self):
        tz = ZoneInfo("Asia/Shanghai")
        assert (
            calendar_window("month", tz, ts("2026-02-15T00:00:00", "Asia/Shanghai")).end
            - calendar_window(
                "month", tz, ts("2026-02-15T00:00:00", "Asia/Shanghai")
            ).start
            == 28 * 86400
        )
        leap = calendar_window("month", tz, ts("2028-02-29T23:59:59", "Asia/Shanghai"))
        assert leap.key == "2028-02"
        assert leap.end - leap.start == 29 * 86400
        assert (
            calendar_window("month", tz, ts("2028-03-01T00:00:00", "Asia/Shanghai")).key
            == "2028-03"
        )
        april = calendar_window("month", tz, ts("2026-04-15T00:00:00", "Asia/Shanghai"))
        assert april.end - april.start == 30 * 86400
        # year boundary
        assert (
            calendar_window("month", tz, ts("2026-12-31T23:59:59", "Asia/Shanghai")).key
            == "2026-12"
        )
        assert (
            calendar_window("month", tz, ts("2027-01-01T00:00:00", "Asia/Shanghai")).key
            == "2027-01"
        )

    def test_non_integral_utc_offset(self):
        tz = ZoneInfo("Asia/Kathmandu")  # UTC+05:45
        assert (
            calendar_window("day", tz, ts("2026-10-05T23:59:59", "Asia/Kathmandu")).key
            == "2026-10-05"
        )
        assert (
            calendar_window("day", tz, ts("2026-10-06T00:00:00", "Asia/Kathmandu")).key
            == "2026-10-06"
        )
        window = calendar_window("day", tz, ts("2026-10-05T12:00:00", "Asia/Kathmandu"))
        assert window.start == ts("2026-10-05T00:00:00", "Asia/Kathmandu")
        assert window.end - window.start == 24 * 3600

    def test_multiples(self):
        tz = ZoneInfo("Asia/Shanghai")
        # quarterly windows
        window = calendar_window(
            "month", tz, ts("2026-05-20T10:00:00", "Asia/Shanghai"), 3
        )
        assert window.key == "2026-04"
        assert window.start == ts("2026-04-01T00:00:00", "Asia/Shanghai")
        assert window.end == ts("2026-07-01T00:00:00", "Asia/Shanghai")
        # two day windows
        window = calendar_window(
            "day", ZoneInfo("UTC"), ts("2026-10-05T12:00:00", "UTC"), 2
        )
        assert window.start == ts("2026-10-04T00:00:00", "UTC")
        assert window.end == ts("2026-10-06T00:00:00", "UTC")

    def test_invalid_period(self):
        with pytest.raises(ValueError):
            calendar_window("week", ZoneInfo("UTC"), ts("2026-10-05T12:00:00", "UTC"))

    def test_invalid_multiples(self):
        with pytest.raises(ValueError):
            calendar_window("day", ZoneInfo("UTC"), ts("2026-10-05T12:00:00", "UTC"), 0)


class TestCalendarWindowItems:
    def test_invalid_timezone(self):
        with pytest.raises(ZoneInfoNotFoundError):
            RateLimitItemPerCalendarDay(1, timezone="Not/AZone")

    def test_no_fixed_expiry(self):
        with pytest.raises(NotImplementedError):
            RateLimitItemPerCalendarDay(1).get_expiry()
        with pytest.raises(NotImplementedError):
            RateLimitItemPerCalendarMonth(1).get_expiry()

    def test_equality_includes_timezone(self):
        assert RateLimitItemPerCalendarDay(1) == RateLimitItemPerCalendarDay(1)
        assert RateLimitItemPerCalendarDay(1) != RateLimitItemPerCalendarDay(
            1, timezone="Asia/Shanghai"
        )
        assert RateLimitItemPerCalendarDay(1) != RateLimitItemPerCalendarMonth(1)
        assert RateLimitItemPerCalendarDay(1) != RateLimitItemPerDay(1)

    def test_key_for(self):
        item = RateLimitItemPerCalendarMonth(5, timezone="Asia/Shanghai")
        assert item.key_for("user1") == "LIMITER/user1/5/1/calendar-month"

    def test_repr(self):
        assert "1 per 1 calendar-day (UTC)" in str(RateLimitItemPerCalendarDay(1))


class TestCalendarWindowRateLimiter:
    def test_hits_share_bucket_across_dst_transition(self):
        clock = FakeClock(ts("2026-03-08T01:00:00", "America/New_York"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(2, timezone="America/New_York")
        assert limiter.hit(limit)
        # spring forward happens in between: 01:59:59 EST -> 03:00:00 EDT
        clock.set(ts("2026-03-08T03:30:00", "America/New_York"))
        assert limiter.hit(limit)
        # both hits landed in the same local day: limit is now exhausted
        assert not limiter.hit(limit)
        assert not limiter.test(limit)

    def test_window_expires_at_window_end(self):
        clock = FakeClock(ts("2026-03-08T01:00:00", "America/New_York"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(1, timezone="America/New_York")
        assert limiter.hit(limit)
        assert not limiter.hit(limit)
        # the window ends at local midnight (EDT), 23 hours later in UTC
        clock.set(ts("2026-03-09T00:00:00", "America/New_York"))
        assert limiter.hit(limit)
        stats = limiter.get_window_stats(limit)
        assert stats.remaining == 0
        assert stats.reset_time == ts("2026-03-10T00:00:00", "America/New_York")

    def test_month_boundary_exact_split(self):
        clock = FakeClock(ts("2026-01-31T23:59:59.999999", "Asia/Shanghai"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarMonth(1, timezone="Asia/Shanghai")
        assert limiter.hit(limit)
        assert not limiter.hit(limit)
        stats = limiter.get_window_stats(limit)
        assert stats.remaining == 0
        assert stats.reset_time == ts("2026-02-01T00:00:00", "Asia/Shanghai")
        # the very first instant of the next month belongs to a new window
        clock.set(ts("2026-02-01T00:00:00", "Asia/Shanghai"))
        assert limiter.hit(limit)
        assert not limiter.hit(limit)
        stats = limiter.get_window_stats(limit)
        assert stats.reset_time == ts("2026-03-01T00:00:00", "Asia/Shanghai")

    def test_get_window_stats(self):
        clock = FakeClock(ts("2026-10-05T08:00:00", "UTC"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(5)
        stats = limiter.get_window_stats(limit)
        assert stats.remaining == 5
        assert stats.reset_time == ts("2026-10-06T00:00:00", "UTC")
        limiter.hit(limit, cost=2)
        stats = limiter.get_window_stats(limit)
        assert stats.remaining == 3

    def test_test_does_not_consume(self):
        clock = FakeClock(ts("2026-10-05T08:00:00", "UTC"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(1)
        assert limiter.test(limit)
        assert limiter.test(limit)
        assert limiter.hit(limit)
        assert not limiter.test(limit)

    def test_cost(self):
        clock = FakeClock(ts("2026-10-05T08:00:00", "UTC"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(3)
        assert limiter.hit(limit, cost=2)
        assert not limiter.test(limit, cost=2)
        assert limiter.hit(limit)
        assert not limiter.hit(limit)

    def test_identifiers_are_isolated(self):
        clock = FakeClock(ts("2026-10-05T08:00:00", "UTC"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(1)
        assert limiter.hit(limit, "user1")
        assert not limiter.hit(limit, "user1")
        assert limiter.hit(limit, "user2")

    def test_rejects_non_calendar_item(self):
        limiter = CalendarWindowRateLimiter(MemoryStorage())
        with pytest.raises(TypeError):
            limiter.hit(RateLimitItemPerDay(1))
        with pytest.raises(TypeError):
            limiter.test(RateLimitItemPerDay(1))
        with pytest.raises(TypeError):
            limiter.get_window_stats(RateLimitItemPerDay(1))

    def test_rejects_unsupported_storage(self):
        with pytest.raises(NotImplementedError):
            CalendarWindowRateLimiter(UnsupportedStorage())

    def test_clear(self):
        clock = FakeClock(ts("2026-10-05T08:00:00", "UTC"))
        storage = MemoryStorage(clock=clock)
        limiter = CalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(1)
        assert limiter.hit(limit)
        assert not limiter.hit(limit)
        limiter.clear(limit)
        assert limiter.hit(limit)


class TestAsyncCalendarWindowRateLimiter:
    async def test_hits_share_bucket_across_dst_transition(self):
        clock = FakeClock(ts("2026-11-01T00:30:00", "America/New_York"))
        storage = AsyncMemoryStorage(clock=clock)
        limiter = AsyncCalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(2, timezone="America/New_York")
        assert await limiter.hit(limit)
        # fall back happens in between: 02:00 EDT -> 01:00 EST
        clock.set(ts("2026-11-01T02:30:00", "America/New_York"))
        assert await limiter.hit(limit)
        assert not await limiter.hit(limit)
        assert not await limiter.test(limit)

    async def test_window_expires_at_window_end(self):
        clock = FakeClock(ts("2026-11-01T00:30:00", "America/New_York"))
        storage = AsyncMemoryStorage(clock=clock)
        limiter = AsyncCalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(1, timezone="America/New_York")
        assert await limiter.hit(limit)
        assert not await limiter.hit(limit)
        # the window ends at local midnight (EST), 25 hours later in UTC
        clock.set(ts("2026-11-02T00:00:00", "America/New_York"))
        assert await limiter.hit(limit)

    async def test_month_boundary_exact_split(self):
        clock = FakeClock(ts("2028-02-29T23:59:59.999999", "Asia/Shanghai"))
        storage = AsyncMemoryStorage(clock=clock)
        limiter = AsyncCalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarMonth(1, timezone="Asia/Shanghai")
        assert await limiter.hit(limit)
        assert not await limiter.hit(limit)
        stats = await limiter.get_window_stats(limit)
        assert stats.reset_time == ts("2028-03-01T00:00:00", "Asia/Shanghai")
        clock.set(ts("2028-03-01T00:00:00", "Asia/Shanghai"))
        assert await limiter.hit(limit)

    async def test_get_window_stats_and_test(self):
        clock = FakeClock(ts("2026-10-05T08:00:00", "UTC"))
        storage = AsyncMemoryStorage(clock=clock)
        limiter = AsyncCalendarWindowRateLimiter(storage, clock=clock)
        limit = RateLimitItemPerCalendarDay(2)
        assert await limiter.test(limit)
        await limiter.hit(limit)
        stats = await limiter.get_window_stats(limit)
        assert stats.remaining == 1
        assert stats.reset_time == ts("2026-10-06T00:00:00", "UTC")

    async def test_rejects_non_calendar_item(self):
        limiter = AsyncCalendarWindowRateLimiter(AsyncMemoryStorage())
        with pytest.raises(TypeError):
            await limiter.hit(RateLimitItemPerDay(1))

    async def test_rejects_unsupported_storage(self):
        with pytest.raises(NotImplementedError):
            AsyncCalendarWindowRateLimiter(UnsupportedAsyncStorage())
