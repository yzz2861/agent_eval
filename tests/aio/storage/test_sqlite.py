from __future__ import annotations

import asyncio
import sqlite3
import time

import pytest

from limits import RateLimitItemPerMinute, RateLimitItemPerSecond
from limits.aio.storage import SQLiteStorage
from limits.aio.strategies import (
    FixedWindowRateLimiter,
    MovingWindowRateLimiter,
    SlidingWindowCounterRateLimiter,
)
from limits.storage import storage_from_string
from limits.storage.sqlite import LockTimeoutError

pytestmark = pytest.mark.sqlite


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "limits-async.sqlite")


@pytest.fixture
def storage(db_path):
    return SQLiteStorage(f"async+sqlite:///{db_path}")


class TestScheme:
    async def test_storage_from_string(self, db_path):
        storage = storage_from_string(f"async+sqlite:///{db_path}")
        assert isinstance(storage, SQLiteStorage)
        assert await storage.check()

    async def test_check_unhealthy(self, tmp_path):
        storage = SQLiteStorage(
            f"async+sqlite:///{tmp_path}/missing-dir/nested/limits.sqlite"
        )
        assert not await storage.check()


class TestFixedWindowContract:
    async def test_incr_get_expiry(self, storage):
        assert await storage.incr("key", 60) == 1
        assert await storage.incr("key", 60, 4) == 5
        assert await storage.get("key") == 5
        assert await storage.get_expiry("key") == pytest.approx(time.time() + 60)

    async def test_expiry(self, storage):
        await storage.incr("key", 1)
        assert await storage.get("key") == 1
        await asyncio.sleep(1.1)
        assert await storage.get("key") == 0

    async def test_key_isolation(self, storage):
        await storage.incr("k1", 60)
        await storage.incr("k2", 60)
        await storage.incr("k2", 60)
        assert await storage.get("k1") == 1
        assert await storage.get("k2") == 2

    async def test_clear(self, storage):
        await storage.incr("key", 60)
        await storage.clear("key")
        assert await storage.get("key") == 0

    async def test_reset(self, storage):
        for i in range(10):
            await storage.incr(f"counter-{i}", 60)
        assert await storage.reset() == 10
        assert await storage.get("counter-0") == 0

    async def test_fixed_window_strategy(self, storage):
        limiter = FixedWindowRateLimiter(storage)
        limit = RateLimitItemPerMinute(10)
        assert all([await limiter.hit(limit) for _ in range(10)])
        assert not await limiter.hit(limit)
        stats = await limiter.get_window_stats(limit)
        assert stats.remaining == 0
        assert stats.reset_time == pytest.approx(time.time() + 60, abs=1)


class TestMovingWindowContract:
    async def test_acquire_entry(self, storage):
        assert await storage.acquire_entry("key", 2, 60)
        assert await storage.acquire_entry("key", 2, 60)
        assert not await storage.acquire_entry("key", 2, 60)

    async def test_acquire_entry_amount(self, storage):
        assert not await storage.acquire_entry("key", 10, 60, amount=11)
        assert await storage.acquire_entry("key", 10, 60, amount=9)
        assert not await storage.acquire_entry("key", 10, 60, amount=2)

    async def test_get_moving_window(self, storage):
        start = time.time()
        await storage.acquire_entry("key", 2, 60)
        await storage.acquire_entry("key", 2, 60)
        window_start, count = await storage.get_moving_window("key", 2, 60)
        assert window_start == pytest.approx(start, abs=1)
        assert count == 2

    async def test_moving_window_strategy(self, storage):
        limiter = MovingWindowRateLimiter(storage)
        limit = RateLimitItemPerMinute(2)
        assert await limiter.hit(limit, "key")
        assert await limiter.hit(limit, "key")
        assert not await limiter.hit(limit, "key")
        assert (await limiter.get_window_stats(limit, "key")).remaining == 0


class TestSlidingWindowContract:
    async def test_acquire_sliding_window_entry(self, storage):
        assert await storage.acquire_sliding_window_entry("key", 2, 60)
        assert await storage.acquire_sliding_window_entry("key", 2, 60)
        assert not await storage.acquire_sliding_window_entry("key", 2, 60)

    async def test_get_sliding_window(self, storage):
        await storage.acquire_sliding_window_entry("key", 5, 60)
        (
            previous_count,
            previous_ttl,
            current_count,
            current_ttl,
        ) = await storage.get_sliding_window("key", 60)
        assert previous_count == 0
        assert previous_ttl == 0
        assert current_count == 1
        assert 60 < current_ttl <= 120

    async def test_clear_sliding_window(self, storage):
        await storage.acquire_sliding_window_entry("key", 2, 60)
        await storage.clear_sliding_window("key", 60)
        _, _, current_count, _ = await storage.get_sliding_window("key", 60)
        assert current_count == 0

    async def test_sliding_window_strategy(self, storage):
        limiter = SlidingWindowCounterRateLimiter(storage)
        limit = RateLimitItemPerSecond(2, 60)
        assert await limiter.hit(limit)
        assert await limiter.hit(limit)
        assert not await limiter.hit(limit)
        assert (await limiter.get_window_stats(limit)).remaining == 0


class TestConcurrency:
    async def test_concurrent_hits_do_not_oversell(self, storage):
        results = await asyncio.gather(
            *(storage.acquire_entry("shared", 10, 60) for _ in range(50))
        )
        assert sum(results) == 10
        assert (await storage.get_moving_window("shared", 10, 60))[1] == 10

    async def test_concurrent_incr_no_lost_updates(self, storage):
        async def incr_many():
            for _ in range(20):
                await storage.incr("counter", 60)

        await asyncio.gather(*(incr_many() for _ in range(5)))
        assert await storage.get("counter") == 100

    async def test_event_loop_not_blocked_by_database_lock(self, db_path):
        storage = SQLiteStorage(f"async+sqlite:///{db_path}", timeout=0.3)
        assert await storage.check()

        blocker = sqlite3.connect(db_path)
        blocker.execute("BEGIN IMMEDIATE")
        ticks = 0
        stop = False

        async def ticker():
            nonlocal ticks
            while not stop:
                ticks += 1
                await asyncio.sleep(0.01)

        try:
            ticker_task = asyncio.create_task(ticker())
            with pytest.raises(LockTimeoutError):
                await storage.incr("key", 60)
            stop = True
            await ticker_task
            # the event loop kept running while a worker thread
            # waited for the database lock
            assert ticks > 3
            # the failed transaction left nothing behind
            blocker.rollback()
            assert await storage.get("key") == 0
        finally:
            stop = True
            blocker.rollback()
            blocker.close()

        assert await storage.incr("key", 60) == 1
