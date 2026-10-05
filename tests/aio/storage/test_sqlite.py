from __future__ import annotations

import threading

import pytest

from limits import RateLimitItemPerSecond
from limits.aio.storage import SQLiteStorage
from limits.aio.strategies import (
    FixedWindowRateLimiter,
    MovingWindowRateLimiter,
    SlidingWindowCounterRateLimiter,
)


class FakeTime:
    def __init__(self, current: float = 1_000.0) -> None:
        self.current = current

    def __call__(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


@pytest.fixture
async def storage(tmp_path):
    return SQLiteStorage(f"sqlite:///{tmp_path / 'limits.db'}")


@pytest.mark.asyncio
class TestAsyncSQLiteStorage:
    async def test_async_strategy_contract(self, storage):
        for strategy_type in (
            FixedWindowRateLimiter,
            MovingWindowRateLimiter,
            SlidingWindowCounterRateLimiter,
        ):
            limiter = strategy_type(storage)
            item = RateLimitItemPerSecond(2, 60)
            assert await limiter.hit(item, "key")
            assert await limiter.hit(item, "key")
            assert not await limiter.hit(item, "key")
            await limiter.clear(item, "key")
            assert (await limiter.get_window_stats(item, "key")).remaining == 2

    async def test_async_virtual_time_expiry(self, storage):
        backend = await storage._get_storage()
        clock = FakeTime()
        backend._time = clock
        assert await storage.incr("fixed", 10) == 1
        assert await storage.acquire_entry("moving", 2, 10)
        clock.advance(10)
        assert await storage.get("fixed") == 0
        assert (await storage.get_moving_window("moving", 2, 10))[1] == 0

    async def test_database_calls_run_outside_event_loop_thread(
        self, storage, monkeypatch
    ):
        event_loop_thread = threading.get_ident()
        seen = []
        original_to_thread = __import__("asyncio").to_thread

        async def tracked_to_thread(func, /, *args, **kwargs):
            def wrapped():
                seen.append(threading.get_ident() != event_loop_thread)
                return func(*args, **kwargs)

            return await original_to_thread(wrapped)

        monkeypatch.setattr("asyncio.to_thread", tracked_to_thread)
        await storage.incr("offloaded", 60)
        await storage.acquire_entry("moving", 2, 60)
        await storage.acquire_sliding_window_entry("sliding", 2, 60)
        assert seen and all(seen)
        assert len(seen) == 4

    async def test_async_reset_and_clear(self, storage):
        await storage.incr("fixed", 60)
        await storage.acquire_entry("moving", 2, 60)
        await storage.acquire_sliding_window_entry("sliding", 2, 60)
        assert await storage.reset() == 3
        assert await storage.get("fixed") == 0

        await storage.incr("fixed", 60)
        await storage.clear("fixed")
        assert await storage.get("fixed") == 0
