from __future__ import annotations

import threading

import pytest

from limits import RateLimitItemPerMinute
from limits.aio.storage import MemoryStorage as AsyncMemoryStorage
from limits.aio.storage import Storage as AsyncStorage
from limits.aio.strategies import (
    DistinctWindowRateLimiter as AsyncDistinctWindowRateLimiter,
)
from limits.storage import MemoryStorage, Storage
from limits.strategies import DistinctWindowRateLimiter


class VirtualClock:
    def __init__(self) -> None:
        self.now = 100.0

    def time(self) -> float:
        return self.now


def test_distinct_window_repeats_refresh_without_event_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = VirtualClock()
    monkeypatch.setattr("limits.storage.memory.time.time", clock.time)
    storage = MemoryStorage()
    limiter = DistinctWindowRateLimiter(storage)
    limit = RateLimitItemPerMinute(2)
    key = limit.key_for("account")

    assert limiter.hit(limit, "account", resource="resource")
    assert storage.distinct_entries[key] == {"resource": 160.0}

    clock.now = 130.0
    assert limiter.hit(limit, "account", resource="resource")
    assert storage.distinct_entries[key] == {"resource": 190.0}
    assert len(storage.distinct_entries[key]) == 1
    assert limiter.get_distinct_window_stats(limit, "account").count == 1
    window_stats = limiter.get_window_stats(limit, "account")
    assert window_stats.remaining == 1
    assert window_stats.reset_time == 130.0


def test_distinct_window_rejects_over_limit_without_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = VirtualClock()
    monkeypatch.setattr("limits.storage.memory.time.time", clock.time)
    storage = MemoryStorage()
    limiter = DistinctWindowRateLimiter(storage)
    limit = RateLimitItemPerMinute(2)
    key = limit.key_for()

    assert limiter.hit(limit, resource="one")
    assert limiter.hit(limit, resource=b"two")
    assert not limiter.hit(limit, resource="three")

    assert storage.distinct_entries[key] == {"one": 160.0, b"two": 160.0}
    assert "three" not in storage.distinct_entries[key]
    stats = limiter.get_distinct_window_stats(limit)
    assert stats.count == 2
    assert stats.next_available_time == 160.0


def test_distinct_window_expired_entry_frees_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = VirtualClock()
    monkeypatch.setattr("limits.storage.memory.time.time", clock.time)
    storage = MemoryStorage()
    limiter = DistinctWindowRateLimiter(storage)
    limit = RateLimitItemPerMinute(1)
    key = limit.key_for()

    assert limiter.hit(limit, resource="old")
    clock.now = 160.0
    stats = limiter.get_distinct_window_stats(limit)
    assert stats.count == 0
    assert stats.next_available_time == 160.0
    assert limiter.hit(limit, resource="new")

    assert storage.distinct_entries[key] == {"new": 220.0}
    assert limiter.get_distinct_window_stats(limit).count == 1


def test_distinct_window_two_new_resources_compete_for_last_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = VirtualClock()
    monkeypatch.setattr("limits.storage.memory.time.time", clock.time)
    storage = MemoryStorage()
    limiter = DistinctWindowRateLimiter(storage)
    limit = RateLimitItemPerMinute(2)
    key = limit.key_for()

    assert limiter.hit(limit, resource="occupied")
    results: dict[str, bool] = {}

    def acquire(resource: str) -> None:
        barrier.wait()
        results[resource] = limiter.hit(limit, resource=resource)

    barrier = threading.Barrier(2)
    threads = [
        threading.Thread(target=acquire, args=("candidate-a",)),
        threading.Thread(target=acquire, args=("candidate-b",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results.values()) == [False, True]
    assert len(storage.distinct_entries[key]) == 2


def test_distinct_window_rejects_unsupported_sync_storage() -> None:
    class FixedOnlyStorage(Storage):
        STORAGE_SCHEME = None

        @property
        def base_exceptions(self) -> type[Exception]:
            return ValueError

        def incr(self, key: str, expiry: int, amount: int = 1) -> int:
            return 0

        def get(self, key: str) -> int:
            return 0

        def get_expiry(self, key: str) -> float:
            return 0.0

        def check(self) -> bool:
            return True

        def reset(self) -> int | None:
            return 0

        def clear(self, key: str) -> None:
            return None

    with pytest.raises(NotImplementedError):
        DistinctWindowRateLimiter(FixedOnlyStorage())


@pytest.mark.asyncio
async def test_async_distinct_window_virtual_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = VirtualClock()
    monkeypatch.setattr("limits.aio.storage.memory.time.time", clock.time)
    storage = AsyncMemoryStorage()
    limiter = AsyncDistinctWindowRateLimiter(storage)
    limit = RateLimitItemPerMinute(1)
    key = limit.key_for()

    assert await limiter.hit(limit, resource="resource")
    clock.now = 130.0
    assert await limiter.hit(limit, resource="resource")
    assert storage.distinct_entries[key] == {"resource": 190.0}

    assert not await limiter.hit(limit, resource=b"resource")
    assert len(storage.distinct_entries[key]) == 1

    clock.now = 190.0
    assert await limiter.hit(limit, resource=b"resource")
    assert storage.distinct_entries[key] == {b"resource": 250.0}
    stats = await limiter.get_distinct_window_stats(limit)
    assert stats.count == 1
    assert stats.next_available_time == 250.0
    storage.__del__()


@pytest.mark.asyncio
async def test_distinct_window_rejects_unsupported_async_storage() -> None:
    class FixedOnlyStorage(AsyncStorage):
        STORAGE_SCHEME = None

        @property
        def base_exceptions(self) -> type[Exception]:
            return ValueError

        async def incr(self, key: str, expiry: int, amount: int = 1) -> int:
            return 0

        async def get(self, key: str) -> int:
            return 0

        async def get_expiry(self, key: str) -> float:
            return 0.0

        async def check(self) -> bool:
            return True

        async def reset(self) -> int | None:
            return 0

        async def clear(self, key: str) -> None:
            return None

    with pytest.raises(NotImplementedError):
        AsyncDistinctWindowRateLimiter(FixedOnlyStorage())
