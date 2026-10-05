from __future__ import annotations

import asyncio
import pickle
import random

import limits.aio.storage.memory
from limits.aio.storage import MemoryStorage
from tests.utils import FakeClock, ReferenceMovingWindow


def weighted_storage(monkeypatch, clock):
    monkeypatch.setattr(limits.aio.storage.memory, "time", clock)
    storage = MemoryStorage()

    async def no_schedule(self):
        return None

    monkeypatch.setattr(MemoryStorage, "_MemoryStorage__schedule_expiry", no_schedule)
    return storage


class TestSerialization:
    async def test_pickle(self):
        storage = MemoryStorage()
        assert 1 == await storage.incr("test", 60)
        assert await storage.acquire_entry("moving_test", 2, 60)
        dump = pickle.dumps(storage)
        restored = pickle.loads(dump)
        assert 2 == await restored.incr("test", 60)
        assert await restored.acquire_entry("moving_test", 2, 60)
        assert not await restored.acquire_entry("moving_test", 2, 60)


class TestMovingWindowWeightedEntries:
    async def test_matches_reference_implementation(self, monkeypatch):
        clock = FakeClock()
        storage = weighted_storage(monkeypatch, clock)
        reference = ReferenceMovingWindow(clock)
        rng = random.Random(20261001)
        keys = ("k1", "k2", "k3")
        for _ in range(1000):
            key = rng.choice(keys)
            limit = rng.choice((1, 2, 5, 10))
            expiry = rng.choice((10, 30, 120))
            amount = rng.randint(1, limit + 2)
            assert await storage.acquire_entry(
                key, limit, expiry, amount
            ) == reference.acquire_entry(key, limit, expiry, amount)
            assert await storage.get_moving_window(
                key, limit, expiry
            ) == reference.get_moving_window(key, limit, expiry)
            clock.advance(rng.choice((0, 0.25, 1, 5, 60)))

    async def test_expire_events(self, monkeypatch):
        clock = FakeClock()
        storage = weighted_storage(monkeypatch, clock)
        assert await storage.acquire_entry("k", 100, 10, amount=5)
        clock.advance(5)
        assert await storage.acquire_entry("k", 100, 60, amount=7)
        clock.advance(6)
        await storage._MemoryStorage__expire_events()
        events = storage.events["k"]
        assert len(events) == 1
        assert events[0].weight == 7
        assert await storage.get_moving_window("k", 100, 60) == (events[0].atime, 7)

    async def test_large_amount_storage_is_constant(self, monkeypatch):
        clock = FakeClock()
        storage = weighted_storage(monkeypatch, clock)
        huge = 10**18
        assert await storage.acquire_entry("k", huge, 60, amount=huge)
        assert len(storage.events["k"]) == 1
        assert storage.events["k"][0].weight == huge
        assert await storage.get_moving_window("k", huge, 60) == (
            storage.events["k"][0].atime,
            huge,
        )
        # the window is now full: further acquires fail without changing state
        assert not await storage.acquire_entry("k", huge, 60)
        assert len(storage.events["k"]) == 1
        # an amount larger than the limit fails without leaving state behind
        assert not await storage.acquire_entry("other", 10, 60, amount=huge)
        assert "other" not in storage.events
        # storage grows with the number of events, not with the amounts
        for i in range(100):
            assert await storage.acquire_entry(f"k{i}", huge, 60, amount=huge)
        assert len(storage.events) == 101
        assert all(len(events) == 1 for events in storage.events.values())

    async def test_concurrent_acquire_entry_is_atomic(self):
        storage = MemoryStorage()
        limit = 64
        results = await asyncio.gather(
            *(storage.acquire_entry("k", limit, 60) for _ in range(512))
        )
        assert sum(results) == limit
        assert sum(event.weight for event in storage.events["k"]) == limit
