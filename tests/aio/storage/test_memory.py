from __future__ import annotations

import asyncio
import pickle

from limits.aio.storage import MemoryStorage
from tests.storage.test_memory import OldWeightedMovingWindow


class _LiveTimer:
    def done(self):
        return False


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


class TestMovingWindowWeighted:
    async def test_matches_expanded_entry_algorithm(self, monkeypatch):
        import limits.aio.storage.memory as module

        current_time = 1000.0
        monkeypatch.setattr(module.time, "time", lambda: current_time)
        storage = MemoryStorage()
        storage.timer = _LiveTimer()
        reference = OldWeightedMovingWindow(lambda: current_time)

        limit = 10
        expiry = 5
        script = [
            (1, True),
            (1, True),
            (3, True),
            (1, True),
            (6, False),
            (5, False),
            (4, True),
            (1, False),
            (11, False),
        ]

        accepted_count = 0
        for amount, accepted in script:
            new_result = await storage.acquire_entry(
                "k", limit, expiry, amount=amount
            )
            old_result = reference.acquire_entry("k", limit, expiry, amount=amount)
            assert new_result is old_result is accepted
            assert reference.acquire_entry("k", limit, expiry, amount=0) is True
            assert await storage.acquire_entry("k", limit, expiry, amount=0) is True
            assert await storage.get_moving_window(
                "k", limit, expiry
            ) == reference.get_moving_window("k", limit, expiry)
            if accepted:
                accepted_count += 1
                assert len(storage.events["k"]) == accepted_count

        current_time = 1005.0
        assert await storage.get_moving_window(
            "k", limit, expiry
        ) == reference.get_moving_window("k", limit, expiry)
        assert await storage.acquire_entry("k", limit, expiry) is False
        assert reference.acquire_entry("k", limit, expiry) is False

        current_time = 1005.0 + 1e-9
        assert await storage.get_moving_window(
            "k", limit, expiry
        ) == reference.get_moving_window("k", limit, expiry)
        assert await storage.acquire_entry("k", limit, expiry) is True
        assert reference.acquire_entry("k", limit, expiry) is True

    async def test_large_cost_uses_single_weighted_entry(self):
        storage = MemoryStorage()
        limit = 10**12
        assert await storage.acquire_entry("k", limit, 60, amount=limit - 1) is True
        assert await storage.acquire_entry("k", limit, 60, amount=2) is False
        assert await storage.acquire_entry("k", limit, 60) is True
        assert len(storage.events["k"]) == 2
        assert sum(event.weight for event in storage.events["k"]) == limit
        assert (await storage.get_moving_window("k", limit, 60))[1] == limit

    async def test_failed_large_cost_leaves_no_state(self):
        storage = MemoryStorage()
        assert await storage.acquire_entry("k", 10, 60, amount=11) is False
        assert "k" not in storage.events
        assert await storage.acquire_entry("k", 10, 60) is True
        assert await storage.acquire_entry("k", 10, 60, amount=10) is False
        assert len(storage.events["k"]) == 1

    async def test_expired_weighted_entries_are_swept(self, monkeypatch):
        import limits.aio.storage.memory as module

        current_time = 1000.0
        monkeypatch.setattr(module.time, "time", lambda: current_time)
        storage = MemoryStorage()
        storage.timer = _LiveTimer()

        assert await storage.acquire_entry("k", 10, 60, amount=4) is True
        current_time = 1059.0
        assert await storage.acquire_entry("k", 10, 60, amount=6) is True
        assert len(storage.events["k"]) == 2
        current_time = 1060.0
        await storage._MemoryStorage__expire_events()
        assert len(storage.events["k"]) == 1
        assert storage.events["k"][0].weight == 6
        current_time = 1120.0 + 1e-9
        await storage._MemoryStorage__expire_events()
        assert "k" not in storage.events
        assert await storage.acquire_entry("k", 10, 60, amount=10) is True

    async def test_concurrent_acquires_are_atomic(self):
        storage = MemoryStorage()
        amounts = [1] * 40 + [3] * 30

        async def acquire(amount, accepted):
            if await storage.acquire_entry("k", 100, 60, amount=amount):
                accepted.append(amount)

        accepted = []
        await asyncio.gather(*(acquire(amount, accepted) for amount in amounts))

        assert sum(accepted) == 100
        assert (await storage.get_moving_window("k", 100, 60))[1] == 100
