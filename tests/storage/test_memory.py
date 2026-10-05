from __future__ import annotations

import bisect
import pickle
import threading

from limits.storage import MemoryStorage


class TestSerialization:
    def test_pickle(self):
        storage = MemoryStorage()
        assert 1 == storage.incr("test", 60)
        assert storage.acquire_entry("moving_test", 2, 60)
        dump = pickle.dumps(storage)
        restored = pickle.loads(dump)
        assert 2 == restored.incr("test", 60)
        assert restored.acquire_entry("moving_test", 2, 60)
        assert not restored.acquire_entry("moving_test", 2, 60)


class OldWeightedMovingWindow:
    """Reference implementation of the pre-weighted-events memory storage."""

    class Entry:
        def __init__(self, atime, expiry):
            self.atime = atime
            self.expiry = atime + expiry

    def __init__(self, clock):
        self.clock = clock
        self.events = {}

    def acquire_entry(self, key, limit, expiry, amount=1):
        if amount > limit:
            return False
        self.events.setdefault(key, [])
        timestamp = self.clock()
        try:
            entry = self.events[key][limit - amount]
        except IndexError:
            entry = None
        if entry and entry.atime >= timestamp - expiry:
            return False
        self.events[key][:0] = [
            self.Entry(timestamp, expiry) for _ in range(amount)
        ]
        return True

    def get_moving_window(self, key, limit, expiry):
        timestamp = self.clock()
        if events := self.events.get(key, []):
            oldest = bisect.bisect_left(
                events, -(timestamp - expiry), key=lambda entry: -entry.atime
            )
            return events[oldest - 1].atime, oldest
        return timestamp, 0


class _LiveTimer:
    def is_alive(self):
        return True

    def start(self):
        pass


class TestMovingWindowWeighted:
    def test_matches_expanded_entry_algorithm(self, monkeypatch):
        import limits.storage.memory as module

        current_time = 1000.0
        monkeypatch.setattr(module.time, "time", lambda: current_time)
        storage = MemoryStorage()
        monkeypatch.setattr(storage, "timer", _LiveTimer(), raising=False)
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
            new_result = storage.acquire_entry("k", limit, expiry, amount=amount)
            old_result = reference.acquire_entry("k", limit, expiry, amount=amount)
            assert new_result is old_result is accepted
            assert reference.acquire_entry("k", limit, expiry, amount=0) is True
            assert storage.acquire_entry("k", limit, expiry, amount=0) is True
            assert storage.get_moving_window(
                "k", limit, expiry
            ) == reference.get_moving_window("k", limit, expiry)
            if accepted:
                accepted_count += 1
                assert len(storage.events["k"]) == accepted_count

        # Boundary: events at exactly ``now - expiry`` are still counted
        # (rejection compares with ``>=``), while get_moving_window uses ``>``.
        current_time = 1005.0
        assert storage.get_moving_window("k", limit, expiry) == (
            reference.get_moving_window("k", limit, expiry)
        )
        assert storage.acquire_entry("k", limit, expiry) is False
        assert reference.acquire_entry("k", limit, expiry) is False

        current_time = 1005.0 + 1e-9
        assert storage.get_moving_window("k", limit, expiry) == (
            reference.get_moving_window("k", limit, expiry)
        )
        assert storage.acquire_entry("k", limit, expiry) is True
        assert reference.acquire_entry("k", limit, expiry) is True

    def test_large_cost_uses_single_weighted_entry(self):
        storage = MemoryStorage()
        limit = 10**12
        assert storage.acquire_entry("k", limit, 60, amount=limit - 1) is True
        assert storage.acquire_entry("k", limit, 60, amount=2) is False
        assert storage.acquire_entry("k", limit, 60) is True
        assert len(storage.events["k"]) == 2
        assert sum(event.weight for event in storage.events["k"]) == limit
        assert storage.get_moving_window("k", limit, 60)[1] == limit

    def test_failed_large_cost_leaves_no_state(self):
        storage = MemoryStorage()
        assert storage.acquire_entry("k", 10, 60, amount=11) is False
        assert "k" not in storage.events
        assert storage.acquire_entry("k", 10, 60) is True
        assert storage.acquire_entry("k", 10, 60, amount=10) is False
        assert len(storage.events["k"]) == 1

    def test_expired_weighted_entries_are_swept(self, monkeypatch):
        import limits.storage.memory as module

        current_time = 1000.0
        monkeypatch.setattr(module.time, "time", lambda: current_time)
        storage = MemoryStorage()
        monkeypatch.setattr(storage, "timer", _LiveTimer(), raising=False)

        assert storage.acquire_entry("k", 10, 60, amount=4) is True
        current_time = 1059.0
        assert storage.acquire_entry("k", 10, 60, amount=6) is True
        assert len(storage.events["k"]) == 2
        current_time = 1060.0
        storage._MemoryStorage__expire_events()
        assert len(storage.events["k"]) == 1
        assert storage.events["k"][0].weight == 6
        current_time = 1120.0 + 1e-9
        storage._MemoryStorage__expire_events()
        assert storage.events["k"] == []
        assert storage.acquire_entry("k", 10, 60, amount=10) is True

    def test_concurrent_acquires_are_atomic(self):
        storage = MemoryStorage()
        accepted = []

        def acquire(amount):
            if storage.acquire_entry("k", 100, 60, amount=amount):
                accepted.append(amount)

        threads = [
            threading.Thread(target=acquire, args=(1,)) for _ in range(40)
        ] + [threading.Thread(target=acquire, args=(3,)) for _ in range(30)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sum(accepted) == 100
        assert storage.get_moving_window("k", 100, 60)[1] == 100
