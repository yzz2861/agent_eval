from __future__ import annotations

import multiprocessing
import os
import sqlite3
import time

import pytest

from limits import RateLimitItemPerMinute, RateLimitItemPerSecond
from limits.errors import ConfigurationError
from limits.storage import storage_from_string
from limits.storage.sqlite import LockTimeoutError, SQLiteStorage
from limits.strategies import (
    FixedWindowRateLimiter,
    MovingWindowRateLimiter,
    SlidingWindowCounterRateLimiter,
)

pytestmark = pytest.mark.sqlite


class VirtualClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def virtual_clock(monkeypatch):
    clock = VirtualClock()
    monkeypatch.setattr(time, "time", clock)
    return clock


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "limits.sqlite")


@pytest.fixture
def storage(db_path):
    return SQLiteStorage(f"sqlite:///{db_path}")


def _moving_window_worker(db_path: str, key: str, limit: int, attempts: int, queue):
    storage = SQLiteStorage(f"sqlite:///{db_path}", timeout=30)
    successes = 0
    for _ in range(attempts):
        if storage.acquire_entry(key, limit, 60):
            successes += 1
    queue.put(successes)


def _incr_worker(db_path: str, key: str, count: int, queue):
    storage = SQLiteStorage(f"sqlite:///{db_path}", timeout=30)
    for _ in range(count):
        storage.incr(key, 60)
    queue.put(storage.get(key))


def _fork_child(storage, queue):
    try:
        value = storage.incr("fork-key", 60)
        queue.put((os.getpid(), storage._pid, value))
    except Exception as exc:  # pragma: no cover
        queue.put(exc)


class TestScheme:
    def test_storage_from_string(self, db_path):
        storage = storage_from_string(f"sqlite:///{db_path}")
        assert isinstance(storage, SQLiteStorage)
        assert storage.check()

    def test_in_memory(self):
        storage = storage_from_string("sqlite:///:memory:")
        assert isinstance(storage, SQLiteStorage)
        assert storage.check()
        assert storage.incr("k", 60) == 1

    def test_missing_path(self):
        with pytest.raises(ConfigurationError):
            storage_from_string("sqlite://")

    def test_check_unhealthy(self, tmp_path):
        storage = SQLiteStorage(
            f"sqlite:///{tmp_path}/missing-dir/nested/limits.sqlite"
        )
        assert not storage.check()


class TestFixedWindowContract:
    def test_incr_get_expiry(self, storage, virtual_clock):
        assert storage.incr("key", 10) == 1
        assert storage.incr("key", 10) == 2
        assert storage.get("key") == 2
        assert storage.get_expiry("key") == virtual_clock.now + 10

    def test_incr_amount(self, storage):
        assert storage.incr("key", 60, amount=5) == 5
        assert storage.incr("key", 60, amount=6) == 11

    def test_key_isolation(self, storage):
        storage.incr("k1", 60)
        storage.incr("k1", 60)
        storage.incr("k2", 60)
        assert storage.get("k1") == 2
        assert storage.get("k2") == 1

    def test_expiry_boundary(self, storage, virtual_clock):
        storage.incr("key", 10)
        virtual_clock.advance(9.9)
        assert storage.get("key") == 1
        virtual_clock.advance(0.1)
        assert storage.get("key") == 0

    def test_counter_resets_after_expiry(self, storage, virtual_clock):
        storage.incr("key", 10)
        virtual_clock.advance(20)
        assert storage.incr("key", 10) == 1
        assert storage.get_expiry("key") == virtual_clock.now + 10

    def test_get_expiry_missing_key(self, storage, virtual_clock):
        assert storage.get_expiry("missing") == virtual_clock.now

    def test_clear(self, storage):
        storage.incr("key", 60)
        storage.acquire_entry("key", 2, 60)
        storage.clear("key")
        assert storage.get("key") == 0
        assert storage.get_moving_window("key", 2, 60) == (
            pytest.approx(time.time()),
            0,
        )

    def test_reset(self, storage):
        for i in range(10):
            storage.incr(f"counter-{i}", 60)
        for i in range(2):
            storage.acquire_entry(f"moving-{i}", 5, 60)
        assert storage.reset() == 12
        assert storage.get("counter-0") == 0
        assert storage.get_moving_window("moving-0", 5, 60)[1] == 0
        assert storage.reset() == 0

    def test_fixed_window_strategy(self, storage, virtual_clock):
        limiter = FixedWindowRateLimiter(storage)
        limit = RateLimitItemPerSecond(10, 10)
        assert all(limiter.hit(limit) for _ in range(10))
        assert not limiter.hit(limit)
        stats = limiter.get_window_stats(limit)
        assert stats.remaining == 0
        assert stats.reset_time == virtual_clock.now + 10
        virtual_clock.advance(10)
        assert limiter.hit(limit)
        assert limiter.get_window_stats(limit).remaining == 9


class TestMovingWindowContract:
    def test_acquire_entry(self, storage, virtual_clock):
        assert storage.acquire_entry("key", 2, 10)
        virtual_clock.advance(1)
        assert storage.acquire_entry("key", 2, 10)
        assert not storage.acquire_entry("key", 2, 10)

    def test_acquire_entry_amount(self, storage):
        assert not storage.acquire_entry("key", 10, 60, amount=11)
        assert storage.acquire_entry("key", 10, 60, amount=9)
        assert not storage.acquire_entry("key", 10, 60, amount=2)
        assert storage.acquire_entry("key", 10, 60, amount=1)

    def test_moving_window_stats(self, storage, virtual_clock):
        start = virtual_clock.now
        storage.acquire_entry("key", 3, 10)
        virtual_clock.advance(1)
        storage.acquire_entry("key", 3, 10)
        window_start, count = storage.get_moving_window("key", 3, 10)
        assert window_start == start
        assert count == 2

    def test_window_slides(self, storage, virtual_clock):
        storage.acquire_entry("key", 3, 10)
        virtual_clock.advance(1)
        storage.acquire_entry("key", 3, 10)
        virtual_clock.advance(1)
        storage.acquire_entry("key", 3, 10)
        assert not storage.acquire_entry("key", 3, 10)
        virtual_clock.advance(9)
        # only the entry at t+2 is still strictly inside the window
        assert storage.get_moving_window("key", 3, 10)[1] == 1
        assert storage.acquire_entry("key", 3, 10)
        assert storage.acquire_entry("key", 3, 10)
        assert not storage.acquire_entry("key", 3, 10)

    def test_entries_expire(self, storage, virtual_clock):
        storage.acquire_entry("key", 2, 10)
        virtual_clock.advance(11)
        assert storage.get_moving_window("key", 2, 10) == (virtual_clock.now, 0)
        assert storage.acquire_entry("key", 2, 10)

    def test_moving_window_strategy(self, storage, virtual_clock):
        limiter = MovingWindowRateLimiter(storage)
        limit = RateLimitItemPerMinute(2)
        assert limiter.hit(limit, "key")
        virtual_clock.advance(1)
        assert limiter.hit(limit, "key")
        assert not limiter.hit(limit, "key")
        stats = limiter.get_window_stats(limit, "key")
        assert stats.remaining == 0
        assert stats.reset_time == virtual_clock.now + 59
        virtual_clock.advance(59)
        assert limiter.hit(limit, "key")


class TestSlidingWindowContract:
    def test_acquire_sliding_window_entry(self, storage):
        assert storage.acquire_sliding_window_entry("key", 2, 10)
        assert storage.acquire_sliding_window_entry("key", 2, 10)
        assert not storage.acquire_sliding_window_entry("key", 2, 10)

    def test_acquire_sliding_window_entry_amount(self, storage):
        assert not storage.acquire_sliding_window_entry("key", 10, 60, amount=11)
        assert storage.acquire_sliding_window_entry("key", 10, 60, amount=5)
        assert not storage.acquire_sliding_window_entry("key", 10, 60, amount=6)
        assert storage.acquire_sliding_window_entry("key", 10, 60, amount=5)

    def test_weighted_previous_window(self, storage, virtual_clock):
        expiry = 10
        for _ in range(6):
            assert storage.acquire_sliding_window_entry("key", 10, expiry)
        # move half a window forward: the 6 hits of the previous window
        # now weigh 6 * 0.5 = 3
        virtual_clock.advance(expiry + expiry / 2)
        previous_count, previous_ttl, current_count, current_ttl = (
            storage.get_sliding_window("key", expiry)
        )
        assert previous_count == 6
        assert previous_ttl == pytest.approx(expiry / 2)
        assert current_count == 0
        assert current_ttl == pytest.approx(expiry + expiry / 2)
        # 3 (weighted) + 7 = 10 hits are allowed
        for _ in range(7):
            assert storage.acquire_sliding_window_entry("key", 10, expiry)
        assert not storage.acquire_sliding_window_entry("key", 10, expiry)

    def test_windows_expire(self, storage, virtual_clock):
        storage.acquire_sliding_window_entry("key", 2, 10)
        virtual_clock.advance(20)
        assert storage.get_sliding_window("key", 10) == (0, 0.0, 0, pytest.approx(20.0))
        assert storage.acquire_sliding_window_entry("key", 2, 10)

    def test_clear_sliding_window(self, storage):
        storage.acquire_sliding_window_entry("key", 2, 10)
        storage.clear_sliding_window("key", 10)
        previous_count, _, current_count, _ = storage.get_sliding_window("key", 10)
        assert previous_count == 0
        assert current_count == 0

    def test_sliding_window_strategy(self, storage, virtual_clock):
        limiter = SlidingWindowCounterRateLimiter(storage)
        limit = RateLimitItemPerSecond(2, 10)
        assert limiter.hit(limit)
        assert limiter.hit(limit)
        assert not limiter.hit(limit)
        assert limiter.get_window_stats(limit).remaining == 0
        limiter.clear(limit)
        assert limiter.get_window_stats(limit).remaining == 2


class TestExpiryCleanup:
    def test_cleanup_removes_expired_rows_in_batches(self, db_path, virtual_clock):
        storage = SQLiteStorage(f"sqlite:///{db_path}", cleanup_batch_size=3)
        for i in range(10):
            storage.incr(f"counter-{i}", 10)
        for i in range(8):
            storage.acquire_entry(f"moving-{i}", 5, 10)
        storage.incr("fresh", 100)
        virtual_clock.advance(20)

        statements = []
        storage._get_connection().set_trace_callback(statements.append)
        assert storage._cleanup_expired() == 18
        deletes = [stmt for stmt in statements if stmt.startswith("DELETE")]
        # ceil(10 / 3) + ceil(8 / 3) batches, each its own statement
        assert len(deletes) == 4 + 3
        connection = storage._get_connection()
        assert connection.execute("SELECT COUNT(*) FROM counters").fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM moving_entries").fetchone()[0] == 0
        )

    def test_cleanup_is_throttled(self, storage, virtual_clock):
        storage.incr("key", 10)
        statements = []
        storage._get_connection().set_trace_callback(statements.append)
        # the first incr already ran a cleanup: a second one within the
        # interval must not run again
        storage.incr("key", 10)
        assert not any(stmt.startswith("DELETE") for stmt in statements)
        virtual_clock.advance(31)
        storage.incr("key", 10)
        assert any(stmt.startswith("DELETE") for stmt in statements)

    def test_cleanup_is_best_effort(self, storage, monkeypatch):
        def failing_cleanup(now=None):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(storage, "_cleanup_expired", failing_cleanup)
        storage._last_cleanup = -1
        # a failing cleanup must not break the actual operation
        assert storage.incr("key", 60) == 1


class TestLockingAndTransactions:
    def test_lock_timeout_raises_and_rolls_back(self, db_path):
        storage = SQLiteStorage(f"sqlite:///{db_path}", timeout=0.1)
        assert storage.check()
        blocker = sqlite3.connect(db_path)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(LockTimeoutError):
                storage.incr("key", 60)
            # the failed transaction left nothing behind
            assert storage.get("key") == 0
        finally:
            blocker.rollback()
            blocker.close()
        assert storage.incr("key", 60) == 1

    def test_transaction_rolls_back_on_error(self, storage):
        with pytest.raises(ValueError), storage._transaction() as connection:
            connection.execute(
                "INSERT INTO counters (key, value, expires_at) VALUES (?, ?, ?)",
                ("key", 1, time.time() + 60),
            )
            raise ValueError("boom")
        assert storage.get("key") == 0

    def test_read_allowed_while_writer_holds_lock(self, db_path):
        storage = SQLiteStorage(f"sqlite:///{db_path}", timeout=0.1)
        storage.incr("key", 60)
        blocker = sqlite3.connect(db_path)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            # WAL mode: readers are not blocked by the writer
            assert storage.get("key") == 1
        finally:
            blocker.rollback()
            blocker.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork not available")
class TestMultipleProcesses:
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_connection_not_shared_across_fork(self, storage):
        assert storage.incr("fork-key", 60) == 1
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        process = ctx.Process(target=_fork_child, args=(storage, queue))
        process.start()
        process.join(30)
        assert process.exitcode == 0
        child_pid, connection_pid, value = queue.get(timeout=10)
        assert value == 2
        # the child reconnected instead of reusing the parent handle
        assert connection_pid == child_pid != os.getpid()

    def test_moving_window_no_oversell(self, db_path):
        storage = SQLiteStorage(f"sqlite:///{db_path}")
        storage.check()
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        processes = [
            ctx.Process(
                target=_moving_window_worker,
                args=(db_path, "shared", 20, 100, queue),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(60)
        assert all(process.exitcode == 0 for process in processes)
        results = sorted(queue.get(timeout=10) for _ in processes)
        assert sum(results) == 20
        assert storage.get_moving_window("shared", 20, 60)[1] == 20

    def test_incr_no_lost_updates(self, db_path):
        storage = SQLiteStorage(f"sqlite:///{db_path}")
        storage.check()
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        processes = [
            ctx.Process(target=_incr_worker, args=(db_path, "counter", 100, queue))
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(60)
        assert all(process.exitcode == 0 for process in processes)
        for _ in processes:
            queue.get(timeout=10)
        assert storage.get("counter") == 200
