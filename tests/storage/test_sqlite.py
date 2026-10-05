from __future__ import annotations

import multiprocessing
import os
import sqlite3
import threading

import pytest

from limits import RateLimitItemPerSecond
from limits.errors import LockTimeoutError
from limits.storage import SQLiteStorage, storage_from_string
from limits.strategies import (
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
def storage(tmp_path):
    return SQLiteStorage(f"sqlite:///{tmp_path / 'limits.db'}")


def worker(path: str, strategy: str, limit: int, expiry: int, barrier, queue):
    storage = SQLiteStorage(f"sqlite:///{path}", timeout=5)
    strategies = {
        "fixed": FixedWindowRateLimiter,
        "moving": MovingWindowRateLimiter,
        "sliding": SlidingWindowCounterRateLimiter,
    }
    limiter = strategies[strategy](storage)
    item = RateLimitItemPerSecond(limit, expiry)
    barrier.wait()
    accepted = 0
    for _ in range(limit * 2):
        if limiter.hit(item, "shared"):
            accepted += 1
    queue.put(accepted)


class TestSQLiteStorage:
    def test_storage_string(self, tmp_path):
        path = tmp_path / "limits.db"
        storage = storage_from_string(f"sqlite:///{path}")
        assert isinstance(storage, SQLiteStorage)
        assert storage.check()

    @pytest.mark.parametrize(
        "strategy",
        [
            FixedWindowRateLimiter,
            MovingWindowRateLimiter,
            SlidingWindowCounterRateLimiter,
        ],
    )
    def test_strategy_contract(self, storage, strategy):
        limiter = strategy(storage)
        item = RateLimitItemPerSecond(2, 60)
        assert limiter.hit(item, "key")
        assert limiter.hit(item, "key")
        assert not limiter.hit(item, "key")
        assert limiter.test(item, "other")
        stats = limiter.get_window_stats(item, "key")
        assert stats.remaining == 0
        limiter.clear(item, "key")
        assert limiter.get_window_stats(item, "key").remaining == 2

    def test_key_isolation(self, storage):
        clock = FakeTime()
        storage._time = clock
        assert storage.incr("one", 60, 2)
        assert storage.acquire_entry("moving", 2, 60, amount=2)
        assert storage.acquire_sliding_window_entry("sliding", 2, 60, amount=2)
        assert storage.get("two") == 0
        assert storage.get_moving_window("other", 2, 60) == (
            pytest.approx(1000.0, abs=1),
            0,
        )
        window = storage.get_sliding_window("other", 60)
        assert (window[0], window[1], window[2]) == (0, 0.0, 0)
        storage.clear("one")
        storage.clear("moving")
        storage.clear_sliding_window("sliding", 60)
        assert storage.reset() == 0

    def test_reset_counts_both_tables(self, storage):
        storage.incr("fixed", 60)
        storage.acquire_entry("moving", 2, 60)
        storage.acquire_sliding_window_entry("sliding", 2, 60)
        assert storage.reset() == 3
        assert storage.get("fixed") == 0
        assert storage.get_moving_window("moving", 2, 60)[1] == 0
        window = storage.get_sliding_window("sliding", 60)
        assert (window[0], window[2]) == (0, 0)

    def test_fixed_window_expiry_boundary(self, storage):
        clock = FakeTime()
        storage._time = clock
        assert storage.incr("fixed", 10) == 1
        clock.advance(9.999)
        assert storage.get("fixed") == 1
        clock.advance(0.001)
        assert storage.get("fixed") == 0
        assert storage.get_expiry("fixed") == clock.current

    def test_moving_window_expiry_boundary(self, storage):
        clock = FakeTime()
        storage._time = clock
        assert storage.acquire_entry("moving", 2, 10)
        clock.advance(9.999)
        assert storage.get_moving_window("moving", 2, 10)[1] == 1
        clock.advance(0.001)
        assert storage.get_moving_window("moving", 2, 10)[1] == 0

    def test_sliding_window_boundary_and_stats(self, storage):
        clock = FakeTime(0.0)
        storage._time = clock
        assert storage.acquire_sliding_window_entry("sliding", 2, 10, amount=2)
        assert not storage.acquire_sliding_window_entry("sliding", 2, 10)
        previous_count, previous_ttl, current_count, current_ttl = (
            storage.get_sliding_window("sliding", 10)
        )
        assert (previous_count, previous_ttl, current_count) == (0, 0.0, 2)
        assert current_ttl == pytest.approx(10.0)
        clock.advance(10)
        assert not storage.acquire_sliding_window_entry("sliding", 2, 10)
        clock.advance(0.001)
        assert storage.acquire_sliding_window_entry("sliding", 2, 10)
        previous_count, previous_ttl, current_count, _ = storage.get_sliding_window(
            "sliding", 10
        )
        assert previous_count == 2
        assert previous_ttl == pytest.approx(9.999)
        assert current_count == 1
        clock.advance(9.999)
        window = storage.get_sliding_window("sliding", 10)
        assert (window[0], window[2]) == (1, 0)
        clock.advance(0.001)
        window = storage.get_sliding_window("sliding", 10)
        assert (window[0], window[2]) == (1, 0)
        clock.advance(10)
        window = storage.get_sliding_window("sliding", 10)
        assert (window[0], window[2]) == (0, 0)

    def test_cleanup_uses_batches_and_indexes(self, storage, monkeypatch):
        clock = FakeTime()
        storage._time = clock
        storage.cleanup_batch_size = 2
        storage.incr("fixed-1", 10, amount=2)
        storage.acquire_entry("moving", 10, 10, amount=2)
        clock.advance(11)
        storage.incr("trigger", 10)
        counters = storage.connection.execute("SELECT count(*) FROM counters")
        events = storage.connection.execute("SELECT count(*) FROM events")
        assert counters.fetchone()[0] == 1
        assert events.fetchone()[0] == 0
        plans = storage.connection.execute(
            (
                "EXPLAIN QUERY PLAN SELECT rowid FROM counters "
                "WHERE expires_at <= 1 ORDER BY expires_at LIMIT 2"
            )
        ).fetchall()
        assert any("counters_expires_at_idx" in str(plan) for plan in plans)
        plans = storage.connection.execute(
            (
                "EXPLAIN QUERY PLAN SELECT rowid FROM events "
                "WHERE expires_at <= 1 ORDER BY expires_at LIMIT 2"
            )
        ).fetchall()
        assert any("events_expires_at_idx" in str(plan) for plan in plans)

    def test_lock_timeout_is_distinct_and_rolls_back(self, tmp_path):
        for wrap_exceptions in (False, True):
            path = tmp_path / f"limits-{int(wrap_exceptions)}.db"
            holder = SQLiteStorage(f"sqlite:///{path}", timeout=0.01)
            waiter = SQLiteStorage(
                f"sqlite:///{path}",
                timeout=0.01,
                wrap_exceptions=wrap_exceptions,
            )
            barrier = threading.Barrier(2)

            def hold_lock():
                holder.connection.execute("BEGIN IMMEDIATE")
                barrier.wait()
                barrier.wait()
                holder.connection.rollback()

            thread = threading.Thread(target=hold_lock)
            thread.start()
            barrier.wait()
            with pytest.raises(LockTimeoutError):
                waiter.incr("locked", 60)
            barrier.wait()
            thread.join()
            assert waiter.get("locked") == 0

    def test_application_error_rolls_back_transaction(self, storage, monkeypatch):
        original_cleanup = storage._purge_expired

        def failing_cleanup(connection, now):
            result = original_cleanup(connection, now)
            connection.execute(
                "INSERT INTO counters (key, count, expires_at) VALUES (?, ?, ?)",
                ("cleanup-marker", 1, now + 60),
            )
            raise ValueError("boom")

        monkeypatch.setattr(storage, "_purge_expired", failing_cleanup)
        with pytest.raises(ValueError, match="boom"):
            storage.incr("rolled-back", 60)
        row = storage.connection.execute(
            "SELECT count(*) FROM counters WHERE key = ?", ("rolled-back",)
        ).fetchone()
        assert row[0] == 0

    @pytest.mark.parametrize("strategy_name", ["fixed", "moving", "sliding"])
    def test_two_processes_do_not_overissue(self, tmp_path, strategy_name):
        path = tmp_path / "shared.db"
        SQLiteStorage(f"sqlite:///{path}")
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        barrier = ctx.Barrier(2)
        limit = 25
        processes = [
            ctx.Process(
                target=worker,
                args=(path, strategy_name, limit, 60, barrier, queue),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        accepted = sum(queue.get(timeout=20) for _ in processes)
        for process in processes:
            process.join(20)
            assert process.exitcode == 0
        assert accepted == limit

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is not available")
    def test_connection_is_not_reused_after_fork(self, tmp_path):
        path = tmp_path / "fork.db"
        storage = SQLiteStorage(f"sqlite:///{path}")
        storage.incr("parent", 60)
        parent_pid = os.getpid()
        parent_connection_id = id(storage.connection)
        parent_connection = storage.connection
        reader, writer = multiprocessing.Pipe(duplex=False)

        def child():
            assert storage._pid == parent_pid
            assert storage.incr("child", 60)
            writer.send(
                (
                    os.getpid(),
                    storage.connection is not parent_connection,
                    storage.get("parent"),
                )
            )
            writer.close()

        process = os.fork()
        if process == 0:
            try:
                child()
            finally:
                os._exit(0)
        os.waitpid(process, 0)
        assert reader.poll(5)
        child_pid, connection_recreated, parent_count = reader.recv()
        assert child_pid != parent_pid
        assert connection_recreated
        assert parent_count == 1
        assert storage.incr("parent", 60) == 2
