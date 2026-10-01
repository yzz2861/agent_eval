from __future__ import annotations

import asyncio
import math
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any

import pytest

from anyio import (
    CancelScope,
    CapacityLimiter,
    Condition,
    Event,
    Lock,
    RWLock,
    Semaphore,
    WouldBlock,
    create_task_group,
    fail_after,
    move_on_after,
    run,
    to_thread,
    wait_all_tasks_blocked,
)
from anyio.lowlevel import checkpoint

from .conftest import asyncio_params

if TYPE_CHECKING:
    from anyio.abc import TaskStatus


class TestLock:
    async def test_contextmanager(self) -> None:
        async def task() -> None:
            assert lock.locked()
            async with lock:
                results.append("2")

        results = []
        lock = Lock()
        async with create_task_group() as tg, lock:
            tg.start_soon(task)
            await wait_all_tasks_blocked()
            results.append("1")

        assert not lock.locked()
        assert results == ["1", "2"]

    async def test_manual_acquire(self) -> None:
        async def task() -> None:
            assert lock.locked()
            await lock.acquire()
            try:
                results.append("2")
            finally:
                lock.release()

        results = []
        lock = Lock()
        async with create_task_group() as tg:
            await lock.acquire()
            try:
                tg.start_soon(task)
                await wait_all_tasks_blocked()
                results.append("1")
            finally:
                lock.release()

        assert not lock.locked()
        assert results == ["1", "2"]

    async def test_fast_acquire(self) -> None:
        """
        Test that fast_acquire=True does not yield back control to the event loop when
        there is no contention.

        """
        other_task_called = False

        async def other_task() -> None:
            nonlocal other_task_called
            other_task_called = True

        lock = Lock(fast_acquire=True)
        async with create_task_group() as tg:
            tg.start_soon(other_task)
            async with lock:
                assert not other_task_called

    async def test_acquire_nowait(self) -> None:
        lock = Lock()
        lock.acquire_nowait()
        assert lock.locked()

    async def test_acquire_nowait_wouldblock(self) -> None:
        async def try_lock() -> None:
            pytest.raises(WouldBlock, lock.acquire_nowait)

        lock = Lock()
        async with lock, create_task_group() as tg:
            assert lock.locked()
            tg.start_soon(try_lock)

    @pytest.mark.parametrize("fast_acquire", [True, False])
    async def test_acquire_twice_async(self, fast_acquire: bool) -> None:
        lock = Lock(fast_acquire=fast_acquire)
        await lock.acquire()
        with pytest.raises(
            RuntimeError, match="Attempted to acquire an already held Lock"
        ):
            await lock.acquire()

    async def test_acquire_twice_sync(self) -> None:
        lock = Lock()
        lock.acquire_nowait()
        with pytest.raises(
            RuntimeError, match="Attempted to acquire an already held Lock"
        ):
            lock.acquire_nowait()

    @pytest.mark.parametrize(
        "release_first",
        [pytest.param(False, id="releaselast"), pytest.param(True, id="releasefirst")],
    )
    async def test_cancel_during_acquire(self, release_first: bool) -> None:
        acquired = False

        async def task(*, task_status: TaskStatus) -> None:
            nonlocal acquired
            task_status.started()
            async with lock:
                acquired = True

        lock = Lock()
        async with create_task_group() as tg:
            await lock.acquire()
            await tg.start(task)
            tg.cancel_scope.cancel()
            with CancelScope(shield=True):
                if release_first:
                    lock.release()
                    await wait_all_tasks_blocked()
                else:
                    await wait_all_tasks_blocked()
                    lock.release()

        assert not acquired
        assert not lock.locked()

    async def test_statistics(self) -> None:
        async def waiter() -> None:
            async with lock:
                pass

        lock = Lock()
        async with create_task_group() as tg:
            assert not lock.statistics().locked
            assert lock.statistics().tasks_waiting == 0
            async with lock:
                assert lock.statistics().locked
                assert lock.statistics().tasks_waiting == 0
                for i in range(1, 3):
                    tg.start_soon(waiter)
                    await wait_all_tasks_blocked()
                    assert lock.statistics().tasks_waiting == i

        assert not lock.statistics().locked
        assert lock.statistics().tasks_waiting == 0

    @pytest.mark.parametrize("anyio_backend", asyncio_params)
    async def test_asyncio_deadlock(self) -> None:
        """Regression test for #398."""
        lock = Lock()

        async def acquire() -> None:
            async with lock:
                await asyncio.sleep(0)

        loop = asyncio.get_running_loop()
        task1 = loop.create_task(acquire())
        task2 = loop.create_task(acquire())
        await asyncio.sleep(0)
        task1.cancel()
        await asyncio.wait_for(task2, 1)

    @pytest.mark.parametrize("anyio_backend", asyncio_params)
    async def test_cancel_after_release(self) -> None:
        """
        Test that a native asyncio cancellation will not cause a lock ownership
        to get lost between a release() and the resumption of acquire().

        """
        # Create the lock and acquire it right away so that any task acquiring it will
        # block
        lock = Lock()
        lock.acquire_nowait()

        # Start a task that gets blocked on trying to acquire the semaphore
        loop = asyncio.get_running_loop()
        task1 = loop.create_task(lock.acquire(), name="task1")
        await asyncio.sleep(0)

        # Trigger the acquiring task to be rescheduled, but also cancel it right away
        lock.release()
        task1.cancel()
        statistics = lock.statistics()
        assert statistics.owner
        assert statistics.owner.name == "task1"
        await asyncio.wait([task1], timeout=5)

        # The acquire() method should've released the semaphore because acquisition
        # failed due to cancellation
        statistics = lock.statistics()
        assert statistics.owner is None
        assert statistics.tasks_waiting == 0
        lock.acquire_nowait()

    async def test_cancelled_after_acquire(self) -> None:
        lock = Lock()
        lock.acquire_nowait()
        async with create_task_group() as tg:
            task1 = tg.create_task(lock.acquire())
            await wait_all_tasks_blocked()
            task1.cancel()
            lock.release()
            assert lock.statistics().tasks_waiting == 0
            with fail_after(3):
                await lock.acquire()

    def test_instantiate_outside_event_loop(
        self, anyio_backend_name: str, anyio_backend_options: dict[str, Any]
    ) -> None:
        async def use_lock() -> None:
            async with lock:
                pass

        lock = Lock()
        statistics = lock.statistics()
        assert not statistics.locked
        assert statistics.owner is None
        assert statistics.tasks_waiting == 0

        run(use_lock, backend=anyio_backend_name, backend_options=anyio_backend_options)

    async def test_owner_after_release(self) -> None:
        async def taskfunc1() -> None:
            await lock.acquire()
            owner = lock.statistics().owner
            assert owner
            assert owner.name == "task1"
            await event.wait()
            lock.release()
            owner = lock.statistics().owner
            assert owner
            assert owner.name == "task2"

        event = Event()
        lock = Lock()
        async with create_task_group() as tg:
            tg.start_soon(taskfunc1, name="task1")
            await wait_all_tasks_blocked()
            tg.start_soon(lock.acquire, name="task2")
            await wait_all_tasks_blocked()
            event.set()


class TestRWLock:
    async def test_reader_contextmanager(self) -> None:
        lock = RWLock()
        async with lock.reader:
            assert lock.locked()
            statistics = lock.statistics()
            assert statistics.writer_owner is None
            assert len(statistics.reader_owners) == 1

        assert not lock.locked()
        statistics = lock.statistics()
        assert statistics.writer_owner is None
        assert statistics.reader_owners == ()

    async def test_writer_contextmanager(self) -> None:
        lock = RWLock()
        async with lock.writer:
            assert lock.locked()
            statistics = lock.statistics()
            assert statistics.writer_owner is not None
            assert statistics.reader_owners == ()

        assert not lock.locked()
        assert lock.statistics().writer_owner is None

    async def test_context_manager_is_reusable(self) -> None:
        lock = RWLock()
        async with lock.reader:
            pass
        async with lock.reader:
            pass
        async with lock.writer:
            pass

    async def test_multiple_readers(self) -> None:
        lock = RWLock()
        entered = 0

        async def reader() -> None:
            nonlocal entered
            async with lock.reader:
                entered += 1
                await event.wait()

        event = Event()
        async with create_task_group() as tg:
            tg.start_soon(reader)
            tg.start_soon(reader)
            await wait_all_tasks_blocked()
            assert entered == 2
            assert len(lock.statistics().reader_owners) == 2
            event.set()

        assert not lock.locked()

    async def test_writer_blocks_readers(self) -> None:
        lock = RWLock()
        results = []

        async def reader() -> None:
            async with lock.reader:
                results.append("reader")

        async with create_task_group() as tg, lock.writer:
            tg.start_soon(reader)
            await wait_all_tasks_blocked()
            assert results == []

        assert results == ["reader"]

    async def test_writer_blocks_writer(self) -> None:
        lock = RWLock()
        results = []

        async def writer() -> None:
            async with lock.writer:
                results.append("writer2")

        async with create_task_group() as tg, lock.writer:
            tg.start_soon(writer)
            await wait_all_tasks_blocked()
            assert results == []

        assert results == ["writer2"]

    async def test_reader_blocks_writer(self) -> None:
        lock = RWLock()
        results = []

        async def writer() -> None:
            async with lock.writer:
                results.append("writer")

        async with create_task_group() as tg, lock.reader:
            tg.start_soon(writer)
            await wait_all_tasks_blocked()
            assert results == []

        assert results == ["writer"]

    async def test_writer_fairness_new_readers_wait_behind(self) -> None:
        """A reader arriving after a waiting writer must not jump ahead of it."""
        lock = RWLock()
        order = []
        gate = Event()

        async def writer() -> None:
            async with lock.writer:
                order.append("writer")

        async def late_reader() -> None:
            await gate.wait()
            async with lock.reader:
                order.append("late-reader")

        async with create_task_group() as tg:
            tg.start_soon(writer)
            tg.start_soon(late_reader)
            async with lock.reader:
                await wait_all_tasks_blocked()
                assert lock.statistics().tasks_waiting_to_write == 1
                gate.set()
                await wait_all_tasks_blocked()
                assert lock.statistics().tasks_waiting_to_read == 1
                assert order == []

            await wait_all_tasks_blocked()
            assert order == ["writer", "late-reader"]

    async def test_fair_fifo_ordering(self) -> None:
        """Queued waiters proceed in queue order; consecutive readers run as a batch."""
        lock = RWLock()
        order = []
        release = Event()

        async def queued(name: str, write: bool) -> None:
            side = lock.writer if write else lock.reader
            async with side:
                order.append(name)
                await release.wait()

        async with create_task_group() as tg, lock.reader:
            for name, write in (
                ("w1", True),
                ("r1", False),
                ("r2", False),
                ("w2", True),
                ("r3", False),
            ):
                tg.start_soon(queued, name, write)
                await wait_all_tasks_blocked()

            assert order == []
            assert lock.statistics().tasks_waiting_to_write == 2
            assert lock.statistics().tasks_waiting_to_read == 3
            release.set()

        assert order[0] == "w1"
        assert set(order[1:3]) == {"r1", "r2"}
        assert order[3:] == ["w2", "r3"]

    async def test_last_reader_releases_exactly_one_writer(self) -> None:
        """When the last reader leaves, only one writer may be admitted."""
        lock = RWLock()
        active_writers = 0
        max_active_writers = 0
        readers_started = Event()
        release_readers = Event()
        release_writer = Event()

        async def reader() -> None:
            async with lock.reader:
                readers_started.set()
                await release_readers.wait()

        async def writer() -> None:
            nonlocal active_writers, max_active_writers
            async with lock.writer:
                active_writers += 1
                max_active_writers = max(max_active_writers, active_writers)
                await release_writer.wait()
                active_writers -= 1

        async with create_task_group() as tg:
            tg.start_soon(reader)
            tg.start_soon(reader)
            await readers_started.wait()
            await wait_all_tasks_blocked()
            tg.start_soon(writer)
            tg.start_soon(writer)
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_write == 2
            release_readers.set()
            await wait_all_tasks_blocked()
            assert active_writers == 1
            assert max_active_writers == 1
            release_writer.set()

        assert max_active_writers == 1

    async def test_cancelled_writer_wakes_readers_in_batch(self) -> None:
        """Cancelling a head writer must wake the queued readers together."""
        lock = RWLock()
        active_readers = 0
        start_readers = Event()
        release_readers = Event()

        async def queued_reader() -> None:
            await start_readers.wait()
            async with lock.reader:
                nonlocal active_readers
                active_readers += 1
                await release_readers.wait()

        async with create_task_group() as tg, lock.reader:
            writer_task = tg.create_task(lock.acquire_write(), name="writer")
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_write == 1
            tg.start_soon(queued_reader)
            tg.start_soon(queued_reader)
            start_readers.set()
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_read == 2
            assert active_readers == 0
            writer_task.cancel()
            await wait_all_tasks_blocked()
            assert active_readers == 2
            release_readers.set()

        assert not lock.locked()

    async def test_cancel_queued_reader(self) -> None:
        lock = RWLock()
        async with create_task_group() as tg, lock.writer:
            reader_task = tg.create_task(lock.acquire_read(), name="reader")
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_read == 1
            reader_task.cancel()
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_read == 0

        assert not lock.locked()

    async def test_cancel_queued_writer_keeps_lock_usable(self) -> None:
        lock = RWLock()
        async with create_task_group() as tg, lock.writer:
            writer_task = tg.create_task(lock.acquire_write(), name="writer")
            await wait_all_tasks_blocked()
            writer_task.cancel()
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_write == 0

        async with lock.writer:
            assert lock.statistics().writer_owner is not None

    async def test_grant_and_cancel_race_writer_ownership_not_lost(self) -> None:
        """
        If ownership is granted in the same scheduling step that cancels the waiter,
        the lock must be released cleanly instead of becoming permanently held.

        """
        lock = RWLock()
        lock.acquire_read_nowait()

        async with create_task_group() as tg:
            writer_task = tg.create_task(lock.acquire_write(), name="writer")
            await wait_all_tasks_blocked()
            writer_task.cancel()
            lock.release_read()
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_write == 0

        assert not lock.locked()
        lock.acquire_write_nowait()

    async def test_grant_and_cancel_race_reader_ownership_not_lost(self) -> None:
        lock = RWLock()
        lock.acquire_write_nowait()

        async with create_task_group() as tg:
            reader_task = tg.create_task(lock.acquire_read(), name="reader")
            await wait_all_tasks_blocked()
            reader_task.cancel()
            lock.release_write()
            await wait_all_tasks_blocked()
            assert lock.statistics().tasks_waiting_to_read == 0

        assert not lock.locked()
        lock.acquire_write_nowait()

    @pytest.mark.parametrize("anyio_backend", asyncio_params)
    async def test_asyncio_native_cancel_after_grant_writer(self) -> None:
        """
        Regression test for the asyncio-specific race where the future result
        (ownership) and the cancellation are delivered in the same step.

        """
        lock = RWLock()
        lock.acquire_read_nowait()
        loop = asyncio.get_running_loop()
        task1 = loop.create_task(lock.acquire_write(), name="task1")

        async def second_writer() -> None:
            await lock.acquire_write()
            lock.release_write()

        task2 = loop.create_task(second_writer(), name="task2")
        await asyncio.sleep(0)

        lock.release_read()
        task1.cancel()
        await asyncio.wait([task1, task2], timeout=5)

        statistics = lock.statistics()
        assert statistics.writer_owner is None
        assert statistics.tasks_waiting_to_write == 0
        assert not lock.locked()
        lock.acquire_write_nowait()

    async def test_reentrant_read_raises(self) -> None:
        lock = RWLock()
        async with lock.reader:
            with pytest.raises(RuntimeError, match="already held read lock"):
                await lock.acquire_read()

    async def test_reentrant_write_raises(self) -> None:
        lock = RWLock()
        async with lock.writer:
            with pytest.raises(RuntimeError, match="already held write lock"):
                await lock.acquire_write()

    async def test_upgrade_raises(self) -> None:
        lock = RWLock()
        async with lock.reader:
            with pytest.raises(RuntimeError, match="does not support upgrading"):
                await lock.acquire_write()

    async def test_downgrade_raises(self) -> None:
        lock = RWLock()
        async with lock.writer:
            with pytest.raises(RuntimeError, match="does not support downgrading"):
                await lock.acquire_read()

    async def test_release_read_without_holding_raises(self) -> None:
        lock = RWLock()
        with pytest.raises(RuntimeError, match="not holding the read lock"):
            lock.release_read()

    async def test_release_write_without_holding_raises(self) -> None:
        lock = RWLock()
        with pytest.raises(RuntimeError, match="not holding the write lock"):
            lock.release_write()

    async def test_nowait_wouldblock(self) -> None:
        lock = RWLock()

        async def try_read() -> None:
            pytest.raises(WouldBlock, lock.acquire_read_nowait)

        async def try_write() -> None:
            pytest.raises(WouldBlock, lock.acquire_write_nowait)

        lock.acquire_write_nowait()
        async with create_task_group() as tg:
            tg.start_soon(try_read)
            tg.start_soon(try_write)
            await wait_all_tasks_blocked()

        lock.release_write()
        lock.acquire_read_nowait()
        async with create_task_group() as tg:
            tg.start_soon(try_write)
            await wait_all_tasks_blocked()

        lock.release_read()
        lock.acquire_write_nowait()
        lock.release_write()

    async def test_nowait_respects_waiting_writer(self) -> None:
        lock = RWLock()

        async def try_read() -> None:
            pytest.raises(WouldBlock, lock.acquire_read_nowait)

        async with create_task_group() as tg, lock.reader:
            tg.create_task(lock.acquire_write(), name="writer")
            await wait_all_tasks_blocked()
            tg.start_soon(try_read)
            await wait_all_tasks_blocked()

    async def test_statistics(self) -> None:
        lock = RWLock()
        release_event = Event()

        async def writer() -> None:
            await lock.acquire_write()
            await release_event.wait()
            lock.release_write()

        async def reader() -> None:
            await lock.acquire_read()
            await release_event.wait()
            lock.release_read()

        statistics = lock.statistics()
        assert statistics.reader_owners == ()
        assert statistics.writer_owner is None
        assert statistics.tasks_waiting_to_read == 0
        assert statistics.tasks_waiting_to_write == 0

        async with create_task_group() as tg, lock.reader:
            tg.start_soon(writer)
            await wait_all_tasks_blocked()
            tg.start_soon(reader)
            await wait_all_tasks_blocked()
            statistics = lock.statistics()
            assert statistics.tasks_waiting_to_write == 1
            assert statistics.tasks_waiting_to_read == 1
            assert len(statistics.reader_owners) == 1
            release_event.set()

        assert not lock.locked()

    def test_instantiate_outside_event_loop(
        self, anyio_backend_name: str, anyio_backend_options: dict[str, Any]
    ) -> None:
        async def use_lock() -> None:
            async with lock.reader:
                pass
            async with lock.writer:
                pass

        lock = RWLock()
        statistics = lock.statistics()
        assert statistics.reader_owners == ()
        assert statistics.writer_owner is None
        assert statistics.tasks_waiting_to_read == 0
        assert statistics.tasks_waiting_to_write == 0
        run(use_lock, backend=anyio_backend_name, backend_options=anyio_backend_options)


class TestEvent:
    async def test_event(self) -> None:
        async def setter() -> None:
            assert not event.is_set()
            event.set()

        event = Event()
        async with create_task_group() as tg:
            tg.start_soon(setter)
            await event.wait()

        assert event.is_set()

    async def test_event_cancel(self) -> None:
        task_started = event_set = False

        async def task() -> None:
            nonlocal task_started, event_set
            task_started = True
            await event.wait()
            event_set = True

        event = Event()
        async with create_task_group() as tg:
            tg.start_soon(task)
            tg.cancel_scope.cancel()
            event.set()

        assert task_started
        assert not event_set

    async def test_event_wait_before_set_before_cancel(self) -> None:
        setter_started = waiter_woke = False

        async def setter() -> None:
            nonlocal setter_started
            setter_started = True
            assert not event.is_set()
            event.set()
            tg.cancel_scope.cancel()

        event = Event()
        async with create_task_group() as tg:
            tg.start_soon(setter)
            await event.wait()
            waiter_woke = True

        assert setter_started
        assert waiter_woke

    async def test_statistics(self) -> None:
        async def waiter() -> None:
            await event.wait()

        event = Event()
        async with create_task_group() as tg:
            assert event.statistics().tasks_waiting == 0
            for i in range(1, 3):
                tg.start_soon(waiter)
                await wait_all_tasks_blocked()
                assert event.statistics().tasks_waiting == i

            event.set()

        assert event.statistics().tasks_waiting == 0

    def test_instantiate_outside_event_loop(
        self, anyio_backend_name: str, anyio_backend_options: dict[str, Any]
    ) -> None:
        event = Event()
        assert not event.is_set()
        assert event.statistics().tasks_waiting == 0

        event.set()
        assert event.is_set()

        run(
            event.wait,
            backend=anyio_backend_name,
            backend_options=anyio_backend_options,
        )


class TestCondition:
    async def test_contextmanager(self) -> None:
        async def notifier() -> None:
            async with condition:
                condition.notify_all()

        condition = Condition()
        async with create_task_group() as tg, condition:
            assert condition.locked()
            tg.start_soon(notifier)
            await condition.wait()

    async def test_manual_acquire(self) -> None:
        async def notifier() -> None:
            await condition.acquire()
            try:
                condition.notify_all()
            finally:
                condition.release()

        condition = Condition()
        async with create_task_group() as tg:
            await condition.acquire()
            try:
                assert condition.locked()
                tg.start_soon(notifier)
                await condition.wait()
            finally:
                condition.release()

    async def test_acquire_nowait(self) -> None:
        condition = Condition()
        condition.acquire_nowait()
        assert condition.locked()

    async def test_acquire_nowait_wouldblock(self) -> None:
        async def try_lock() -> None:
            pytest.raises(WouldBlock, condition.acquire_nowait)

        condition = Condition()
        async with condition, create_task_group() as tg:
            assert condition.locked()
            tg.start_soon(try_lock)

    async def test_wait_cancel(self) -> None:
        task_started = notified = False

        async def task() -> None:
            nonlocal task_started, notified
            task_started = True
            async with condition:
                event.set()
                await condition.wait()
                notified = True

        event = Event()
        condition = Condition()
        async with create_task_group() as tg:
            tg.start_soon(task)
            await event.wait()
            await wait_all_tasks_blocked()
            tg.cancel_scope.cancel()

        assert task_started
        assert not notified

    async def test_notification_handover_on_cancel(self) -> None:
        condition = Condition()

        async def acquirer(scope: AbstractContextManager[CancelScope]) -> None:
            with scope:
                async with condition:
                    await condition.wait()

        async with create_task_group() as tg:
            scope1 = CancelScope()
            scope2 = fail_after(3)
            tg.start_soon(acquirer, scope1)
            tg.start_soon(acquirer, scope2)
            await wait_all_tasks_blocked()
            async with condition:
                scope1.cancel()
                condition.notify(1)

    async def test_wait_no_lock(self) -> None:
        condition = Condition()
        with pytest.raises(
            RuntimeError, match="The current task is not holding the underlying lock"
        ):
            await condition.wait()

    async def test_notify_with_shared_lock(self) -> None:
        lock = Lock()
        condition = Condition(lock)
        async with lock:
            condition.notify()
            condition.notify_all()

    async def test_notify_no_lock(self) -> None:
        condition = Condition()
        with pytest.raises(
            RuntimeError, match="The current task is not holding the underlying lock"
        ):
            condition.notify()

        with pytest.raises(
            RuntimeError, match="The current task is not holding the underlying lock"
        ):
            condition.notify_all()

    async def test_notify_after_release(self) -> None:
        condition = Condition()
        await condition.acquire()
        condition.release()
        with pytest.raises(
            RuntimeError, match="The current task is not holding the underlying lock"
        ):
            condition.notify()

    async def test_statistics(self) -> None:
        async def waiter() -> None:
            async with condition:
                await condition.wait()

        condition = Condition()
        async with create_task_group() as tg:
            assert not condition.statistics().lock_statistics.locked
            assert condition.statistics().tasks_waiting == 0
            async with condition:
                assert condition.statistics().lock_statistics.locked
                assert condition.statistics().tasks_waiting == 0

            for i in range(1, 3):
                tg.start_soon(waiter)
                await wait_all_tasks_blocked()
                assert condition.statistics().tasks_waiting == i

            for i in range(1, -1, -1):
                async with condition:
                    condition.notify(1)

                await wait_all_tasks_blocked()
                assert condition.statistics().tasks_waiting == i

        assert not condition.statistics().lock_statistics.locked
        assert condition.statistics().tasks_waiting == 0

    def test_instantiate_outside_event_loop(
        self, anyio_backend_name: str, anyio_backend_options: dict[str, Any]
    ) -> None:
        async def use_condition() -> None:
            async with condition:
                pass

        condition = Condition()
        assert condition.statistics().tasks_waiting == 0

        run(
            use_condition,
            backend=anyio_backend_name,
            backend_options=anyio_backend_options,
        )

    async def test_wait_for(self) -> None:
        result = None

        async def waiter() -> None:
            nonlocal result
            async with condition:
                result = await condition.wait_for(lambda: value)

        value = None
        condition = Condition()
        async with create_task_group() as tg:
            tg.start_soon(waiter)
            await wait_all_tasks_blocked()
            async with condition:
                condition.notify_all()

            await wait_all_tasks_blocked()
            assert result is None
            value = "foo"
            async with condition:
                condition.notify_all()

        assert result == "foo"


class TestSemaphore:
    async def test_contextmanager(self) -> None:
        async def acquire() -> None:
            async with semaphore:
                assert semaphore.value in (0, 1)

        semaphore = Semaphore(2)
        async with create_task_group() as tg:
            tg.start_soon(acquire, name="task 1")
            tg.start_soon(acquire, name="task 2")

        assert semaphore.value == 2

    async def test_manual_acquire(self) -> None:
        async def acquire() -> None:
            await semaphore.acquire()
            try:
                assert semaphore.value in (0, 1)
            finally:
                semaphore.release()

        semaphore = Semaphore(2)
        async with create_task_group() as tg:
            tg.start_soon(acquire, name="task 1")
            tg.start_soon(acquire, name="task 2")

        assert semaphore.value == 2

    async def test_fast_acquire(self) -> None:
        """
        Test that fast_acquire=True does not yield back control to the event loop when
        there is no contention.

        """
        other_task_called = False

        async def other_task() -> None:
            nonlocal other_task_called
            other_task_called = True

        semaphore = Semaphore(1, fast_acquire=True)
        async with create_task_group() as tg:
            tg.start_soon(other_task)
            async with semaphore:
                assert not other_task_called

    async def test_acquire_nowait(self) -> None:
        semaphore = Semaphore(1)
        semaphore.acquire_nowait()
        assert semaphore.value == 0
        pytest.raises(WouldBlock, semaphore.acquire_nowait)

    @pytest.mark.parametrize(
        "release_first",
        [pytest.param(False, id="releaselast"), pytest.param(True, id="releasefirst")],
    )
    async def test_cancel_during_acquire(self, release_first: bool) -> None:
        acquired = False

        async def task(*, task_status: TaskStatus) -> None:
            nonlocal acquired
            task_status.started()
            async with semaphore:
                acquired = True

        semaphore = Semaphore(1)
        async with create_task_group() as tg:
            await semaphore.acquire()
            await tg.start(task)
            tg.cancel_scope.cancel()
            with CancelScope(shield=True):
                if release_first:
                    semaphore.release()
                    await wait_all_tasks_blocked()
                else:
                    await wait_all_tasks_blocked()
                    semaphore.release()

        assert not acquired
        assert semaphore.value == 1

    @pytest.mark.parametrize("max_value", [2, None])
    async def test_max_value(self, max_value: int | None) -> None:
        semaphore = Semaphore(0, max_value=max_value)
        assert semaphore.max_value == max_value

    async def test_max_value_exceeded(self) -> None:
        semaphore = Semaphore(1, max_value=2)
        semaphore.release()
        pytest.raises(ValueError, semaphore.release)

    async def test_statistics(self) -> None:
        async def waiter() -> None:
            async with semaphore:
                pass

        semaphore = Semaphore(1)
        async with create_task_group() as tg:
            assert semaphore.statistics().tasks_waiting == 0
            async with semaphore:
                assert semaphore.statistics().tasks_waiting == 0
                for i in range(1, 3):
                    tg.start_soon(waiter)
                    await wait_all_tasks_blocked()
                    assert semaphore.statistics().tasks_waiting == i

        assert semaphore.statistics().tasks_waiting == 0

    async def test_acquire_race(self) -> None:
        """
        Test against a race condition: when a task waiting on acquire() is rescheduled
        but another task snatches the last available slot, the task should not raise
        WouldBlock.

        """
        semaphore = Semaphore(1)
        async with create_task_group() as tg:
            semaphore.acquire_nowait()
            tg.start_soon(semaphore.acquire)
            await wait_all_tasks_blocked()
            semaphore.release()
            pytest.raises(WouldBlock, semaphore.acquire_nowait)

    @pytest.mark.parametrize("anyio_backend", asyncio_params)
    async def test_asyncio_deadlock(self) -> None:
        """Regression test for #398."""
        semaphore = Semaphore(1)

        async def acquire() -> None:
            async with semaphore:
                await asyncio.sleep(0)

        loop = asyncio.get_running_loop()
        task1 = loop.create_task(acquire())
        task2 = loop.create_task(acquire())
        await asyncio.sleep(0)
        task1.cancel()
        await asyncio.wait_for(task2, 1)

    @pytest.mark.parametrize("anyio_backend", asyncio_params)
    async def test_cancel_after_release(self) -> None:
        """
        Test that a native asyncio cancellation will not cause a semaphore ownership
        to get lost between a release() and the resumption of acquire().

        """
        # Create the semaphore in such a way that any task acquiring it will block
        semaphore = Semaphore(0, max_value=1)

        # Start a task that gets blocked on trying to acquire the semaphore
        loop = asyncio.get_running_loop()
        task1 = loop.create_task(semaphore.acquire())
        await asyncio.sleep(0)

        # Trigger the acquiring task to be rescheduled, but also cancel it right away
        semaphore.release()
        task1.cancel()
        assert semaphore.value == 0
        await asyncio.wait([task1], timeout=5)

        # The acquire() method should've released the semaphore because acquisition
        # failed due to cancellation
        assert semaphore.value == 1
        assert semaphore.statistics().tasks_waiting == 0
        semaphore.acquire_nowait()

    async def test_cancelled_after_acquire(self) -> None:
        semaphore = Semaphore(1, max_value=1)
        semaphore.acquire_nowait()
        async with create_task_group() as tg:
            task1 = tg.create_task(semaphore.acquire())
            await wait_all_tasks_blocked()
            task1.cancel()
            semaphore.release()
            assert semaphore.statistics().tasks_waiting == 0
            with fail_after(3):
                await semaphore.acquire()

    def test_instantiate_outside_event_loop(
        self, anyio_backend_name: str, anyio_backend_options: dict[str, Any]
    ) -> None:
        async def use_semaphore() -> None:
            async with semaphore:
                pass

        semaphore = Semaphore(1, max_value=3)
        assert semaphore.value == 1
        assert semaphore.max_value == 3
        assert semaphore.statistics().tasks_waiting == 0

        run(
            use_semaphore,
            backend=anyio_backend_name,
            backend_options=anyio_backend_options,
        )


class TestCapacityLimiter:
    async def test_bad_init_type(self) -> None:
        pytest.raises(TypeError, CapacityLimiter, 1.0).match(
            "total_tokens must be an int or math.inf"
        )

    async def test_bad_init_value(self) -> None:
        pytest.raises(ValueError, CapacityLimiter, -1).match(
            "total_tokens must be >= 0"
        )

    async def test_zero_tokens(self) -> None:
        limiter = CapacityLimiter(0)
        assert limiter.total_tokens == 0

    async def test_borrow(self) -> None:
        limiter = CapacityLimiter(2)
        assert limiter.total_tokens == 2
        assert limiter.available_tokens == 2
        assert limiter.borrowed_tokens == 0
        async with limiter:
            assert limiter.total_tokens == 2
            assert limiter.available_tokens == 1
            assert limiter.borrowed_tokens == 1

    async def test_limit(self) -> None:
        value = 0

        async def taskfunc() -> None:
            nonlocal value
            for _ in range(5):
                async with limiter:
                    assert value == 0
                    value = 1
                    await wait_all_tasks_blocked()
                    value = 0

        limiter = CapacityLimiter(1)
        async with create_task_group() as tg:
            for _ in range(3):
                tg.start_soon(taskfunc)

    async def test_borrow_twice(self) -> None:
        limiter = CapacityLimiter(1)
        await limiter.acquire()
        with pytest.raises(RuntimeError) as exc:
            await limiter.acquire()

        exc.match(
            "this borrower is already holding one of this CapacityLimiter's tokens"
        )

    async def test_bad_release(self) -> None:
        limiter = CapacityLimiter(1)
        with pytest.raises(RuntimeError) as exc:
            limiter.release()

        exc.match("this borrower isn't holding any of this CapacityLimiter's tokens")

    async def test_increase_tokens(self) -> None:
        async def setter() -> None:
            # Wait until waiter() is inside the limiter block
            await event1.wait()
            async with limiter:
                # This can only happen when total_tokens has been increased
                event2.set()

        async def waiter() -> None:
            async with limiter:
                event1.set()
                await event2.wait()

        limiter = CapacityLimiter(1)
        event1, event2 = Event(), Event()
        async with create_task_group() as tg:
            tg.start_soon(setter)
            tg.start_soon(waiter)
            await wait_all_tasks_blocked()
            assert event1.is_set()
            assert not event2.is_set()
            limiter.total_tokens = 2

        assert event2.is_set()

    async def test_current_default_thread_limiter(self) -> None:
        limiter = to_thread.current_default_thread_limiter()
        assert isinstance(limiter, CapacityLimiter)
        assert limiter.total_tokens == 40

    async def test_statistics(self) -> None:
        async def waiter() -> None:
            async with limiter:
                pass

        limiter = CapacityLimiter(1)
        assert limiter.statistics().total_tokens == 1
        assert limiter.statistics().borrowed_tokens == 0
        assert limiter.statistics().tasks_waiting == 0
        async with create_task_group() as tg, limiter:
            assert limiter.statistics().borrowed_tokens == 1
            assert limiter.statistics().tasks_waiting == 0
            for i in range(1, 3):
                tg.start_soon(waiter)
                await wait_all_tasks_blocked()
                assert limiter.statistics().tasks_waiting == i

        assert limiter.statistics().tasks_waiting == 0
        assert limiter.statistics().borrowed_tokens == 0

    @pytest.mark.parametrize("anyio_backend", asyncio_params)
    async def test_asyncio_deadlock(self) -> None:
        """Regression test for #398."""
        limiter = CapacityLimiter(1)

        async def acquire() -> None:
            async with limiter:
                await asyncio.sleep(0)

        loop = asyncio.get_running_loop()
        task1 = loop.create_task(acquire())
        task2 = loop.create_task(acquire())
        await asyncio.sleep(0)
        task1.cancel()
        await asyncio.wait_for(task2, 1)

    async def test_ordered_queue(self) -> None:
        limiter = CapacityLimiter(1)
        results = []
        event = Event()

        async def append(x: int, task_status: TaskStatus) -> None:
            task_status.started()
            async with limiter:
                await event.wait()
                results.append(x)

        async with create_task_group() as tg:
            for i in [0, 1, 2]:
                await tg.start(append, i)

            event.set()

        assert results == [0, 1, 2]

    async def test_increase_tokens_lets_others_acquire(self) -> None:
        limiter = CapacityLimiter(1)
        entered_events = [Event() for _ in range(3)]
        continue_event = Event()

        async def worker(entered_event: Event) -> None:
            async with limiter:
                entered_event.set()
                await continue_event.wait()

        async with create_task_group() as tg:
            for event in entered_events[:2]:
                tg.start_soon(worker, event)

            # One task should be able to acquire the limiter while the other is left
            # waiting
            await wait_all_tasks_blocked()
            assert sum(ev.is_set() for ev in entered_events) == 1

            # Increase the total tokens and start another worker.
            # All tasks should be able to acquire the limiter now.
            limiter.total_tokens = 3
            tg.start_soon(worker, entered_events[2])
            with fail_after(1):
                for ev in entered_events[1:]:
                    await ev.wait()

            # Allow all tasks to exit
            continue_event.set()

    async def test_increase_tokens_does_not_oversubscribe(self) -> None:
        """
        Raising ``total_tokens`` must not grant more waiters than the spare
        capacity, even when the limiter is over-subscribed because
        ``total_tokens`` was previously lowered below the number of current
        borrowers.
        """
        limiter = CapacityLimiter(2)
        limiter.acquire_on_behalf_of_nowait("A")
        limiter.acquire_on_behalf_of_nowait("B")

        async with create_task_group() as tg:
            tg.start_soon(limiter.acquire)
            tg.start_soon(limiter.acquire)
            await wait_all_tasks_blocked()
            assert limiter.statistics().borrowed_tokens == 2
            assert limiter.statistics().tasks_waiting == 2

            limiter.total_tokens = 1
            limiter.total_tokens = 2
            await wait_all_tasks_blocked()
            assert limiter.statistics().borrowed_tokens == 2
            assert limiter.statistics().tasks_waiting == 2
            tg.cancel()

    def test_instantiate_outside_event_loop(
        self, anyio_backend_name: str, anyio_backend_options: dict[str, Any]
    ) -> None:
        async def use_limiter() -> None:
            async with limiter:
                pass

        limiter = CapacityLimiter(1)
        limiter.total_tokens = 2

        with pytest.raises(TypeError):
            limiter.total_tokens = "2"  # type: ignore[assignment]

        with pytest.raises(TypeError):
            limiter.total_tokens = 3.0

        assert limiter.total_tokens == 2
        assert limiter.borrowed_tokens == 0
        statistics = limiter.statistics()
        assert statistics.total_tokens == 2
        assert statistics.borrowed_tokens == 0
        assert statistics.borrowers == ()
        assert statistics.tasks_waiting == 0

        run(
            use_limiter,
            backend=anyio_backend_name,
            backend_options=anyio_backend_options,
        )

    def test_zero_tokens_outside_event_loop(self) -> None:
        # Regression test for the CapacityLimiterAdapter setter rejecting 0,
        # which contradicted the 4.12 behavior of allowing 0 total tokens
        limiter = CapacityLimiter(1)
        limiter.total_tokens = 0
        assert limiter.total_tokens == 0
        assert CapacityLimiter(0).total_tokens == 0

    def test_float_infinity_outside_event_loop(self) -> None:
        # Regression test: the CapacityLimiterAdapter setter checked for
        # infinity with the identity operator (``value is not math.inf``), so
        # ``float("inf")`` -- a distinct object that merely equals ``math.inf``
        # -- was rejected outside an event loop, while every backend setter
        # (which uses ``math.isinf``) accepts it.
        assert CapacityLimiter(float("inf")).total_tokens == math.inf
        assert CapacityLimiter(math.inf).total_tokens == math.inf

        limiter = CapacityLimiter(1)
        limiter.total_tokens = float("inf")
        assert limiter.total_tokens == math.inf

    async def test_total_tokens_as_kwarg(self) -> None:
        # Regression test for #515
        limiter = CapacityLimiter(total_tokens=1)
        assert limiter.total_tokens == 1

    async def test_acquire_cancelled(self) -> None:
        # Regression test for #947
        limiter = CapacityLimiter(1)

        async def borrower(
            event: Event, *, task_status: TaskStatus[CancelScope]
        ) -> None:
            with CancelScope() as scope:
                task_status.started(scope)
                async with limiter:
                    event.set()
                    await checkpoint()

        async with create_task_group() as tg:
            async with limiter:
                event1 = Event()
                scope1 = await tg.start(borrower, event1)
                event2 = Event()
                await tg.start(borrower, event2)
                scope1.cancel()

            with move_on_after(0.1):
                await event2.wait()
                return

            tg.cancel_scope.cancel()

        pytest.fail("The second borrower failed to acquire the limiter")

    async def test_acquire_nowait(self) -> None:
        async def borrower() -> None:
            limiter.acquire_nowait()

        limiter = CapacityLimiter(1)
        limiter.acquire_nowait()
        with pytest.RaisesGroup(pytest.RaisesExc(WouldBlock)):
            async with create_task_group() as tg:
                tg.start_soon(borrower)

    async def test_acquire_on_behalf_of_nowait(self) -> None:
        borrower1, borrower2 = object(), object()
        limiter = CapacityLimiter(1)
        limiter.acquire_on_behalf_of_nowait(borrower1)
        with pytest.raises(WouldBlock):
            limiter.acquire_on_behalf_of_nowait(borrower2)

    async def test_nowait_acquire_after_release_does_not_oversubscribe(self) -> None:
        # Regression test for #1170: a non-blocking acquire issued in the window
        # between releasing a token (which notifies the next waiter) and that
        # waiter actually resuming must not slip through, as the freed token is
        # already reserved for the woken waiter. The over-granting bug was
        # specific to the asyncio backend, but the invariant holds on both.
        limiter = CapacityLimiter(1)
        limiter.acquire_on_behalf_of_nowait("A")

        async def waiter() -> None:
            await limiter.acquire_on_behalf_of("B")

        async with create_task_group() as tg:
            tg.start_soon(waiter)
            await wait_all_tasks_blocked()
            assert limiter.statistics().tasks_waiting == 1

            # Frees the only token and reserves it for the still-parked "B"; no
            # token is available, so the nowait acquire must raise WouldBlock.
            limiter.release_on_behalf_of("A")
            with pytest.raises(WouldBlock):
                limiter.acquire_on_behalf_of_nowait("X")

        assert limiter.borrowed_tokens <= limiter.total_tokens
        assert limiter.available_tokens >= 0
        assert limiter.statistics().borrowers == ("B",)
        limiter.release_on_behalf_of("B")
