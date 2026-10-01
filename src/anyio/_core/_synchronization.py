from __future__ import annotations

import math
import sys
from collections import deque
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import TypeVar

from ..lowlevel import cancel_shielded_checkpoint, checkpoint_if_cancelled
from ._eventloop import get_async_backend
from ._exceptions import BusyResourceError, NoEventLoopError, WouldBlock
from ._tasks import CancelScope
from ._testing import TaskInfo, get_current_task

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

T = TypeVar("T")


@dataclass(frozen=True)
class EventStatistics:
    """
    :ivar int tasks_waiting: number of tasks waiting on :meth:`~.Event.wait`
    """

    tasks_waiting: int


@dataclass(frozen=True)
class CapacityLimiterStatistics:
    """
    :ivar int borrowed_tokens: number of tokens currently borrowed by tasks
    :ivar float total_tokens: total number of available tokens
    :ivar tuple borrowers: tasks or other objects currently holding tokens borrowed from
        this limiter
    :ivar int tasks_waiting: number of tasks waiting on
        :meth:`~.CapacityLimiter.acquire` or
        :meth:`~.CapacityLimiter.acquire_on_behalf_of`
    """

    borrowed_tokens: int
    total_tokens: float
    borrowers: tuple[object, ...]
    tasks_waiting: int


@dataclass(frozen=True)
class LockStatistics:
    """
    :ivar bool locked: flag indicating if this lock is locked or not
    :ivar ~anyio.TaskInfo owner: task currently holding the lock (or ``None`` if the
        lock is not held by any task)
    :ivar int tasks_waiting: number of tasks waiting on :meth:`~.Lock.acquire`
    """

    locked: bool
    owner: TaskInfo | None
    tasks_waiting: int


@dataclass(frozen=True)
class RWLockStatistics:
    """
    :ivar tuple[~anyio.TaskInfo, ...] readers: tasks currently holding the read lock
    :ivar ~anyio.TaskInfo writer: task currently holding the write lock (or ``None``
        if the write lock is not held by any task)
    :ivar int tasks_waiting_read: number of tasks waiting to acquire the read lock
    :ivar int tasks_waiting_write: number of tasks waiting to acquire the write lock

    .. versionadded:: 4.16
    """

    readers: tuple[TaskInfo, ...]
    writer: TaskInfo | None
    tasks_waiting_read: int
    tasks_waiting_write: int


@dataclass(frozen=True)
class ConditionStatistics:
    """
    :ivar int tasks_waiting: number of tasks blocked on :meth:`~.Condition.wait`
    :ivar ~anyio.LockStatistics lock_statistics: statistics of the underlying
        :class:`~.Lock`
    """

    tasks_waiting: int
    lock_statistics: LockStatistics


@dataclass(frozen=True)
class SemaphoreStatistics:
    """
    :ivar int tasks_waiting: number of tasks waiting on :meth:`~.Semaphore.acquire`

    """

    tasks_waiting: int


class Event:
    __slots__ = ("__weakref__",)

    def __new__(cls) -> Event:
        try:
            return get_async_backend().create_event()
        except NoEventLoopError:
            return EventAdapter()

    def set(self) -> None:
        """Set the flag, notifying all listeners."""
        raise NotImplementedError

    def is_set(self) -> bool:
        """Return ``True`` if the flag is set, ``False`` if not."""
        raise NotImplementedError

    async def wait(self) -> None:
        """
        Wait until the flag has been set.

        If the flag has already been set when this method is called, it returns
        immediately.

        """
        raise NotImplementedError

    def statistics(self) -> EventStatistics:
        """Return statistics about the current state of this event."""
        raise NotImplementedError


class EventAdapter(Event):
    __slots__ = "_internal_event", "_is_set"

    def __new__(cls) -> Self:
        return object.__new__(cls)

    def __init__(self) -> None:
        self._internal_event: Event | None = None
        self._is_set = False

    @property
    def _event(self) -> Event:
        if self._internal_event is None:
            self._internal_event = get_async_backend().create_event()
            if self._is_set:
                self._internal_event.set()

        return self._internal_event

    def set(self) -> None:
        if self._internal_event is None:
            self._is_set = True
        else:
            self._event.set()

    def is_set(self) -> bool:
        if self._internal_event is None:
            return self._is_set

        return self._internal_event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    def statistics(self) -> EventStatistics:
        if self._internal_event is None:
            return EventStatistics(tasks_waiting=0)

        return self._internal_event.statistics()


class Lock:
    __slots__ = ("__weakref__",)

    def __new__(cls, *, fast_acquire: bool = False) -> Lock:
        try:
            return get_async_backend().create_lock(fast_acquire=fast_acquire)
        except NoEventLoopError:
            return LockAdapter(fast_acquire=fast_acquire)

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.release()

    async def acquire(self) -> None:
        """Acquire the lock."""
        raise NotImplementedError

    def acquire_nowait(self) -> None:
        """
        Acquire the lock, without blocking.

        :raises ~anyio.WouldBlock: if the operation would block

        """
        raise NotImplementedError

    def release(self) -> None:
        """Release the lock."""
        raise NotImplementedError

    def locked(self) -> bool:
        """Return True if the lock is currently held."""
        raise NotImplementedError

    def statistics(self) -> LockStatistics:
        """
        Return statistics about the current state of this lock.

        .. versionadded:: 3.0
        """
        raise NotImplementedError


class LockAdapter(Lock):
    __slots__ = "_fast_acquire", "_internal_lock"

    def __new__(cls, *, fast_acquire: bool = False) -> Self:
        return object.__new__(cls)

    def __init__(self, *, fast_acquire: bool = False):
        self._internal_lock: Lock | None = None
        self._fast_acquire = fast_acquire

    @property
    def _lock(self) -> Lock:
        if self._internal_lock is None:
            self._internal_lock = get_async_backend().create_lock(
                fast_acquire=self._fast_acquire
            )

        return self._internal_lock

    async def __aenter__(self) -> None:
        await self._lock.acquire()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._internal_lock is not None:
            self._internal_lock.release()

    async def acquire(self) -> None:
        """Acquire the lock."""
        await self._lock.acquire()

    def acquire_nowait(self) -> None:
        """
        Acquire the lock, without blocking.

        :raises ~anyio.WouldBlock: if the operation would block

        """
        self._lock.acquire_nowait()

    def release(self) -> None:
        """Release the lock."""
        self._lock.release()

    def locked(self) -> bool:
        """Return True if the lock is currently held."""
        return self._lock.locked()

    def statistics(self) -> LockStatistics:
        """
        Return statistics about the current state of this lock.

        .. versionadded:: 3.0

        """
        if self._internal_lock is None:
            return LockStatistics(False, None, 0)

        return self._internal_lock.statistics()


class _RWLockWaiter:
    __slots__ = "event", "granted", "task", "write"

    def __init__(self, task: TaskInfo, *, write: bool) -> None:
        self.task = task
        self.write = write
        self.event = Event()
        self.granted = False


class RWLock:
    """
    A readers-writer lock, allowing either any number of concurrent readers or a
    single writer to hold the lock at any given time.

    The lock is fair: once a writer starts waiting, readers arriving later will
    queue up behind it instead of barging in. Waiters are granted the lock in
    arrival order, except that consecutive readers are granted the lock together.

    Reentrant acquisition and read-to-write upgrades are not supported, and raise
    :exc:`RuntimeError` immediately instead of deadlocking.

    .. versionadded:: 4.16
    """

    __slots__ = "__weakref__", "_readers", "_waiters", "_writer"

    def __init__(self) -> None:
        self._readers: set[TaskInfo] = set()
        self._writer: TaskInfo | None = None
        self._waiters: deque[_RWLockWaiter] = deque()

    def read(self) -> AbstractAsyncContextManager[None]:
        """
        Return an async context manager that acquires the read lock on entry and
        releases it on exit.
        """
        return _RWLockContext(self, write=False)

    def write(self) -> AbstractAsyncContextManager[None]:
        """
        Return an async context manager that acquires the write lock on entry and
        releases it on exit.
        """
        return _RWLockContext(self, write=True)

    def _schedule(self) -> None:
        # Grant the lock to eligible waiters, in arrival order. Readers queued up
        # at the front of the queue are granted the lock together, while writers
        # are granted the lock one at a time, and only once no readers remain.
        if self._writer is not None:
            return

        while self._waiters and not self._waiters[0].write:
            waiter = self._waiters.popleft()
            self._readers.add(waiter.task)
            waiter.granted = True
            waiter.event.set()

        if not self._readers and self._waiters:
            waiter = self._waiters.popleft()
            self._writer = waiter.task
            waiter.granted = True
            waiter.event.set()

    def _cancel_waiter(self, waiter: _RWLockWaiter) -> None:
        if waiter.granted:
            # The lock was granted to this waiter, but the task was cancelled
            # before it could resume, so release the lock on its behalf to avoid
            # losing the ownership
            if waiter.write:
                self._writer = None
            else:
                self._readers.discard(waiter.task)
        else:
            try:
                self._waiters.remove(waiter)
            except ValueError:
                pass

        # The cancellation may have made room for other waiters (e.g. readers
        # queued up behind a cancelled writer)
        self._schedule()

    async def acquire_read(self) -> None:
        """
        Acquire the read lock, waiting if necessary.

        Multiple tasks may hold the read lock simultaneously, but not while a
        task holds the write lock. If any writers are waiting, new readers queue
        up behind them.

        :raises RuntimeError: if the current task already holds this lock
        """
        task = get_current_task()
        if task in self._readers:
            raise RuntimeError(
                "Attempted to acquire the read lock of an RWLock already held by this task (reentrant locking is not supported)"
            )
        if self._writer == task:
            raise RuntimeError(
                "Attempted to acquire the read lock of an RWLock while holding its write lock"
            )

        if self._writer is None and not self._waiters:
            await checkpoint_if_cancelled()
            self._readers.add(task)
            try:
                await cancel_shielded_checkpoint()
            except BaseException:
                self._readers.discard(task)
                self._schedule()
                raise

            return

        waiter = _RWLockWaiter(task, write=False)
        self._waiters.append(waiter)
        try:
            await waiter.event.wait()
        except BaseException:
            self._cancel_waiter(waiter)
            raise

    async def acquire_write(self) -> None:
        """
        Acquire the write lock, waiting if necessary.

        Only one task may hold the write lock, and no readers may hold the lock
        while a task holds the write lock.

        :raises RuntimeError: if the current task already holds this lock
        """
        task = get_current_task()
        if self._writer == task:
            raise RuntimeError(
                "Attempted to acquire the write lock of an RWLock already held by this task (reentrant locking is not supported)"
            )
        if task in self._readers:
            raise RuntimeError(
                "Attempted to acquire the write lock of an RWLock while holding its read lock (upgrading is not supported)"
            )

        if self._writer is None and not self._readers and not self._waiters:
            await checkpoint_if_cancelled()
            self._writer = task
            try:
                await cancel_shielded_checkpoint()
            except BaseException:
                self._writer = None
                self._schedule()
                raise

            return

        waiter = _RWLockWaiter(task, write=True)
        self._waiters.append(waiter)
        try:
            await waiter.event.wait()
        except BaseException:
            self._cancel_waiter(waiter)
            raise

    def acquire_read_nowait(self) -> None:
        """
        Acquire the read lock, without blocking.

        :raises ~anyio.WouldBlock: if the operation would block
        :raises RuntimeError: if the current task already holds this lock
        """
        task = get_current_task()
        if task in self._readers:
            raise RuntimeError(
                "Attempted to acquire the read lock of an RWLock already held by this task (reentrant locking is not supported)"
            )
        if self._writer == task:
            raise RuntimeError(
                "Attempted to acquire the read lock of an RWLock while holding its write lock"
            )
        if self._writer is not None or self._waiters:
            raise WouldBlock

        self._readers.add(task)

    def acquire_write_nowait(self) -> None:
        """
        Acquire the write lock, without blocking.

        :raises ~anyio.WouldBlock: if the operation would block
        :raises RuntimeError: if the current task already holds this lock
        """
        task = get_current_task()
        if self._writer == task:
            raise RuntimeError(
                "Attempted to acquire the write lock of an RWLock already held by this task (reentrant locking is not supported)"
            )
        if task in self._readers:
            raise RuntimeError(
                "Attempted to acquire the write lock of an RWLock while holding its read lock (upgrading is not supported)"
            )
        if self._writer is not None or self._readers or self._waiters:
            raise WouldBlock

        self._writer = task

    def release_read(self) -> None:
        """
        Release the read lock held by the current task.

        :raises RuntimeError: if the current task does not hold the read lock
        """
        task = get_current_task()
        if task not in self._readers:
            raise RuntimeError(
                "Attempted to release the read lock of an RWLock without holding it"
            )

        self._readers.discard(task)
        self._schedule()

    def release_write(self) -> None:
        """
        Release the write lock held by the current task.

        :raises RuntimeError: if the current task does not hold the write lock
        """
        task = get_current_task()
        if self._writer != task:
            raise RuntimeError(
                "Attempted to release the write lock of an RWLock without holding it"
            )

        self._writer = None
        self._schedule()

    def statistics(self) -> RWLockStatistics:
        """
        Return statistics about the current state of this lock.
        """
        return RWLockStatistics(
            readers=tuple(self._readers),
            writer=self._writer,
            tasks_waiting_read=sum(not waiter.write for waiter in self._waiters),
            tasks_waiting_write=sum(waiter.write for waiter in self._waiters),
        )


class _RWLockContext:
    __slots__ = "_lock", "_write"

    def __init__(self, lock: RWLock, *, write: bool) -> None:
        self._lock = lock
        self._write = write

    async def __aenter__(self) -> None:
        if self._write:
            await self._lock.acquire_write()
        else:
            await self._lock.acquire_read()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._write:
            self._lock.release_write()
        else:
            self._lock.release_read()


class Condition:
    __slots__ = "__weakref__", "_lock", "_waiters"

    def __init__(self, lock: Lock | None = None):
        self._lock = lock or Lock()
        self._waiters: deque[Event] = deque()

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.release()

    def _check_acquired(self) -> None:
        if self._lock.statistics().owner != get_current_task():
            raise RuntimeError("The current task is not holding the underlying lock")

    async def acquire(self) -> None:
        """Acquire the underlying lock."""
        await self._lock.acquire()

    def acquire_nowait(self) -> None:
        """
        Acquire the underlying lock, without blocking.

        :raises ~anyio.WouldBlock: if the operation would block

        """
        self._lock.acquire_nowait()

    def release(self) -> None:
        """Release the underlying lock."""
        self._lock.release()

    def locked(self) -> bool:
        """Return True if the lock is set."""
        return self._lock.locked()

    def notify(self, n: int = 1) -> None:
        """Notify exactly n listeners."""
        self._check_acquired()
        for _ in range(n):
            try:
                event = self._waiters.popleft()
            except IndexError:
                break

            event.set()

    def notify_all(self) -> None:
        """Notify all the listeners."""
        self._check_acquired()
        for event in self._waiters:
            event.set()

        self._waiters.clear()

    async def wait(self) -> None:
        """Wait for a notification."""
        await checkpoint_if_cancelled()
        self._check_acquired()
        event = Event()
        self._waiters.append(event)
        self.release()
        try:
            await event.wait()
        except BaseException:
            if not event.is_set():
                self._waiters.remove(event)
            elif self._waiters:
                # This task was notified by could not act on it, so pass
                # it on to the next task
                self._waiters.popleft().set()

            raise
        finally:
            with CancelScope(shield=True):
                await self.acquire()

    async def wait_for(self, predicate: Callable[[], T]) -> T:
        """
        Wait until a predicate becomes true.

        :param predicate: a callable that returns a truthy value when the condition is
            met
        :return: the result of the predicate

        .. versionadded:: 4.11.0

        """
        while not (result := predicate()):
            await self.wait()

        return result

    def statistics(self) -> ConditionStatistics:
        """
        Return statistics about the current state of this condition.

        .. versionadded:: 3.0
        """
        return ConditionStatistics(len(self._waiters), self._lock.statistics())


class Semaphore:
    __slots__ = "__weakref__", "_fast_acquire"

    def __new__(
        cls,
        initial_value: int,
        *,
        max_value: int | None = None,
        fast_acquire: bool = False,
    ) -> Semaphore:
        try:
            return get_async_backend().create_semaphore(
                initial_value, max_value=max_value, fast_acquire=fast_acquire
            )
        except NoEventLoopError:
            return SemaphoreAdapter(initial_value, max_value=max_value)

    def __init__(
        self,
        initial_value: int,
        *,
        max_value: int | None = None,
        fast_acquire: bool = False,
    ):
        if not isinstance(initial_value, int):
            raise TypeError("initial_value must be an integer")
        if initial_value < 0:
            raise ValueError("initial_value must be >= 0")
        if max_value is not None:
            if not isinstance(max_value, int):
                raise TypeError("max_value must be an integer or None")
            if max_value < initial_value:
                raise ValueError(
                    "max_value must be equal to or higher than initial_value"
                )

        self._fast_acquire = fast_acquire

    async def __aenter__(self) -> Self:
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.release()

    async def acquire(self) -> None:
        """Decrement the semaphore value, blocking if necessary."""
        raise NotImplementedError

    def acquire_nowait(self) -> None:
        """
        Acquire the underlying lock, without blocking.

        :raises ~anyio.WouldBlock: if the operation would block

        """
        raise NotImplementedError

    def release(self) -> None:
        """Increment the semaphore value."""
        raise NotImplementedError

    @property
    def value(self) -> int:
        """The current value of the semaphore."""
        raise NotImplementedError

    @property
    def max_value(self) -> int | None:
        """The maximum value of the semaphore."""
        raise NotImplementedError

    def statistics(self) -> SemaphoreStatistics:
        """
        Return statistics about the current state of this semaphore.

        .. versionadded:: 3.0
        """
        raise NotImplementedError


class SemaphoreAdapter(Semaphore):
    __slots__ = "_initial_value", "_internal_semaphore", "_max_value"

    def __new__(
        cls,
        initial_value: int,
        *,
        max_value: int | None = None,
        fast_acquire: bool = False,
    ) -> Self:
        return object.__new__(cls)

    def __init__(
        self,
        initial_value: int,
        *,
        max_value: int | None = None,
        fast_acquire: bool = False,
    ) -> None:
        super().__init__(initial_value, max_value=max_value, fast_acquire=fast_acquire)
        self._internal_semaphore: Semaphore | None = None
        self._initial_value = initial_value
        self._max_value = max_value

    @property
    def _semaphore(self) -> Semaphore:
        if self._internal_semaphore is None:
            self._internal_semaphore = get_async_backend().create_semaphore(
                self._initial_value, max_value=self._max_value
            )

        return self._internal_semaphore

    async def acquire(self) -> None:
        await self._semaphore.acquire()

    def acquire_nowait(self) -> None:
        self._semaphore.acquire_nowait()

    def release(self) -> None:
        self._semaphore.release()

    @property
    def value(self) -> int:
        if self._internal_semaphore is None:
            return self._initial_value

        return self._semaphore.value

    @property
    def max_value(self) -> int | None:
        return self._max_value

    def statistics(self) -> SemaphoreStatistics:
        if self._internal_semaphore is None:
            return SemaphoreStatistics(tasks_waiting=0)

        return self._semaphore.statistics()


class CapacityLimiter:
    __slots__ = ("__weakref__",)

    def __new__(cls, total_tokens: float) -> CapacityLimiter:
        try:
            return get_async_backend().create_capacity_limiter(total_tokens)
        except NoEventLoopError:
            return CapacityLimiterAdapter(total_tokens)

    async def __aenter__(self) -> None:
        raise NotImplementedError

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        raise NotImplementedError

    @property
    def total_tokens(self) -> float:
        """
        The total number of tokens available for borrowing.

        This is a read-write property. If the total number of tokens is increased, the
        proportionate number of tasks waiting on this limiter will be granted their
        tokens.

        .. versionchanged:: 3.0
            The property is now writable.
        .. versionchanged:: 4.12
            The value can now be set to 0.

        """
        raise NotImplementedError

    @total_tokens.setter
    def total_tokens(self, value: float) -> None:
        raise NotImplementedError

    @property
    def borrowed_tokens(self) -> int:
        """The number of tokens that have currently been borrowed."""
        raise NotImplementedError

    @property
    def available_tokens(self) -> float:
        """The number of tokens currently available to be borrowed"""
        raise NotImplementedError

    def acquire_nowait(self) -> None:
        """
        Acquire a token for the current task without waiting for one to become
        available.

        :raises ~anyio.WouldBlock: if there are no tokens available for borrowing

        """
        raise NotImplementedError

    def acquire_on_behalf_of_nowait(self, borrower: object) -> None:
        """
        Acquire a token without waiting for one to become available.

        :param borrower: the entity borrowing a token
        :raises ~anyio.WouldBlock: if there are no tokens available for borrowing

        """
        raise NotImplementedError

    async def acquire(self) -> None:
        """
        Acquire a token for the current task, waiting if necessary for one to become
        available.

        """
        raise NotImplementedError

    async def acquire_on_behalf_of(self, borrower: object) -> None:
        """
        Acquire a token, waiting if necessary for one to become available.

        :param borrower: the entity borrowing a token

        """
        raise NotImplementedError

    def release(self) -> None:
        """
        Release the token held by the current task.

        :raises RuntimeError: if the current task has not borrowed a token from this
            limiter.

        """
        raise NotImplementedError

    def release_on_behalf_of(self, borrower: object) -> None:
        """
        Release the token held by the given borrower.

        :raises RuntimeError: if the borrower has not borrowed a token from this
            limiter.

        """
        raise NotImplementedError

    def statistics(self) -> CapacityLimiterStatistics:
        """
        Return statistics about the current state of this limiter.

        .. versionadded:: 3.0

        """
        raise NotImplementedError


class CapacityLimiterAdapter(CapacityLimiter):
    __slots__ = "_internal_limiter", "_total_tokens"

    def __new__(cls, total_tokens: float) -> Self:
        return object.__new__(cls)

    def __init__(self, total_tokens: float) -> None:
        self._internal_limiter: CapacityLimiter | None = None
        self.total_tokens = total_tokens

    @property
    def _limiter(self) -> CapacityLimiter:
        if self._internal_limiter is None:
            self._internal_limiter = get_async_backend().create_capacity_limiter(
                self._total_tokens
            )

        return self._internal_limiter

    async def __aenter__(self) -> None:
        await self._limiter.__aenter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        return await self._limiter.__aexit__(exc_type, exc_val, exc_tb)

    @property
    def total_tokens(self) -> float:
        if self._internal_limiter is None:
            return self._total_tokens

        return self._internal_limiter.total_tokens

    @total_tokens.setter
    def total_tokens(self, value: float) -> None:
        if not isinstance(value, int) and not math.isinf(value):
            raise TypeError("total_tokens must be an int or math.inf")
        elif value < 0:
            raise ValueError("total_tokens must be >= 0")

        if self._internal_limiter is None:
            self._total_tokens = value
            return

        self._limiter.total_tokens = value

    @property
    def borrowed_tokens(self) -> int:
        if self._internal_limiter is None:
            return 0

        return self._internal_limiter.borrowed_tokens

    @property
    def available_tokens(self) -> float:
        if self._internal_limiter is None:
            return self._total_tokens

        return self._internal_limiter.available_tokens

    def acquire_nowait(self) -> None:
        self._limiter.acquire_nowait()

    def acquire_on_behalf_of_nowait(self, borrower: object) -> None:
        self._limiter.acquire_on_behalf_of_nowait(borrower)

    async def acquire(self) -> None:
        await self._limiter.acquire()

    async def acquire_on_behalf_of(self, borrower: object) -> None:
        await self._limiter.acquire_on_behalf_of(borrower)

    def release(self) -> None:
        self._limiter.release()

    def release_on_behalf_of(self, borrower: object) -> None:
        self._limiter.release_on_behalf_of(borrower)

    def statistics(self) -> CapacityLimiterStatistics:
        if self._internal_limiter is None:
            return CapacityLimiterStatistics(
                borrowed_tokens=0,
                total_tokens=self.total_tokens,
                borrowers=(),
                tasks_waiting=0,
            )

        return self._internal_limiter.statistics()


class ResourceGuard:
    """
    A context manager for ensuring that a resource is only used by a single task at a
    time.

    Entering this context manager while the previous has not exited it yet will trigger
    :exc:`BusyResourceError`.

    :param action: the action to guard against (visible in the :exc:`BusyResourceError`
        when triggered, e.g. "Another task is already {action} this resource")

    .. versionadded:: 4.1
    """

    __slots__ = "__weakref__", "_guarded", "action"

    def __init__(self, action: str = "using"):
        self.action: str = action
        self._guarded = False

    def __enter__(self) -> None:
        if self._guarded:
            raise BusyResourceError(self.action)

        self._guarded = True

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._guarded = False
