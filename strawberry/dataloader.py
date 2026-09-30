from __future__ import annotations

import asyncio
import dataclasses
import time
from abc import ABC, abstractmethod
from asyncio import create_task, gather, get_event_loop
from asyncio.futures import Future
from collections import OrderedDict
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    TypeVar,
    overload,
)

from .exceptions import WrongNumberOfResultsReturned

if TYPE_CHECKING:
    from asyncio.events import AbstractEventLoop
    from collections.abc import (
        Awaitable,
        Callable,
        Hashable,
        Iterable,
        Mapping,
        Sequence,
    )


T = TypeVar("T")
K = TypeVar("K")


@dataclass(slots=True)
class LoaderTask(Generic[K, T]):
    key: K
    future: Future
    batch: Batch[K, T]
    waiters: set[Future[T]] = dataclasses.field(default_factory=set)


@dataclass(slots=True)
class Batch(Generic[K, T]):
    tasks: list[LoaderTask] = dataclasses.field(default_factory=list)
    dispatched: bool = False
    _dispatch_task: asyncio.Task[None] | None = dataclasses.field(
        default=None, repr=False
    )

    def add_task(self, key: Any, future: Future) -> LoaderTask[K, T]:
        task: LoaderTask[K, T] = LoaderTask(key, future, self)
        self.tasks.append(task)
        return task

    def add_waiter(self, task: LoaderTask[K, T], waiter: Future[T]) -> None:
        task.waiters.add(waiter)
        waiter.add_done_callback(lambda _: self._on_waiter_done(waiter))

    def _on_waiter_done(self, waiter: Future[T]) -> None:
        """Cancel dispatch only when every caller has cancelled its waiter."""
        if not waiter.cancelled() or self._dispatch_task is None:
            return

        if self._dispatch_task.done():
            return

        if self.is_abandoned():
            self._dispatch_task.cancel()

    def is_abandoned(self) -> bool:
        return bool(self.tasks) and all(
            task.waiters and all(waiter.cancelled() for waiter in task.waiters)
            for task in self.tasks
        )

    def __len__(self) -> int:
        return len(self.tasks)


class AbstractCache(ABC, Generic[K, T]):
    @abstractmethod
    def get(self, key: K) -> Future[T] | None:
        pass

    @abstractmethod
    def set(self, key: K, value: Future[T]) -> None:
        pass

    @abstractmethod
    def delete(self, key: K) -> None:
        pass

    @abstractmethod
    def clear(self) -> None:
        pass


class DefaultCache(AbstractCache[K, T]):
    def __init__(
        self,
        cache_key_fn: Callable[[K], Hashable] | None = None,
        *,
        ttl: float | None = None,
        max_entries: int | None = None,
        time_func: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cache_key_fn: Callable[[K], Hashable] = (
            cache_key_fn if cache_key_fn is not None else lambda x: x
        )
        self.ttl = ttl
        self.max_entries = max_entries
        self.time_func = time_func
        self.cache_map: OrderedDict[Hashable, CacheEntry[T]] = OrderedDict()

    def get(self, key: K) -> Future[T] | None:
        cache_key = self.cache_key_fn(key)
        entry = self.cache_map.get(cache_key)

        if entry is None:
            return None

        if (
            entry.future.done()
            and entry.expires_at is not None
            and self.time_func() >= entry.expires_at
        ):
            self.cache_map.pop(cache_key, None)
            return None

        if entry.future.done():
            self.cache_map.move_to_end(cache_key)

        return entry.future

    def set(self, key: K, value: Future[T]) -> None:
        cache_key = self.cache_key_fn(key)
        entry = CacheEntry(value)
        self.cache_map[cache_key] = entry

        if value.done():
            self._mark_completed(cache_key, value)
        else:
            value.add_done_callback(
                lambda _: self._mark_completed(cache_key, value)
            )

    def delete(self, key: K) -> None:
        del self.cache_map[self.cache_key_fn(key)]

    def clear(self) -> None:
        self.cache_map.clear()

    def _mark_completed(self, cache_key: Hashable, future: Future[T]) -> None:
        entry = self.cache_map.get(cache_key)
        if entry is None or entry.future is not future or not future.done():
            return

        entry.expires_at = (
            self.time_func() + self.ttl if self.ttl is not None else None
        )
        self.cache_map.move_to_end(cache_key)
        self._evict_completed()

    def _evict_completed(self) -> None:
        if self.max_entries is None:
            return

        completed_count = sum(
            entry.future.done() for entry in self.cache_map.values()
        )

        while completed_count > self.max_entries:
            for cache_key, entry in self.cache_map.items():
                if entry.future.done():
                    self.cache_map.pop(cache_key)
                    completed_count -= 1
                    break


@dataclass(slots=True)
class CacheEntry(Generic[T]):
    future: Future[T]
    expires_at: float | None = None


class DataLoader(Generic[K, T]):
    batch: Batch[K, T] | None = None
    cache: bool = False
    cache_map: AbstractCache[K, T]

    @overload
    def __init__(
        self,
        # any BaseException is rethrown in 'load', so should be excluded from the T type
        load_fn: Callable[[list[K]], Awaitable[Sequence[T | BaseException]]],
        max_batch_size: int | None = None,
        cache: bool = True,
        loop: AbstractEventLoop | None = None,
        cache_map: AbstractCache[K, T] | None = None,
        cache_key_fn: Callable[[K], Hashable] | None = None,
        cache_ttl: float | None = None,
        cache_max_entries: int | None = None,
        cache_exceptions: bool = True,
        time_func: Callable[[], float] = time.monotonic,
    ) -> None: ...

    # fallback if load_fn is untyped and there's no other info for inference
    @overload
    def __init__(
        self: DataLoader[K, Any],
        load_fn: Callable[[list[K]], Awaitable[list[Any]]],
        max_batch_size: int | None = None,
        cache: bool = True,
        loop: AbstractEventLoop | None = None,
        cache_map: AbstractCache[K, T] | None = None,
        cache_key_fn: Callable[[K], Hashable] | None = None,
        cache_ttl: float | None = None,
        cache_max_entries: int | None = None,
        cache_exceptions: bool = True,
        time_func: Callable[[], float] = time.monotonic,
    ) -> None: ...

    def __init__(
        self,
        load_fn: Callable[[list[K]], Awaitable[Sequence[T | BaseException]]],
        max_batch_size: int | None = None,
        cache: bool = True,
        loop: AbstractEventLoop | None = None,
        cache_map: AbstractCache[K, T] | None = None,
        cache_key_fn: Callable[[K], Hashable] | None = None,
        cache_ttl: float | None = None,
        cache_max_entries: int | None = None,
        cache_exceptions: bool = True,
        time_func: Callable[[], float] = time.monotonic,
    ):
        if cache_ttl is not None and cache_ttl <= 0:
            raise ValueError("cache_ttl must be greater than 0")
        if cache_max_entries is not None and cache_max_entries <= 0:
            raise ValueError("cache_max_entries must be greater than 0")

        self.load_fn = load_fn
        self.max_batch_size = max_batch_size

        self._loop = loop

        self.cache = cache
        self.cache_exceptions = cache_exceptions
        self._pending_tasks: dict[Future[T], LoaderTask[K, T]] = {}

        if self.cache:
            self.cache_map = (
                DefaultCache(
                    cache_key_fn,
                    ttl=cache_ttl,
                    max_entries=cache_max_entries,
                    time_func=time_func,
                )
                if cache_map is None
                else cache_map
            )

    @property
    def loop(self) -> AbstractEventLoop:
        if self._loop is None:
            self._loop = get_event_loop()

        return self._loop

    def load(self, key: K) -> Awaitable[T]:
        abandoned_task: LoaderTask[K, T] | None = None

        if self.cache:
            future = self.cache_map.get(key)

            if future is not None and not future.cancelled():
                if self._should_remove_cached_exception(future):
                    self.cache_map.delete(key)
                else:
                    pending_task = self._pending_tasks.get(future)
                    if pending_task is None:
                        return future
                    if not pending_task.batch.is_abandoned():
                        return self._add_waiter(pending_task)
                    abandoned_task = pending_task

        new_future = self.loop.create_future()
        new_future.add_done_callback(
            lambda _: self._on_internal_future_done(key, new_future)
        )

        if self.cache:
            self.cache_map.set(key, new_future)

        if abandoned_task is not None:
            self._discard_abandoned_task(abandoned_task)

        batch = get_current_batch(self)
        task = batch.add_task(key, new_future)
        self._pending_tasks[new_future] = task

        return self._add_waiter(task)

    def _add_waiter(self, task: LoaderTask[K, T]) -> Awaitable[T]:
        waiter: Future[T] = self.loop.create_future()

        if task.future.done():
            self._copy_future_result(task.future, waiter)
        else:
            task.batch.add_waiter(task, waiter)

        return waiter

    def _discard_abandoned_task(self, task: LoaderTask[K, T]) -> None:
        self._pending_tasks.pop(task.future, None)
        task.batch.tasks.remove(task)
        task.future.cancel()

    def _should_remove_cached_exception(self, future: Future[T]) -> bool:
        return (
            not self.cache_exceptions
            and future.done()
            and not future.cancelled()
            and future.exception() is not None
        )

    def _copy_future_result(self, source: Future[T], target: Future[T]) -> None:
        if target.done():
            return

        if source.cancelled():
            target.cancel()
            return

        exception = source.exception()
        if exception is not None:
            target.set_exception(exception)
        else:
            target.set_result(source.result())

    def _get_pending_tasks(self, key: K) -> list[LoaderTask[K, T]]:
        return [task for task in self._pending_tasks.values() if task.key == key]

    def _on_internal_future_done(self, key: K, future: Future[T]) -> None:
        task = self._pending_tasks.pop(future, None)

        if task is not None:
            for waiter in task.waiters:
                self._copy_future_result(future, waiter)

        if not self.cache:
            return

        cached_future = self.cache_map.get(key)
        if cached_future is not future:
            return

        if future.cancelled() or self._should_remove_cached_exception(future):
            self.cache_map.delete(key)

    def load_many(self, keys: Iterable[K]) -> Awaitable[list[T]]:
        return gather(*map(self.load, keys))

    def clear(self, key: K) -> None:
        if self.cache:
            self.cache_map.delete(key)

    def clear_many(self, keys: Iterable[K]) -> None:
        if self.cache:
            for key in keys:
                self.cache_map.delete(key)

    def clear_all(self) -> None:
        if self.cache:
            self.cache_map.clear()

    def prime(self, key: K, value: T, force: bool = False) -> None:
        self.prime_many({key: value}, force)

    def prime_many(self, data: Mapping[K, T], force: bool = False) -> None:
        # Populate the cache with the specified values
        if self.cache:
            for key, value in data.items():
                current_future = self.cache_map.get(key)

                if current_future is not None and not force:
                    continue

                future: Future = Future(loop=self.loop)
                future.set_result(value)

                self.cache_map.set(key, future)

                if force:
                    for task in self._get_pending_tasks(key):
                        if task.batch.dispatched:
                            for waiter in task.waiters:
                                self._copy_future_result(future, waiter)
                        elif not task.future.done():
                            task.future.set_result(value)

        # For keys that are pending on the current batch, but the
        # batch hasn't started fetching yet: Remove it from the
        # batch and set to the specified value
        if self.batch is not None and not self.batch.dispatched:
            batch_updated = False
            for task in self.batch.tasks:
                if task.key in data:
                    batch_updated = True
                    if not task.future.done():
                        task.future.set_result(data[task.key])
            if batch_updated:
                self.batch.tasks = [
                    task for task in self.batch.tasks if not task.future.done()
                ]


def should_create_new_batch(loader: DataLoader, batch: Batch) -> bool:
    return bool(
        batch.dispatched
        or (loader.max_batch_size and len(batch.tasks) >= loader.max_batch_size)
    )


def get_current_batch(loader: DataLoader) -> Batch:
    batch = loader.batch
    if batch is not None and batch.tasks and not should_create_new_batch(loader, batch):
        return batch

    batch = loader.batch = Batch()

    dispatch(loader, batch)

    return batch


def dispatch(loader: DataLoader, batch: Batch) -> None:
    def _schedule() -> None:
        batch._dispatch_task = create_task(dispatch_batch(loader, batch))
        batch._dispatch_task.add_done_callback(
            lambda _: setattr(batch, "_dispatch_task", None)
        )

    loader.loop.call_soon(_schedule)


async def dispatch_batch(loader: DataLoader, batch: Batch) -> None:
    batch.dispatched = True

    keys = [task.key for task in batch.tasks]
    if len(keys) == 0:
        # Ensure batch is not empty
        # Unlikely, but could happen if the tasks are
        # overridden with preset values
        return

    # Skip the batch entirely if all callers have already cancelled.
    # This avoids calling load_fn (e.g. a database query) when no caller
    # is waiting for the results.
    if batch.is_abandoned():
        for task in batch.tasks:
            task.future.cancel()
        return

    # TODO: check if load_fn return an awaitable and it is a list

    try:
        values = await loader.load_fn(keys)
        values = list(values)

        if len(values) != len(batch):
            raise WrongNumberOfResultsReturned(  # noqa: TRY301
                expected=len(batch), received=len(values)
            )

        for task, value in zip(batch.tasks, values, strict=True):
            # Trying to set_result in a cancelled future would raise
            # asyncio.exceptions.InvalidStateError
            if task.future.cancelled():
                continue

            if isinstance(value, BaseException):
                task.future.set_exception(value)
            else:
                task.future.set_result(value)
    except Exception as e:  # noqa: BLE001
        for task in batch.tasks:
            if task.future.cancelled():
                continue
            task.future.set_exception(e)
    except asyncio.CancelledError:
        for task in batch.tasks:
            if all(waiter.cancelled() for waiter in task.waiters):
                task.future.cancel()
        raise


__all__ = [
    "AbstractCache",
    "Batch",
    "DataLoader",
    "DefaultCache",
    "LoaderTask",
    "dispatch",
    "dispatch_batch",
    "get_current_batch",
    "should_create_new_batch",
]
