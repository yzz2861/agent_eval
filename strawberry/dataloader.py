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


@dataclass(slots=True)
class Batch(Generic[K, T]):
    tasks: list[LoaderTask] = dataclasses.field(default_factory=list)
    dispatched: bool = False
    _dispatch_task: asyncio.Task[None] | None = dataclasses.field(
        default=None, repr=False
    )

    def add_task(self, key: Any, future: Future) -> None:
        task: LoaderTask[K, T] = LoaderTask(key, future)
        self.tasks.append(task)
        future.add_done_callback(self._on_future_done)

    def _on_future_done(self, future: Future) -> None:
        """Cancel the dispatch task if all futures in the batch are cancelled."""
        if (
            future.cancelled()
            and self._dispatch_task is not None
            and not self._dispatch_task.done()
            and all(t.future.cancelled() for t in self.tasks)
        ):
            self._dispatch_task.cancel()

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
        result_ttl: float | None = None,
        max_cache_size: int | None = None,
        cache_exceptions: bool = True,
        time_fn: Callable[[], float] | None = None,
    ) -> None:
        if result_ttl is not None and result_ttl < 0:
            raise ValueError("result_ttl must be greater than or equal to 0")
        if max_cache_size is not None and max_cache_size < 0:
            raise ValueError("max_cache_size must be greater than or equal to 0")

        self.cache_key_fn: Callable[[K], Hashable] = (
            cache_key_fn if cache_key_fn is not None else lambda x: x
        )
        self.result_ttl = result_ttl
        self.max_cache_size = max_cache_size
        self.cache_exceptions = cache_exceptions
        self.time_fn = time_fn if time_fn is not None else time.monotonic
        self.cache_map: OrderedDict[Hashable, Future[T]] = OrderedDict()
        self.completed_at: dict[Hashable, float] = {}

    def get(self, key: K) -> Future[T] | None:
        cache_key = self.cache_key_fn(key)
        future = self.cache_map.get(cache_key)

        if future is None:
            return None

        if future.cancelled():
            self._delete(cache_key)
            return None

        completed_at = self.completed_at.get(cache_key)
        if (
            completed_at is not None
            and self.result_ttl is not None
            and self.time_fn() - completed_at >= self.result_ttl
        ):
            self._delete(cache_key)
            return None

        if completed_at is not None:
            self.cache_map.move_to_end(cache_key)

        return future

    def set(self, key: K, value: Future[T]) -> None:
        cache_key = self.cache_key_fn(key)
        self.cache_map[cache_key] = value
        value.add_done_callback(lambda future: self._complete(cache_key, future))

        if value.done():
            self._complete(cache_key, value)
        else:
            self._enforce_cache_size()

    def _complete(self, cache_key: Hashable, future: Future[T]) -> None:
        if self.cache_map.get(cache_key) is not future:
            return

        if future.cancelled():
            self._delete(cache_key)
            return

        if future.exception() is not None and not self.cache_exceptions:
            self._delete(cache_key)
            return

        self.completed_at[cache_key] = self.time_fn()
        self.cache_map.move_to_end(cache_key)
        self._enforce_cache_size()

    def _enforce_cache_size(self) -> None:
        if self.max_cache_size is None:
            return

        while len(self.completed_at) > self.max_cache_size:
            for cache_key in self.cache_map:
                if cache_key in self.completed_at:
                    self._delete(cache_key)
                    break
            else:
                return

    def _delete(self, cache_key: Hashable) -> None:
        self.cache_map.pop(cache_key, None)
        self.completed_at.pop(cache_key, None)

    def delete(self, key: K) -> None:
        self._delete(self.cache_key_fn(key))

    def clear(self) -> None:
        self.cache_map.clear()
        self.completed_at.clear()


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
        result_ttl: float | None = None,
        max_cache_size: int | None = None,
        cache_exceptions: bool = True,
        time_fn: Callable[[], float] | None = None,
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
        result_ttl: float | None = None,
        max_cache_size: int | None = None,
        cache_exceptions: bool = True,
        time_fn: Callable[[], float] | None = None,
    ) -> None: ...

    def __init__(
        self,
        load_fn: Callable[[list[K]], Awaitable[Sequence[T | BaseException]]],
        max_batch_size: int | None = None,
        cache: bool = True,
        loop: AbstractEventLoop | None = None,
        cache_map: AbstractCache[K, T] | None = None,
        cache_key_fn: Callable[[K], Hashable] | None = None,
        result_ttl: float | None = None,
        max_cache_size: int | None = None,
        cache_exceptions: bool = True,
        time_fn: Callable[[], float] | None = None,
    ):
        if result_ttl is not None and result_ttl < 0:
            raise ValueError("result_ttl must be greater than or equal to 0")
        if max_cache_size is not None and max_cache_size < 0:
            raise ValueError("max_cache_size must be greater than or equal to 0")

        self.load_fn = load_fn
        self.max_batch_size = max_batch_size
        self._loop = loop
        self.cache = cache
        self.cache_exceptions = cache_exceptions
        self._waiter_counts: dict[Future[T], int] = {}

        if self.cache:
            self.cache_map = (
                DefaultCache(
                    cache_key_fn,
                    result_ttl=result_ttl,
                    max_cache_size=max_cache_size,
                    cache_exceptions=cache_exceptions,
                    time_fn=time_fn,
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
        if self.cache:
            future = self.cache_map.get(key)

            if future and not future.cancelled():
                return self._subscribe(future)

        future = self.loop.create_future()

        if self.cache:
            self.cache_map.set(key, future)
            future.add_done_callback(
                lambda completed_future: self._cache_future_done(key, completed_future)
            )

        batch = get_current_batch(self)
        batch.add_task(key, future)

        return self._subscribe(future)

    def _subscribe(self, internal_future: Future[T]) -> Future[T]:
        caller_future = self.loop.create_future()

        if internal_future.done():
            self._copy_future_result(internal_future, caller_future)
            return caller_future

        self._waiter_counts[internal_future] = (
            self._waiter_counts.get(internal_future, 0) + 1
        )

        def caller_cancelled(caller: Future[T]) -> None:
            if not caller.cancelled():
                return

            waiters = self._waiter_counts.get(internal_future, 0) - 1
            if waiters > 0:
                self._waiter_counts[internal_future] = waiters
                return

            self._waiter_counts.pop(internal_future, None)
            if not internal_future.done():
                internal_future.cancel()

        def internal_done(completed_future: Future[T]) -> None:
            self._waiter_counts.pop(completed_future, None)

            if caller_future.cancelled():
                return

            if completed_future.cancelled():
                caller_future.cancel()
                return

            self._copy_future_result(completed_future, caller_future)

        caller_future.add_done_callback(caller_cancelled)
        internal_future.add_done_callback(internal_done)
        return caller_future

    @staticmethod
    def _copy_future_result(source: Future[T], target: Future[T]) -> None:
        exception = source.exception()
        if exception is not None:
            target.set_exception(exception)
        else:
            target.set_result(source.result())

    def _cache_future_done(self, key: K, future: Future[T]) -> None:
        if future.cancelled() or future.exception() is None or self.cache_exceptions:
            return

        if self.cache and self.cache_map.get(key) is future:
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
                existing = self.cache_map.get(key)

                if existing is not None and not existing.done() and force:
                    existing.set_result(value)

                if existing is None or force:
                    future: Future = Future(loop=self.loop)
                    future.set_result(value)
                    self.cache_map.set(key, future)

        # For keys that are pending on the current batch, but the
        # batch hasn't started fetching yet: Remove it from the
        # batch and set to the specified value
        if self.batch is not None and not self.batch.dispatched:
            batch_updated = False
            for task in self.batch.tasks:
                if not task.future.done() and task.key in data:
                    batch_updated = True
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

    # Skip the batch entirely if all futures have already been cancelled.
    # This avoids calling load_fn (e.g. a database query) when no caller
    # is waiting for the results.
    if all(task.future.cancelled() for task in batch.tasks):
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
            if task.future.done():
                continue

            if isinstance(value, BaseException):
                task.future.set_exception(value)
            else:
                task.future.set_result(value)
    except Exception as e:  # noqa: BLE001
        for task in batch.tasks:
            if task.future.done():
                continue
            task.future.set_exception(e)


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
