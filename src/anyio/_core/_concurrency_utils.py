from __future__ import annotations

from inspect import iscoroutine

__all__ = ("amap", "amap_iter", "as_completed", "gather")

from collections.abc import (
    AsyncGenerator,
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Callable,
    Coroutine,
    Iterable,
    Iterator,
)
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast, overload

from ..abc._tasks import get_coro_name
from ._exceptions import BrokenResourceError, EndOfStream
from ._streams import create_memory_object_stream
from ._synchronization import Event, Semaphore
from ._tasks import CancelScope, TaskHandle, create_task_group

if TYPE_CHECKING:
    from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

R = TypeVar("R")
S = TypeVar("S")
T = TypeVar("T")
U = TypeVar("U")
V = TypeVar("V")
W = TypeVar("W")


@overload
async def gather(
    coro1: Coroutine[Any, Any, R], coro2: Coroutine[Any, Any, S], /
) -> tuple[R, S]: ...


@overload
async def gather(
    coro1: Coroutine[Any, Any, R],
    coro2: Coroutine[Any, Any, S],
    coro3: Coroutine[Any, Any, T],
    /,
) -> tuple[R, S, T]: ...


@overload
async def gather(
    coro1: Coroutine[Any, Any, R],
    coro2: Coroutine[Any, Any, S],
    coro3: Coroutine[Any, Any, T],
    coro4: Coroutine[Any, Any, U],
    /,
) -> tuple[R, S, T, U]: ...


@overload
async def gather(
    coro1: Coroutine[Any, Any, R],
    coro2: Coroutine[Any, Any, S],
    coro3: Coroutine[Any, Any, T],
    coro4: Coroutine[Any, Any, U],
    coro5: Coroutine[Any, Any, V],
    /,
) -> tuple[R, S, T, U, V]: ...


@overload
async def gather(
    coro1: Coroutine[Any, Any, R],
    coro2: Coroutine[Any, Any, S],
    coro3: Coroutine[Any, Any, T],
    coro4: Coroutine[Any, Any, U],
    coro5: Coroutine[Any, Any, V],
    coro6: Coroutine[Any, Any, W],
    /,
) -> tuple[R, S, T, U, V, W]: ...


# handle arbitrary length if awaitables are all of the same type
@overload
async def gather(*coros: Coroutine[Any, Any, R]) -> tuple[R, ...]: ...


async def gather(*coros: Coroutine[Any, Any, Any]) -> tuple[Any, ...]:
    """
    Run coroutines concurrently in a task group. The order of result values corresponds
    to the order of coroutines passed.

    :param coros: coroutine objects to run as tasks
    :return: task results for each argument in the same order as they were passed

    """
    handles: list[TaskHandle[Any]] = []
    async with create_task_group() as tg:
        handles.extend(tg.create_task(coro) for coro in coros)

    return tuple(h.return_value for h in handles)


@asynccontextmanager
async def as_completed(
    *awaitables: Awaitable[R],
) -> AsyncGenerator[MemoryObjectReceiveStream[TaskHandle[R]]]:
    """
    Run awaitable objects concurrently in a task group, returning an iterator which can
    be used to get finished task handles in the order they complete.

    :param awaitables: awaitable objects to run as tasks
    :return: MemoryObjectReceiveStream for iterating over task handles as tasks complete.

    """
    if not awaitables:
        raise ValueError("as_completed() takes at least one awaitable")

    send, recv = create_memory_object_stream[TaskHandle[R]](len(awaitables))
    task_handles: list[TaskHandle[R]] = []

    async def runner(
        awaitable: Awaitable[R],
        index: int,
        _send: MemoryObjectSendStream[TaskHandle[R]],
    ) -> R:
        async with _send:
            try:
                return await awaitable
            finally:
                try:
                    _send.send_nowait(task_handles[index])
                except BrokenResourceError:
                    pass

    async with recv, create_task_group() as tg:
        async with send:
            for i, awaitable in enumerate(awaitables):
                name = get_coro_name(awaitable) if iscoroutine(awaitable) else None
                task_handles.append(
                    tg.start_soon(runner, awaitable, i, send.clone(), name=name)
                )
        try:
            yield recv
        finally:
            tg.cancel_scope.cancel()


async def amap(
    func: Callable[[T], Coroutine[Any, Any, R]], args: Iterable[T]
) -> list[R]:
    """
    Run the given coroutine function concurrently for multiple argument values.

    :param func: a coroutine function that takes a single argument
    :param args: a sequence of argument values to pass to ``func``
    :return: task results for each argument in the same order as they were passed

    """
    handles: list[TaskHandle[R]] = []
    async with create_task_group() as tg:
        handles.extend(tg.start_soon(func, arg) for arg in args)

    return [h.return_value for h in handles]


class _IterableAsyncIterator(AsyncIterator[T]):
    def __init__(self, iterator: Iterator[T]) -> None:
        self._iterator = iterator

    async def __anext__(self) -> T:
        try:
            return next(self._iterator)
        except StopIteration:
            raise StopAsyncIteration from None


def _iterate(iterable: Iterable[T] | AsyncIterable[T]) -> AsyncIterator[T]:
    if isinstance(iterable, AsyncIterable):
        return iterable.__aiter__()

    return _IterableAsyncIterator(iter(iterable))


class _MapSlot(Generic[R]):
    __slots__ = ("event", "is_exception", "value")

    def __init__(self) -> None:
        self.event = Event()
        self.is_exception = False
        self.value: R | BaseException | None = None


class _OrderedMapIterator(AsyncIterator[R]):
    __slots__ = ("_slots", "_window")

    def __init__(
        self, slots: MemoryObjectReceiveStream[_MapSlot[R]], window: Semaphore
    ) -> None:
        self._slots = slots
        self._window = window

    async def __anext__(self) -> R:
        try:
            slot = await self._slots.receive()
        except EndOfStream:
            raise StopAsyncIteration from None

        await slot.event.wait()
        self._window.release()
        if slot.is_exception:
            raise cast(BaseException, slot.value)

        return cast(R, slot.value)


class _UnorderedMapIterator(AsyncIterator[R]):
    __slots__ = ("_results", "_window")

    def __init__(
        self, results: MemoryObjectReceiveStream[R], window: Semaphore
    ) -> None:
        self._results = results
        self._window = window

    async def __anext__(self) -> R:
        try:
            result = await self._results.receive()
        except EndOfStream:
            raise StopAsyncIteration from None

        self._window.release()
        return result


@asynccontextmanager
async def amap_iter(
    func: Callable[[T], Awaitable[R]],
    iterable: Iterable[T] | AsyncIterable[T],
    *,
    max_tasks: int = 10,
    max_buffered: int = 0,
    ordered: bool = True,
) -> AsyncGenerator[AsyncIterator[R], None]:
    """
    Map an asynchronous function over an iterable concurrently, returning an
    asynchronous iterator of the results.

    The source iterable is consumed lazily by a background task: at most
    ``max_tasks`` calls to ``func`` are in flight at any time, and the number of
    items pulled from the source but not yet consumed never exceeds
    ``max_tasks + max_buffered``. This provides backpressure, so a slow consumer
    (or, in ordered mode, a slow first item) cannot cause the source to be read
    in its entirety or completed results to pile up without bound.

    If the consumer stops iterating early, the source iterable fails, or any call
    to ``func`` fails, the source iterator is closed and all remaining worker
    tasks are cancelled and awaited before the context manager exits. Exceptions
    are propagated with their original tracebacks; ``None`` is treated as a
    regular result value.

    :param func: an async function (or any callable returning an awaitable) that
        takes a single argument
    :param iterable: a synchronous or asynchronous iterable of argument values to
        pass to ``func``
    :param max_tasks: maximum number of calls to ``func`` running concurrently
    :param max_buffered: maximum number of items allowed to be completed or in
        flight but not yet consumed, in excess of ``max_tasks``
    :param ordered: if ``True`` (the default), yield the results in the order of
        the input items; if ``False``, yield them in order of completion
    :return: an asynchronous iterator of the results

    """
    if max_tasks < 1:
        raise ValueError("max_tasks must be at least 1")
    if max_buffered < 0:
        raise ValueError("max_buffered must be at least 0")

    iterator = _iterate(iterable)
    task_semaphore = Semaphore(max_tasks)
    window = Semaphore(max_tasks + max_buffered, max_value=max_tasks + max_buffered)

    async def close_iterator() -> None:
        aclose = getattr(iterator, "aclose", None)
        if aclose is not None:
            with CancelScope(shield=True):
                await aclose()

    async with create_task_group() as tg:
        if ordered:
            send_slots, receive_slots = create_memory_object_stream[_MapSlot[R]](
                max_tasks + max_buffered
            )

            async def ordered_worker(slot: _MapSlot[R], item: T) -> None:
                try:
                    async with task_semaphore:
                        slot.value = await func(item)
                except BaseException as exc:
                    slot.is_exception = True
                    slot.value = exc
                    slot.event.set()
                    raise

                slot.event.set()

            async def ordered_producer() -> None:
                try:
                    async with send_slots:
                        while True:
                            await window.acquire()
                            try:
                                item = await anext(iterator)
                            except StopAsyncIteration:
                                window.release()
                                break

                            slot: _MapSlot[R] = _MapSlot()
                            try:
                                send_slots.send_nowait(slot)
                            except BrokenResourceError:
                                window.release()
                                break

                            tg.start_soon(ordered_worker, slot, item)
                finally:
                    await close_iterator()

            tg.start_soon(ordered_producer)
            try:
                async with receive_slots:
                    yield _OrderedMapIterator(receive_slots, window)
            finally:
                tg.cancel_scope.cancel()
        else:
            send_results, receive_results = create_memory_object_stream[R](max_buffered)

            async def unordered_worker(
                item: T, send: MemoryObjectSendStream[R]
            ) -> None:
                async with send:
                    async with task_semaphore:
                        result = await func(item)

                    try:
                        await send.send(result)
                    except BrokenResourceError:
                        pass

            async def unordered_producer() -> None:
                try:
                    async with send_results:
                        while True:
                            await window.acquire()
                            try:
                                item = await anext(iterator)
                            except StopAsyncIteration:
                                window.release()
                                break

                            tg.start_soon(unordered_worker, item, send_results.clone())
                finally:
                    await close_iterator()

            tg.start_soon(unordered_producer)
            try:
                async with receive_results:
                    yield _UnorderedMapIterator(receive_results, window)
            finally:
                tg.cancel_scope.cancel()
