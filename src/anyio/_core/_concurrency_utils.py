from __future__ import annotations

from inspect import iscoroutine

__all__ = ("amap", "amap_stream", "as_completed", "gather")

import sys
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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar, overload

from ..abc._tasks import get_coro_name
from ..lowlevel import checkpoint
from ._exceptions import BrokenResourceError
from ._streams import create_memory_object_stream
from ._synchronization import Condition, Semaphore
from ._tasks import CancelScope, TaskHandle, create_task_group

if sys.version_info < (3, 11):
    from exceptiongroup import BaseExceptionGroup

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


@dataclass(eq=False)
class _SyncIterableAsyncIterator(AsyncIterator[T]):
    iterator: Iterator[T]

    async def __anext__(self) -> T:
        try:
            return next(self.iterator)
        except StopIteration:
            raise StopAsyncIteration from None


async def amap_stream(
    func: Callable[[T], Awaitable[R]],
    iterable: Iterable[T] | AsyncIterable[T],
    *,
    limit: int,
    max_buffered: int = 0,
    ordered: bool = True,
) -> AsyncGenerator[R, None]:
    """
    Map an async function over an iterable, yielding results as they become available.

    Items are pulled from ``iterable`` lazily: at most ``limit`` tasks run ``func``
    concurrently, and only a bounded number of finished results are kept waiting to
    be consumed (at most ``max_buffered`` in unordered mode, and at most
    ``max_buffered + 1`` in ordered mode), so the source is never read further ahead
    than ``limit + max_buffered + 1`` items. If the consumer stops iterating, the
    source fails or any task fails, the source is closed and all remaining tasks are
    cancelled and awaited.

    If exactly one task (or the source) fails, its exception is raised as-is. If
    several fail before the first one can be delivered, a ``BaseExceptionGroup`` is
    raised instead.

    :param func: an async function (or any callable returning an awaitable) applied to
        each item
    :param iterable: a sync or async iterable of items to process
    :param limit: maximum number of tasks running ``func`` concurrently
    :param max_buffered: maximum number of finished results held in the output buffer
        while waiting to be consumed
    :param ordered: if ``True`` (the default), yield results in the order of the
        input items; if ``False``, yield each result as soon as its task completes

    """
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if max_buffered < 0:
        raise ValueError("max_buffered must be at least 0")

    if isinstance(iterable, AsyncIterator):
        source: AsyncIterator[T] = iterable
    elif isinstance(iterable, AsyncIterable):
        source = iterable.__aiter__()
    else:
        source = _SyncIterableAsyncIterator(iter(iterable))

    send, receive = create_memory_object_stream[tuple[int, R]](max_buffered)
    semaphore = Semaphore(limit)
    condition = Condition()
    next_index = 0

    async def worker(
        index: int, item: T, send_stream: MemoryObjectSendStream[tuple[int, R]]
    ) -> None:
        async with send_stream:
            try:
                result = await func(item)
                if ordered:
                    # Don't let finished results pile up while an earlier result is
                    # still pending
                    async with condition:
                        await condition.wait_for(
                            lambda: index - next_index <= max_buffered
                        )

                try:
                    await send_stream.send((index, result))
                except BrokenResourceError:
                    # The consumer stopped iterating, so discard the result
                    pass
            finally:
                semaphore.release()

    async def producer() -> None:
        async with send:
            index = 0
            try:
                while True:
                    try:
                        item = await anext(source)
                    except StopAsyncIteration:
                        return

                    await semaphore.acquire()
                    tg.start_soon(worker, index, item, send.clone())
                    index += 1
            finally:
                aclose = getattr(source, "aclose", None)
                if aclose is not None:
                    with CancelScope(shield=True):
                        await aclose()

    result_yielded = False
    try:
        async with receive, create_task_group() as tg:
            tg.start_soon(producer)
            if ordered:
                pending: dict[int, R] = {}
                async for index, result in receive:
                    pending[index] = result
                    while next_index in pending:
                        result_yielded = True
                        yield pending.pop(next_index)
                        async with condition:
                            next_index += 1
                            condition.notify_all()
            else:
                async for _index, result in receive:
                    result_yielded = True
                    yield result
    except BaseExceptionGroup as group:
        if len(group.exceptions) == 1:
            raise group.exceptions[0] from None

        raise

    if not result_yielded:
        await checkpoint()
