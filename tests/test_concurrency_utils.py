from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Generator
from typing import TYPE_CHECKING, Any

import pytest

from anyio import (
    CancelScope,
    Event,
    amap,
    amap_stream,
    as_completed,
    create_task_group,
    gather,
    sleep,
    wait_all_tasks_blocked,
)
from anyio.lowlevel import checkpoint

if TYPE_CHECKING:
    from anyio._core._tasks import TaskHandle


async def test_gather_results_in_order() -> None:
    # Chain events so the tasks complete in reverse order (3, 2, 1)
    events = [Event() for _ in range(3)]
    events[-1].set()

    async def return_when(value: int) -> int:
        await events[value - 1].wait()
        if value > 1:
            events[value - 2].set()

        return value

    results = await gather(return_when(1), return_when(2), return_when(3))
    assert results == (1, 2, 3)


async def test_gather_propagates_exception() -> None:
    async def fail() -> None:
        raise ValueError("boom")

    async def succeed() -> int:
        return 1

    with pytest.RaisesGroup(pytest.RaisesExc(ValueError, match="boom")):
        await gather(succeed(), fail())


async def test_as_completed_ordering() -> None:
    events = {value: Event() for value in (1, 2, 3)}
    # Chain completions to occur in the order 2 -> 3 -> 1
    triggers: dict[int, Event | None] = {2: events[3], 3: events[1], 1: None}
    events[2].set()

    async def return_when(value: int) -> int:
        await events[value].wait()
        if (trigger := triggers[value]) is not None:
            trigger.set()

        return value

    results: list[int] = []
    async with as_completed(return_when(1), return_when(2), return_when(3)) as stream:
        results.extend([r.return_value async for r in stream])

    assert results == [2, 3, 1]


async def test_as_completed_naming() -> None:
    class Testing(Awaitable[int]):
        async def get_answer(self) -> int:
            return 42

        def __await__(self) -> Generator[Any, Any, int]:
            return self.get_answer().__await__()

    results: list[TaskHandle[Any]] = []
    async with as_completed(checkpoint(), Testing()) as stream:
        results.extend([r async for r in stream])

    # anyio._core._concurrency_utils.as_completed.<locals>.runner
    # would be name of both if coroutine name didn't pass through
    assert results[0].name != results[1].name


async def test_as_completed_no_coroutines() -> None:
    with pytest.raises(ValueError, match="at least one awaitable"):
        async with as_completed():
            pass


async def test_as_completed_propagates_exception() -> None:
    async def fail() -> None:
        raise ValueError("boom")

    async def succeed() -> int:
        await Event().wait()
        return 1

    with pytest.RaisesGroup(pytest.RaisesExc(ValueError, match="boom")):
        async with as_completed(succeed(), fail()) as stream:
            async for _ in stream:
                pass


async def test_as_completed_early_exit() -> None:
    async def return_now() -> int:
        return 1

    async def never() -> int:
        await Event().wait()
        return 2

    # Exiting after the first result must cancel the unfinished task
    async with as_completed(return_now(), never()) as stream:
        assert (await anext(stream)).return_value == 1


async def test_map_results_ordering() -> None:
    # Chain events so the tasks complete in reverse order (3, 2, 1)
    events = [Event() for _ in range(3)]
    events[-1].set()

    async def double(value: int) -> int:
        await events[value - 1].wait()
        if value > 1:
            events[value - 2].set()

        return value * 2

    results = await amap(double, [1, 2, 3])
    assert results == [2, 4, 6]


async def test_map_empty_args() -> None:
    async def double(value: int) -> int:
        return value * 2

    assert await amap(double, []) == []


async def test_map_propagates_exception() -> None:
    async def fail(value: int) -> int:
        if value == 2:
            raise ValueError("boom")

        return value

    with pytest.RaisesGroup(pytest.RaisesExc(ValueError, match="boom")):
        await amap(fail, [1, 2, 3])


async def test_amap_stream_results_in_input_order() -> None:
    # Chain events so the tasks complete in reverse order (3, 2, 1)
    events = [Event() for _ in range(3)]
    events[-1].set()

    async def double(value: int) -> int:
        await events[value - 1].wait()
        if value > 1:
            events[value - 2].set()

        return value * 2

    results = [r async for r in amap_stream(double, [1, 2, 3], limit=3)]
    assert results == [2, 4, 6]


async def test_amap_stream_unordered() -> None:
    # Chain completions to occur in the order 3 -> 2 -> 1
    events = {value: Event() for value in (1, 2, 3)}
    triggers: dict[int, Event | None] = {3: events[2], 2: events[1], 1: None}
    events[3].set()

    async def work(value: int) -> int:
        await events[value].wait()
        if (trigger := triggers[value]) is not None:
            trigger.set()

        return value

    results = [r async for r in amap_stream(work, [1, 2, 3], limit=3, ordered=False)]
    assert results == [3, 2, 1]


async def test_amap_stream_limit() -> None:
    current = 0
    max_concurrent = 0

    async def work(value: int) -> int:
        nonlocal current, max_concurrent
        current += 1
        max_concurrent = max(max_concurrent, current)
        await sleep(0.01)
        current -= 1
        return value

    results = [r async for r in amap_stream(work, range(10), limit=3)]
    assert results == list(range(10))
    assert max_concurrent == 3


async def test_amap_stream_empty() -> None:
    async def work(value: int) -> int:
        return value

    assert [r async for r in amap_stream(work, [], limit=3)] == []


async def test_amap_stream_none_results() -> None:
    async def work(value: int) -> None:
        return None

    results = [r async for r in amap_stream(work, [1, 2, 3], limit=2)]
    assert results == [None, None, None]


async def test_amap_stream_async_iterable() -> None:
    class Source:
        async def __aiter__(self) -> AsyncGenerator[int, None]:
            for value in range(3):
                yield value

    async def double(value: int) -> int:
        return value * 2

    results = [r async for r in amap_stream(double, Source(), limit=2)]
    assert results == [0, 2, 4]


async def test_amap_stream_invalid_arguments() -> None:
    async def work(value: int) -> int:
        return value

    with pytest.raises(ValueError, match="limit must be at least 1"):
        [r async for r in amap_stream(work, [1], limit=0)]

    with pytest.raises(ValueError, match="max_buffered must be at least 0"):
        [r async for r in amap_stream(work, [1], limit=1, max_buffered=-1)]


async def test_amap_stream_func_exception() -> None:
    pulled = 0
    closed = False

    async def source() -> AsyncGenerator[int, None]:
        nonlocal pulled, closed
        try:
            for value in range(100):
                pulled += 1
                yield value
        finally:
            closed = True

    async def work(value: int) -> int:
        if value == 2:
            raise ValueError("boom")

        await Event().wait()  # never completes
        return value

    with pytest.raises(ValueError, match="boom"):
        [r async for r in amap_stream(work, source(), limit=3)]

    # Pulling from the source stopped, the source was closed and the original
    # exception was propagated as-is (not wrapped in an ExceptionGroup)
    assert pulled <= 5
    assert closed


async def test_amap_stream_source_exception() -> None:
    async def source() -> AsyncGenerator[int, None]:
        yield 1
        raise RuntimeError("source failed")

    async def work(value: int) -> int:
        return value

    with pytest.raises(RuntimeError, match="source failed"):
        [r async for r in amap_stream(work, source(), limit=3)]


async def test_amap_stream_multiple_exceptions() -> None:
    async def work(value: int) -> int:
        if value in (1, 2):
            # The shielded checkpoint ensures both tasks have started before
            # either raises, so both exceptions are delivered
            with CancelScope(shield=True):
                await checkpoint()

            raise ValueError(f"boom {value}")

        await Event().wait()  # never completes
        return value

    with pytest.RaisesGroup(ValueError, ValueError):
        [r async for r in amap_stream(work, [0, 1, 2], limit=3)]


async def test_amap_stream_consumer_early_exit() -> None:
    closed = False
    finished: list[int] = []

    async def source() -> AsyncGenerator[int, None]:
        nonlocal closed
        try:
            for value in range(100):
                yield value
        finally:
            closed = True

    async def work(value: int) -> int:
        try:
            await sleep(1)
            return value
        finally:
            finished.append(value)

    stream = amap_stream(work, source(), limit=3)
    async for _ in stream:
        break

    await stream.aclose()
    assert closed
    # The remaining tasks were cancelled and collected, not left hanging
    assert len(finished) >= 2


async def test_amap_stream_consumer_cancelled() -> None:
    async def work(value: int) -> int:
        await sleep(0.01)
        return value

    with CancelScope() as scope:
        async for _ in amap_stream(work, range(10), limit=3):
            scope.cancel()

    assert scope.cancelled_caught


async def test_amap_stream_does_not_read_ahead() -> None:
    pulled = 0
    closed = False

    async def source() -> AsyncGenerator[int, None]:
        nonlocal pulled, closed
        try:
            for value in range(100):
                pulled += 1
                yield value
        finally:
            closed = True

    async def work(value: int) -> int:
        await Event().wait()  # never completes
        return value

    async def consume() -> None:
        async for _ in amap_stream(work, source(), limit=3, max_buffered=2):
            pass

    async with create_task_group() as tg:
        tg.start_soon(consume)
        await wait_all_tasks_blocked()
        # The producer holds one item while waiting for a free task slot
        assert pulled == 4
        tg.cancel_scope.cancel()

    assert closed


async def test_amap_stream_ordered_slow_first_item() -> None:
    pulled = 0
    first_gate = Event()

    async def source() -> AsyncGenerator[int, None]:
        nonlocal pulled
        for value in range(10):
            pulled += 1
            yield value

    async def work(value: int) -> int:
        if value == 0:
            await first_gate.wait()

        return value

    results: list[int] = []

    async def consume() -> None:
        stream = amap_stream(work, source(), limit=3, max_buffered=1)
        results.extend([result async for result in stream])

    async with create_task_group() as tg:
        tg.start_soon(consume)
        await wait_all_tasks_blocked()
        # Results must not pile up behind the slow first item, and the source
        # must not be drained: at most limit + max_buffered + 1 items are pulled
        assert results == []
        assert pulled == 5
        first_gate.set()

    assert results == list(range(10))
