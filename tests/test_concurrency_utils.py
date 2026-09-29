from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Generator
from typing import TYPE_CHECKING, Any

import pytest

from anyio import (
    CancelScope,
    Event,
    amap,
    amap_iter,
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


async def test_amap_iter_ordered_results() -> None:
    # Chain events so the tasks complete in reverse order (3, 2, 1)
    events = [Event() for _ in range(3)]
    events[-1].set()

    async def double_when(value: int) -> int:
        await events[value - 1].wait()
        if value > 1:
            events[value - 2].set()

        return value * 2

    async with amap_iter(double_when, [1, 2, 3], max_tasks=3) as results:
        assert [result async for result in results] == [2, 4, 6]


async def test_amap_iter_unordered_results() -> None:
    events = {value: Event() for value in (1, 2, 3)}
    # Chain completions to occur in the order 2 -> 3 -> 1
    triggers: dict[int, Event | None] = {2: events[3], 3: events[1], 1: None}
    events[2].set()

    async def return_when(value: int) -> int:
        await events[value].wait()
        if (trigger := triggers[value]) is not None:
            trigger.set()

        return value

    async with amap_iter(return_when, [1, 2, 3], max_tasks=3, ordered=False) as results:
        assert [result async for result in results] == [2, 3, 1]


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_max_tasks(ordered: bool) -> None:
    current = 0
    peak = 0

    async def work(value: int) -> int:
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await sleep(0.01)
        current -= 1
        return value

    async with amap_iter(
        work, range(10), max_tasks=3, max_buffered=2, ordered=ordered
    ) as results:
        assert sorted([result async for result in results]) == list(range(10))

    assert peak <= 3


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_does_not_read_ahead(ordered: bool) -> None:
    pulled = 0

    async def source() -> AsyncGenerator[int, None]:
        nonlocal pulled
        for index in range(100):
            pulled += 1
            yield index

    async def work(value: int) -> int:
        await sleep(0.01)
        return value

    async with amap_iter(
        work, source(), max_tasks=2, max_buffered=1, ordered=ordered
    ) as results:
        async for _ in results:
            break

        # The source must not be pulled beyond the consumed item plus the
        # in-flight/buffering window (max_tasks + max_buffered)
        assert pulled <= 1 + 2 + 1


async def test_amap_iter_ordered_slow_first_item() -> None:
    pulled = 0
    completed: list[int] = []
    first_gate = Event()

    async def source() -> AsyncGenerator[int, None]:
        nonlocal pulled
        for index in range(10):
            pulled += 1
            yield index

    async def work(value: int) -> int:
        if value == 0:
            await first_gate.wait()

        completed.append(value)
        return value

    async def check_bounded() -> None:
        await wait_all_tasks_blocked()
        # While the first item is stuck, later results may complete, but the
        # source must not be pulled beyond max_tasks + max_buffered items
        assert pulled == 4
        assert sorted(completed) == [1, 2, 3]
        first_gate.set()

    async with amap_iter(work, source(), max_tasks=2, max_buffered=2) as results:
        async with create_task_group() as tg:
            tg.start_soon(check_bounded)
            assert [result async for result in results] == list(range(10))


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_early_exit(ordered: bool) -> None:
    closed = False
    started: list[int] = []
    finished: list[int] = []
    gate = Event()

    async def source() -> AsyncGenerator[int, None]:
        nonlocal closed
        try:
            for index in range(100):
                yield index
        finally:
            closed = True

    async def work(value: int) -> int:
        started.append(value)
        try:
            if value:
                await gate.wait()

            return value
        finally:
            finished.append(value)

    async with amap_iter(work, source(), max_tasks=2, ordered=ordered) as results:
        async for _ in results:
            break

    # Exiting early must close the source iterator and collect all workers
    assert closed
    assert sorted(started) == sorted(finished)


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_source_failure(ordered: bool) -> None:
    closed = False

    async def source() -> AsyncGenerator[int, None]:
        nonlocal closed
        try:
            yield 1
            raise RuntimeError("source boom")
        finally:
            closed = True

    async def work(value: int) -> int:
        return value

    with pytest.RaisesGroup(pytest.RaisesExc(RuntimeError, match="source boom")):
        async with amap_iter(work, source(), max_tasks=2, ordered=ordered) as results:
            async for _ in results:
                pass

    assert closed


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_func_failure(ordered: bool) -> None:
    closed = False
    pulled = 0

    async def source() -> AsyncGenerator[int, None]:
        nonlocal closed, pulled
        try:
            for index in range(100):
                pulled += 1
                yield index
        finally:
            closed = True

    async def work(value: int) -> int:
        if value == 1:
            raise ValueError("func boom")

        await Event().wait()
        return value

    with pytest.RaisesGroup(pytest.RaisesExc(ValueError, match="func boom")):
        async with amap_iter(work, source(), max_tasks=2, ordered=ordered) as results:
            async for _ in results:
                pass

    # A failing task must stop the source from being pulled further, and the
    # source iterator must be closed
    assert closed
    assert pulled == 2


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_empty(ordered: bool) -> None:
    async def work(value: int) -> int:
        return value

    async with amap_iter(work, [], ordered=ordered) as results:
        assert [result async for result in results] == []


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_none_results(ordered: bool) -> None:
    async def work(value: int) -> None:
        return None

    async with amap_iter(work, range(3), max_tasks=2, ordered=ordered) as results:
        assert [result async for result in results] == [None, None, None]


@pytest.mark.parametrize("ordered", [True, False])
async def test_amap_iter_consumer_cancelled(ordered: bool) -> None:
    started: list[int] = []
    finished: list[int] = []

    async def work(value: int) -> int:
        started.append(value)
        try:
            if value:
                await Event().wait()

            return value
        finally:
            finished.append(value)

    async with amap_iter(work, range(10), max_tasks=2, ordered=ordered) as results:
        with CancelScope() as scope:
            async for _ in results:
                scope.cancel()

    # Cancelling the consumer must not leave any workers hanging
    assert sorted(started) == sorted(finished)


async def test_amap_iter_invalid_params() -> None:
    async def work(value: int) -> int:
        return value

    with pytest.raises(ValueError, match="max_tasks must be at least 1"):
        async with amap_iter(work, [1], max_tasks=0):
            pass

    with pytest.raises(ValueError, match="max_buffered must be at least 0"):
        async with amap_iter(work, [1], max_buffered=-1):
            pass
