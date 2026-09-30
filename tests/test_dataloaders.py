import asyncio
from asyncio.futures import Future
from collections.abc import Awaitable, Callable
from typing import Any, Optional, cast

import pytest
from pytest_mock import MockerFixture

from strawberry.dataloader import AbstractCache, DataLoader
from strawberry.exceptions import WrongNumberOfResultsReturned

IDXType = Callable[[list[int]], Awaitable[list[int]]]


async def idx(keys: list[int]) -> list[int]:
    return keys


@pytest.mark.asyncio
async def test_loading():
    loader = DataLoader(load_fn=idx)

    value_a = await loader.load(1)
    value_b = await loader.load(2)
    value_c = await loader.load(3)

    assert value_a == 1
    assert value_b == 2
    assert value_c == 3

    values = await loader.load_many([1, 2, 3, 4, 5, 6])

    assert values == [1, 2, 3, 4, 5, 6]


@pytest.mark.asyncio
async def test_gathering(mocker: MockerFixture):
    mock_loader = mocker.Mock(side_effect=idx)

    loader = DataLoader(load_fn=cast("IDXType", mock_loader))

    [value_a, value_b, value_c] = await asyncio.gather(
        loader.load(1),
        loader.load(2),
        loader.load(3),
    )

    mock_loader.assert_called_once_with([1, 2, 3])

    assert value_a == 1
    assert value_b == 2
    assert value_c == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_max_batch_size(mocker: MockerFixture, cache: bool):
    mock_loader = mocker.Mock(side_effect=idx)

    loader = DataLoader(
        load_fn=cast("IDXType", mock_loader), max_batch_size=2, cache=cache
    )

    [value_a, value_b, value_c] = await asyncio.gather(
        loader.load(1),
        loader.load(2),
        loader.load(3),
    )

    mock_loader.assert_has_calls([mocker.call([1, 2]), mocker.call([3])])  # type: ignore

    assert value_a == 1
    assert value_b == 2
    assert value_c == 3


@pytest.mark.asyncio
async def test_error():
    async def idx(keys: list[int]) -> list[int | ValueError]:
        return [ValueError()]

    loader = DataLoader(load_fn=idx)

    with pytest.raises(ValueError):
        await loader.load(1)


@pytest.mark.asyncio
async def test_error_and_values():
    async def idx(keys: list[int]) -> list[int | ValueError]:
        return [2] if keys == [2] else [ValueError()]

    loader = DataLoader(load_fn=idx)

    with pytest.raises(ValueError):
        await loader.load(1)

    assert await loader.load(2) == 2


@pytest.mark.asyncio
async def test_when_raising_error_in_loader():
    async def idx(keys: list[int]) -> list[int | ValueError]:
        raise ValueError

    loader = DataLoader(load_fn=idx)

    with pytest.raises(ValueError):
        await loader.load(1)

    with pytest.raises(ValueError):
        await asyncio.gather(
            loader.load(1),
            loader.load(2),
            loader.load(3),
        )


@pytest.mark.asyncio
async def test_returning_wrong_number_of_results():
    async def idx(keys: list[int]) -> list[int]:
        return [1, 2]

    loader = DataLoader(load_fn=idx)

    with pytest.raises(
        WrongNumberOfResultsReturned,
        match=(
            "Received wrong number of results in dataloader, expected: 1, received: 2"
        ),
    ):
        await loader.load(1)


@pytest.mark.asyncio
async def test_caches_by_id(mocker: MockerFixture):
    mock_loader = mocker.Mock(side_effect=idx)

    loader = DataLoader(load_fn=cast("IDXType", mock_loader), cache=True)

    a = loader.load(1)
    b = loader.load(1)

    assert a is not b

    assert await a == 1
    assert await b == 1

    mock_loader.assert_called_once_with([1])


@pytest.mark.asyncio
async def test_caches_by_id_when_loading_many(mocker: MockerFixture):
    mock_loader = mocker.Mock(side_effect=idx)

    loader = DataLoader(load_fn=cast("IDXType", mock_loader), cache=True)

    a = loader.load(1)
    b = loader.load(1)

    assert a is not b

    assert await asyncio.gather(a, b) == [1, 1]

    mock_loader.assert_called_once_with([1])


@pytest.mark.asyncio
async def test_cache_disabled(mocker: MockerFixture):
    mock_loader = mocker.Mock(side_effect=idx)

    loader = DataLoader(load_fn=cast("IDXType", mock_loader), cache=False)

    a = loader.load(1)
    b = loader.load(1)

    assert a != b

    assert await a == 1
    assert await b == 1

    mock_loader.assert_has_calls([mocker.call([1, 1])])  # type: ignore


@pytest.mark.asyncio
async def test_cache_disabled_immediate_await(mocker: MockerFixture):
    mock_loader = mocker.Mock(side_effect=idx)

    loader = DataLoader(load_fn=cast("IDXType", mock_loader), cache=False)

    a = await loader.load(1)
    b = await loader.load(1)

    assert a == b

    mock_loader.assert_has_calls([mocker.call([1]), mocker.call([1])])  # type: ignore


@pytest.mark.asyncio
async def test_prime():
    async def idx(keys: list[int | float]) -> list[int | float]:
        assert keys, "At least one key must be specified"
        return keys

    loader = DataLoader(load_fn=idx)

    # Basic behavior intact
    a1 = loader.load(1)
    assert await a1 == 1

    # Prime doesn't overrides value
    loader.prime(1, 1.1)
    loader.prime(2, 2.1)
    b1 = loader.load(1)
    b2 = loader.load(2)
    assert await b1 == 1
    assert await b2 == 2.1

    # Unless you tell it to
    loader.prime(1, 1.2, force=True)
    loader.prime(2, 2.2, force=True)
    b1 = loader.load(1)
    b2 = loader.load(2)
    assert await b1 == 1.2
    assert await b2 == 2.2

    # Preset will override pending values, but not cached values
    c2 = loader.load(2)  # This is in cache
    c3 = loader.load(3)  # This is pending
    loader.prime_many({2: 2.3, 3: 3.3}, force=True)
    assert await c2 == 2.2
    assert await c3 == 3.3

    # If we prime all keys in a batch, the load_fn is never called
    # (See assertion in idx)
    c4 = loader.load(4)
    loader.prime_many({4: 4.4})
    assert await c4 == 4.4

    # Yield to ensure the last batch has been dispatched,
    # despite all values being primed
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_prime_nocache():
    async def idx(keys: list[int | float]) -> list[int | float]:
        assert keys, "At least one key must be specified"
        return keys

    loader = DataLoader(load_fn=idx, cache=False)

    # Primed value is ignored
    loader.prime(1, 1.1)
    a1 = loader.load(1)
    assert await a1 == 1

    # Unless it affects pending value in the current batch
    b1 = loader.load(2)
    loader.prime(2, 2.2)
    assert await b1 == 2.2

    # Yield to ensure the last batch has been dispatched,
    # despite all values being primed
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_clear():
    batch_num = 0

    async def idx(keys: list[int]) -> list[tuple[int, int]]:
        """Maps key => (key, batch_num)"""
        nonlocal batch_num
        batch_num += 1
        return [(key, batch_num) for key in keys]

    loader = DataLoader(load_fn=idx)

    assert await loader.load_many([1, 2, 3]) == [(1, 1), (2, 1), (3, 1)]

    loader.clear(1)

    assert await loader.load_many([1, 2, 3]) == [(1, 2), (2, 1), (3, 1)]

    loader.clear_many([1, 2])

    assert await loader.load_many([1, 2, 3]) == [(1, 3), (2, 3), (3, 1)]

    loader.clear_all()

    assert await loader.load_many([1, 2, 3]) == [(1, 4), (2, 4), (3, 4)]


@pytest.mark.asyncio
async def test_clear_nocache():
    batch_num = 0

    async def idx(keys: list[int]) -> list[tuple[int, int]]:
        """Maps key => (key, batch_num)"""
        nonlocal batch_num
        batch_num += 1
        return [(key, batch_num) for key in keys]

    loader = DataLoader(load_fn=idx, cache=False)

    assert await loader.load_many([1, 2, 3]) == [(1, 1), (2, 1), (3, 1)]

    loader.clear(1)

    assert await loader.load_many([1, 2, 3]) == [(1, 2), (2, 2), (3, 2)]

    loader.clear_many([1, 2])

    assert await loader.load_many([1, 2, 3]) == [(1, 3), (2, 3), (3, 3)]

    loader.clear_all()

    assert await loader.load_many([1, 2, 3]) == [(1, 4), (2, 4), (3, 4)]


@pytest.mark.asyncio
async def test_dont_dispatch_cancelled():
    async def idx(keys: list[int]) -> list[int]:
        await asyncio.sleep(0.2)
        return keys

    loader = DataLoader(load_fn=idx)

    value_a = await loader.load(1)
    # value_b will be cancelled by hand
    value_b = cast("Future[Any]", loader.load(2))
    value_b.cancel()
    # value_c will be cancelled by the timeout
    value_c = cast("Future[Any]", loader.load(3))
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(value_c, 0.1)
    value_d = await loader.load(4)

    assert value_a == 1
    assert value_d == 4

    # 2 can still be used here because a new future will be created for it
    values = await loader.load_many([1, 2, 3, 4, 5, 6])
    assert values == [1, 2, 3, 4, 5, 6]

    with pytest.raises(asyncio.CancelledError):
        value_b.result()
    with pytest.raises(asyncio.CancelledError):
        value_c.result()  # pyright: ignore

    # Try single loading results again to make sure the cancelled
    # futures are not being reused
    value_a = await loader.load(1)
    value_b = await loader.load(2)
    value_c = await loader.load(3)
    value_d = await loader.load(4)

    assert value_a == 1
    assert value_b == 2
    assert value_c == 3
    assert value_d == 4


@pytest.mark.asyncio
async def test_cancelled_future_with_failing_loader():
    """When the load function raises and some futures are already cancelled,
    the error handler should skip cancelled futures instead of raising
    InvalidStateError.

    This reproduces a real-world scenario where a client disconnects
    mid-request: some DataLoader futures get cancelled by the event loop,
    then the batch load function fails (e.g. because the executor is torn
    down). The error handler must not crash trying to set_exception on
    the already-cancelled futures.
    """

    async def failing_loader(keys: list[int]) -> list[int]:
        raise RuntimeError("executor is broken")

    loader = DataLoader(load_fn=failing_loader, cache=False)

    future_a = cast("Future[Any]", loader.load(1))
    future_b = cast("Future[Any]", loader.load(2))
    future_c = cast("Future[Any]", loader.load(3))

    # Simulate a client disconnect cancelling one of the futures before
    # the batch dispatches
    future_a.cancel()

    # Let the event loop dispatch the batch — this must not raise
    # InvalidStateError from trying to set_exception on the cancelled future.
    # Two yields: one for call_soon to fire create_task, one for the task to run.
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    # The cancelled future should remain cleanly cancelled — not broken by
    # an InvalidStateError inside dispatch_batch
    assert future_a.cancelled()
    with pytest.raises(asyncio.CancelledError):
        future_a.result()

    # The non-cancelled futures should receive the loader's exception
    # (without the fix, dispatch_batch crashes on future_a before reaching these)
    results = await asyncio.gather(future_b, future_c, return_exceptions=True)
    assert all(
        isinstance(result, RuntimeError) and result.args == ("executor is broken",)
        for result in results
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_all_futures_cancelled_skips_load_fn(cache: bool):
    """When all futures in a batch are cancelled before dispatch, the load_fn
    should not be called at all.  This prevents wasted work like database
    queries whose results no one is waiting for.
    """
    call_count = 0

    async def counting_loader(keys: list[int]) -> list[int]:
        nonlocal call_count
        call_count += 1
        return keys

    loader = DataLoader(load_fn=counting_loader, cache=cache)

    future_a = cast("Future[Any]", loader.load(1))
    future_b = cast("Future[Any]", loader.load(2))

    # Cancel all futures before the batch dispatches
    future_a.cancel()
    future_b.cancel()

    # Let the event loop dispatch (call_soon → create_task → dispatch_batch)
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert future_a.cancelled()
    assert future_b.cancelled()
    assert call_count == 0, "load_fn should not have been called"


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_cancelled_futures_cancel_dispatch_task(cache: bool):
    """When all futures in a batch are cancelled, the underlying dispatch
    task should also be cancelled.  This is important for resource cleanup
    when using asyncio.TaskGroup or similar structured concurrency patterns.
    """

    async def slow_loader(keys: list[int]) -> list[int]:
        await asyncio.sleep(10)
        return keys

    loader = DataLoader(load_fn=slow_loader, cache=cache)

    future_a = cast("Future[Any]", loader.load(1))
    future_b = cast("Future[Any]", loader.load(2))

    # Let call_soon fire so the dispatch task is created
    await asyncio.sleep(0)
    # Let the task start and suspend inside slow_loader's asyncio.sleep(10)
    await asyncio.sleep(0)

    assert loader.batch is not None
    dispatch_task = loader.batch._dispatch_task
    assert dispatch_task is not None
    assert not dispatch_task.done()

    # Cancel all futures — this should cascade to the dispatch task
    future_a.cancel()
    future_b.cancel()

    # Wait for the internal futures' cancellation callbacks to propagate
    # CancelledError to the dispatch task.
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(dispatch_task, timeout=1)

    assert dispatch_task.cancelled()


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_cancelled_futures_cancel_running_dispatch(cache: bool):
    """When all futures are cancelled after load_fn has already started,
    the dispatch task should still be cancelled, interrupting the in-progress
    load_fn via CancelledError.
    """
    load_started = asyncio.Event()

    async def slow_loader(keys: list[int]) -> list[int]:
        load_started.set()
        # Block until cancelled
        await asyncio.sleep(10)
        return keys

    loader = DataLoader(load_fn=slow_loader, cache=cache)

    future_a = cast("Future[Any]", loader.load(1))
    future_b = cast("Future[Any]", loader.load(2))

    # Let call_soon fire and dispatch_batch start running
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await load_started.wait()

    assert loader.batch is not None
    dispatch_task = loader.batch._dispatch_task
    assert dispatch_task is not None
    assert not dispatch_task.done()

    # Cancel all futures while load_fn is in progress
    future_a.cancel()
    future_b.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(dispatch_task, timeout=1)

    assert future_a.cancelled()
    assert future_b.cancelled()
    assert dispatch_task.cancelled()


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_partial_cancellation_still_dispatches(cache: bool):
    """When only some futures in a batch are cancelled, the batch should
    still dispatch and deliver results for the non-cancelled futures.
    """
    call_count = 0

    async def counting_loader(keys: list[int]) -> list[int]:
        nonlocal call_count
        call_count += 1
        return keys

    loader = DataLoader(load_fn=counting_loader, cache=cache)

    future_a = cast("Future[Any]", loader.load(1))
    future_b = cast("Future[Any]", loader.load(2))
    future_c = cast("Future[Any]", loader.load(3))

    # Cancel only one future
    future_b.cancel()

    # Let the batch dispatch and propagate results to caller futures
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert await asyncio.gather(future_a, future_c) == [1, 3]
    assert future_b.cancelled()
    assert call_count == 1, "load_fn should still be called for non-cancelled futures"


@pytest.mark.asyncio
async def test_cache_override():
    class TestCache(AbstractCache[int, int]):
        def __init__(self):
            self.cache: dict[int, Future[int]] = {}

        def get(self, key: int) -> Optional["Future[int]"]:
            return self.cache.get(key)

        def set(self, key: int, value: "Future[int]") -> None:
            self.cache[key] = value

        def delete(self, key: int) -> None:
            del self.cache[key]

        def clear(self) -> None:
            self.cache.clear()

    custom_cache = TestCache()
    loader = DataLoader(load_fn=idx, cache_map=custom_cache)

    await loader.load(1)
    await loader.load(2)
    await loader.load(3)

    assert len(custom_cache.cache) == 3
    assert await custom_cache.cache[1] == 1
    assert await custom_cache.cache[2] == 2
    assert await custom_cache.cache[3] == 3

    loader.clear(1)
    assert len(custom_cache.cache) == 2
    assert sorted(custom_cache.cache.keys()) == [2, 3]

    loader.clear_all()
    assert len(custom_cache.cache) == 0
    assert not list(custom_cache.cache.keys())

    await loader.load(1)
    await loader.load(2)
    await loader.load(3)

    loader.clear_many([1, 2])
    assert len(custom_cache.cache) == 1
    assert list(custom_cache.cache.keys()) == [3]

    data = await loader.load(3)
    assert data == 3

    loader.prime(3, 4)
    assert await custom_cache.cache[3] == 3

    loader.prime(3, 4, True)
    assert await custom_cache.cache[3] == 4

    with pytest.raises(TypeError, match="unhashable type: 'list'"):
        await loader.load([1, 2, 3])  # type: ignore

    data = await loader.load((1, 2, 3))  # type: ignore
    assert await custom_cache.get((1, 2, 3)) == data  # type: ignore


@pytest.mark.asyncio
async def test_custom_cache_key_fn():
    def custom_cache_key(key: list[int]) -> str:
        return ",".join(str(k) for k in key)

    loader = DataLoader(load_fn=idx, cache_key_fn=custom_cache_key)
    data = await loader.load([1, 2, "test"])
    assert data == [1, 2, "test"]


@pytest.mark.asyncio
async def test_user_class_custom_cache_key_fn():
    class CustomData:
        def __init__(self, custom_id: int, name: str):
            self.id: int = custom_id
            self.name: str = name

    def custom_cache_key(key: CustomData) -> int:
        return key.id

    loader = DataLoader(load_fn=idx, cache_key_fn=custom_cache_key)
    data1 = await loader.load(CustomData(1, "Nick"))
    data2 = await loader.load(CustomData(1, "Nick"))
    assert data1 == data2

    data2 = await loader.load(CustomData(2, "Jane"))
    assert data1 != data2


def test_works_when_created_in_a_different_loop(mocker: MockerFixture):
    mock_loader = mocker.Mock(side_effect=idx)
    loader = DataLoader(load_fn=cast("IDXType", mock_loader), cache=False)

    loop = asyncio.new_event_loop()

    async def run():
        return await loader.load(1)

    data = loop.run_until_complete(run())

    assert data == 1

    mock_loader.assert_called_once_with([1])


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_batching_window(cache: bool):
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        return keys

    loader = DataLoader(load_fn=load, cache=cache)
    first = loader.load(1)
    # Scheduling the dispatch task must still allow loads in this next turn
    # to join the batch, before load_fn starts.
    await asyncio.sleep(0)
    second = loader.load(2)
    assert calls == []
    assert await asyncio.gather(first, second) == [1, 2]
    assert await loader.load(3) == 3
    assert calls == [[1, 2], [3]]


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_prime_empty_batch_then_load(cache: bool):
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        return keys

    loader = DataLoader(load_fn=load, cache=cache, max_batch_size=2)
    first = loader.load(1)
    loader.prime(1, 10)
    # A pending dispatch for the emptied batch must not affect later loads.
    assert await loader.load_many([2, 3, 4]) == [2, 3, 4]
    assert await first == 10
    assert calls == [[2, 3], [4]]


@pytest.mark.asyncio
@pytest.mark.parametrize("cache", [False, True])
async def test_partial_cancellation_during_load(cache: bool):
    started = asyncio.Event()
    finish = asyncio.Event()
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        started.set()
        await finish.wait()
        return keys

    loader = DataLoader(load_fn=load, cache=cache)
    first = cast("Future[int]", loader.load(1))
    second = loader.load(2)
    await started.wait()
    first.cancel()
    await asyncio.sleep(0)
    finish.set()

    assert await asyncio.wait_for(second, timeout=1) == 2
    assert first.cancelled()
    # A cancelled cached future must be replaced on the next load.
    assert await asyncio.wait_for(loader.load(1), timeout=1) == 1
    assert calls == [[1, 2], [1]]


@pytest.mark.asyncio
async def test_result_ttl_uses_completion_time_with_injected_clock():
    current_time = 100.0
    started = asyncio.Event()
    finish = asyncio.Event()
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        started.set()
        await finish.wait()
        return keys

    loader = DataLoader(
        load_fn=load,
        result_ttl=5,
        time_fn=lambda: current_time,
    )

    pending = loader.load(1)
    await started.wait()

    current_time = 200.0
    finish.set()
    assert await pending == 1
    assert calls == [[1]]

    current_time = 204.0
    assert await loader.load(1) == 1
    assert calls == [[1]]

    current_time = 205.0
    assert await loader.load(1) == 1
    assert calls == [[1], [1]]


@pytest.mark.asyncio
async def test_max_cache_size_evicts_completed_results_only():
    pending_started = asyncio.Event()
    release_pending = asyncio.Event()
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        if 3 in keys:
            pending_started.set()
            await release_pending.wait()
        return keys

    loader = DataLoader(load_fn=load, max_cache_size=2)
    pending = loader.load(3)
    await pending_started.wait()

    assert await loader.load_many([1, 2]) == [1, 2]

    assert await loader.load(1) == 1
    assert await loader.load(2) == 2

    release_pending.set()
    assert await pending == 3

    assert await loader.load(3) == 3
    assert calls == [[3], [1, 2]]
    assert await loader.load(1) == 1
    assert calls == [[3], [1, 2], [1]]


@pytest.mark.asyncio
async def test_max_cache_size_uses_lru_order(mocker: MockerFixture):
    mock_loader = mocker.Mock(side_effect=idx)
    loader = DataLoader(load_fn=cast("IDXType", mock_loader), max_cache_size=2)

    assert await loader.load_many([1, 2, 3]) == [1, 2, 3]
    mock_loader.reset_mock()

    assert await loader.load(2) == 2
    assert await loader.load(3) == 3
    assert await loader.load(1) == 1

    mock_loader.assert_called_once_with([1])


@pytest.mark.asyncio
@pytest.mark.parametrize("cache_exceptions", [False, True])
async def test_cache_exceptions_configuration(cache_exceptions: bool):
    calls = 0

    async def load(keys: list[int]) -> list[int | ValueError]:
        nonlocal calls
        calls += 1
        return [ValueError("missing") for _ in keys]

    loader = DataLoader(load_fn=load, cache_exceptions=cache_exceptions)

    for _ in range(2):
        with pytest.raises(ValueError, match="missing"):
            await loader.load(1)

    if cache_exceptions:
        assert calls == 1
    else:
        assert calls == 2


@pytest.mark.parametrize(
    ("result_ttl", "max_cache_size"),
    [(-1, None), (None, -1)],
)
def test_invalid_cache_options(result_ttl: int | None, max_cache_size: int | None):
    with pytest.raises(ValueError):
        DataLoader(
            load_fn=idx,
            result_ttl=result_ttl,
            max_cache_size=max_cache_size,
        )


@pytest.mark.asyncio
async def test_clear_takes_precedence_over_late_batch_result():
    started = asyncio.Event()
    finish = asyncio.Event()
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        started.set()
        await finish.wait()
        return keys

    loader = DataLoader(load_fn=load)
    first = loader.load(1)
    await started.wait()
    loader.clear(1)
    finish.set()

    assert await first == 1

    assert await loader.load(1) == 1
    assert calls == [[1], [1]]


@pytest.mark.asyncio
async def test_force_prime_takes_precedence_over_late_batch_result():
    started = asyncio.Event()
    finish = asyncio.Event()
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        started.set()
        await finish.wait()
        return keys

    loader = DataLoader(load_fn=load)
    first = loader.load(1)
    await started.wait()
    loader.prime(1, 10, force=True)
    finish.set()

    assert await first == 10
    assert await loader.load(1) == 10
    assert calls == [[1]]


@pytest.mark.asyncio
async def test_force_prime_takes_precedence_over_old_dispatched_batch():
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        if 1 in keys:
            first_started.set()
            await release_first.wait()
        return keys

    loader = DataLoader(load_fn=load, max_batch_size=1)
    first = loader.load(1)
    await first_started.wait()

    second = loader.load(2)
    loader.prime(1, 10, force=True)
    release_first.set()

    assert await first == 10
    assert await second == 2
    assert await loader.load(1) == 10
    assert calls == [[1], [2]]


@pytest.mark.asyncio
async def test_cancelling_one_caller_does_not_cancel_other_waiters():
    started = asyncio.Event()
    finish = asyncio.Event()
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        started.set()
        await finish.wait()
        return keys

    loader = DataLoader(load_fn=load)
    first = cast("Future[Any]", loader.load(1))
    second = loader.load(1)
    await started.wait()

    first.cancel()
    await asyncio.sleep(0)

    assert first.cancelled()
    assert not second.done()

    finish.set()
    assert await second == 1
    assert calls == [[1]]


@pytest.mark.asyncio
async def test_same_key_is_merged_in_one_batch():
    calls: list[list[int]] = []

    async def load(keys: list[int]) -> list[int]:
        calls.append(keys)
        return keys

    loader = DataLoader(load_fn=load)
    results = await asyncio.gather(loader.load(1), loader.load(1))

    assert results == [1, 1]
    assert calls == [[1]]
