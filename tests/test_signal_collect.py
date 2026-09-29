import asyncio
import gc

import pytest
import pytest_asyncio

from sanic_routing.exceptions import NotFound


@pytest_asyncio.fixture
async def unretrieved():
    """Capture any background exception the loop reports (e.g. exceptions
    that were never retrieved from a task)."""
    loop = asyncio.get_running_loop()
    captured = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: captured.append(ctx))
    yield captured
    loop.set_exception_handler(previous)
    gc.collect()
    assert captured == []


def make_handlers(app, event, delays, values):
    completion_order = []

    for delay, value in zip(delays, values):

        async def handler(delay=delay, value=value):
            await asyncio.sleep(delay)
            completion_order.append(value)
            return value

        app.add_signal(handler, event)

    return completion_order


@pytest.mark.asyncio
async def test_collect_stable_slot_order_regardless_of_completion(app):
    delays = {"a": 0.05, "b": 0.01, "c": 0.03}
    completion_order = []

    for value in ("a", "b", "c"):

        async def handler(value=value):
            # Read the (mutable) delay at call time so the completion
            # order can be changed between collect calls
            await asyncio.sleep(delays[value])
            completion_order.append(value)
            return value

        app.add_signal(handler, "foo.bar.baz")

    app.signal_router.finalize()

    first = await app.collect("foo.bar.baz")
    first_completion = list(completion_order)

    # Change the timing so handlers complete in a different order
    delays.update({"a": 0.01, "b": 0.05, "c": 0.03})
    completion_order.clear()
    second = await app.collect("foo.bar.baz")

    assert first == second
    assert sorted(first) == ["a", "b", "c"]
    # Completion order really did change and differs from slot order
    assert completion_order == ["a", "c", "b"]
    assert first_completion == ["b", "c", "a"]
    assert first != first_completion


@pytest.mark.asyncio
async def test_collect_reverses_with_reverse_flag(app):
    make_handlers(app, "foo.bar.baz", [0, 0, 0], ["a", "b", "c"])
    app.signal_router.finalize()

    normal = await app.collect("foo.bar.baz")
    reversed_results = await app.collect("foo.bar.baz", reverse=True)

    assert normal == list(reversed(reversed_results))
    assert sorted(normal) == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_collect_false_and_none_are_real_results(app):
    make_handlers(app, "foo.bar.baz", [0, 0, 0], [False, None, 0])
    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz")

    assert sorted(results, key=lambda r: (r is None, r is False, r)) == [
        0,
        False,
        None,
    ]
    assert len(results) == 3


@pytest.mark.asyncio
async def test_collect_dispatch_behavior_unchanged(app):
    # dispatch still short-circuits on the first truthy value
    make_handlers(app, "foo.bar.baz", [0, 0, 0], ["", "winner", "late"])
    app.signal_router.finalize()

    result = await app.dispatch("foo.bar.baz", inline=True)

    assert result == "winner"


@pytest.mark.asyncio
async def test_collect_with_dynamic_event_and_context(app):
    @app.signal("foo.bar.<uid:int>")
    async def dynamic_handler(uid, extra):
        return (uid, extra)

    app.signal_router.finalize()

    results = await app.collect("foo.bar.9", context={"extra": "ctx"})

    assert results == [(9, "ctx")]


@pytest.mark.asyncio
async def test_collect_with_condition(app):
    @app.signal("foo.bar.baz")
    async def plain():
        return "plain"

    @app.signal("foo.bar.baz", condition={"one": "two"})
    async def conditional():
        return "conditional"

    app.signal_router.finalize()

    assert await app.collect("foo.bar.baz") == ["plain"]
    assert await app.collect("foo.bar.baz", condition={"one": "two"}) == [
        "conditional"
    ]


@pytest.mark.asyncio
async def test_collect_max_concurrency_limits_parallelism(app):
    running = 0
    max_seen = 0

    for value in ("a", "b", "c"):

        async def handler(value=value):
            nonlocal running, max_seen
            running += 1
            max_seen = max(max_seen, running)
            await asyncio.sleep(0.01)
            running -= 1
            return value

        app.add_signal(handler, "foo.bar.baz")

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz", max_concurrency=1)

    assert max_seen == 1
    assert sorted(results) == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_collect_invalid_options(app):
    @app.signal("foo.bar.baz")
    async def handler():
        return "x"

    app.signal_router.finalize()

    with pytest.raises(ValueError, match="on_failure"):
        await app.collect("foo.bar.baz", on_failure="boom")
    with pytest.raises(ValueError, match="max_concurrency"):
        await app.collect("foo.bar.baz", max_concurrency=0)


@pytest.mark.asyncio
async def test_collect_not_found(app):
    app.signal_router.finalize()

    with pytest.raises(NotFound):
        await app.collect("foo.bar.baz")
    assert await app.collect("foo.bar.baz", fail_not_found=False) == []


@pytest.mark.asyncio
async def test_collect_aggregate_exceptions(app, unretrieved):
    error = ValueError("handler failed")

    @app.signal("foo.bar.baz")
    async def good_one():
        await asyncio.sleep(0.01)
        return "good-one"

    @app.signal("foo.bar.baz")
    async def bad():
        await asyncio.sleep(0)
        raise error

    @app.signal("foo.bar.baz")
    async def good_two():
        await asyncio.sleep(0.02)
        return "good-two"

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz")

    assert len(results) == 3
    assert results[0] == "good-one"
    assert results[1] is error
    assert results[2] == "good-two"


@pytest.mark.asyncio
async def test_collect_cancel_on_failure(app, unretrieved):
    error = ValueError("handler failed")
    slow_exited = asyncio.Event()

    @app.signal("foo.bar.baz")
    async def slow():
        try:
            await asyncio.sleep(10)
            return "slow"
        finally:
            slow_exited.set()

    @app.signal("foo.bar.baz")
    async def bad():
        await asyncio.sleep(0.01)
        raise error

    app.signal_router.finalize()

    with pytest.raises(ValueError, match="handler failed"):
        await app.collect("foo.bar.baz", on_failure="cancel")

    # The remaining handler was cancelled and fully exited before the
    # exception propagated
    assert slow_exited.is_set()


@pytest.mark.asyncio
async def test_collect_external_cancellation_waits_for_handlers(
    app, unretrieved
):
    started = []
    exited = []

    for name in ("a", "b", "c"):

        async def handler(name=name):
            started.append(name)
            try:
                await asyncio.sleep(10)
                return name
            finally:
                await asyncio.sleep(0)
                exited.append(name)

        app.add_signal(handler, "foo.bar.baz")

    app.signal_router.finalize()

    task = asyncio.create_task(app.collect("foo.bar.baz"))
    while len(started) < 3:
        await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    # Every started handler fully exited before cancellation propagated
    assert sorted(exited) == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_collect_uses_fixed_snapshot_with_nested_dispatch(app):
    nested_done = False
    inner_results = None

    @app.signal("foo.bar.baz")
    async def first(**_):
        return "first"

    @app.signal("foo.bar.baz")
    async def nested(**_):
        nonlocal nested_done, inner_results
        if not nested_done:
            nested_done = True
            # Re-entrant collect of the same event with its own context
            # must not corrupt the outer collect call
            inner_results = await app.collect(
                "foo.bar.baz", context={"inner": True}
            )
        return "nested"

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz")

    assert sorted(results) == ["first", "nested"]
    assert sorted(inner_results) == ["first", "nested"]


@pytest.mark.asyncio
async def test_collect_triggers_waiters(app):
    @app.signal("foo.bar.baz")
    async def handler():
        return "x"

    app.signal_router.finalize()

    event_task = asyncio.create_task(app.event("foo.bar.baz"))
    await asyncio.sleep(0)
    await app.collect("foo.bar.baz")
    await asyncio.sleep(0)

    assert event_task.done()
    event_task.result()
