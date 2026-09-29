import asyncio

import pytest

from sanic_routing.exceptions import NotFound

from sanic.exceptions import SignalCollectError


@pytest.mark.asyncio
async def test_collect_stable_result_order_with_varied_durations(app):
    completion_order = []
    delays = {}

    def make_handler(name):
        async def handler(**_):
            await asyncio.sleep(delays[name])
            completion_order.append(name)
            return name

        return handler

    app.add_signal(make_handler("one"), "foo.bar.baz")
    app.add_signal(make_handler("two"), "foo.bar.baz")
    app.add_signal(make_handler("three"), "foo.bar.baz")

    app.signal_router.finalize()

    # The default slot order follows the registration order
    delays.update({"one": 0.03, "two": 0.01, "three": 0.02})
    first = await app.collect("foo.bar.baz")
    assert first == ["one", "two", "three"]
    assert completion_order == ["two", "three", "one"]

    # Change the completion order; the slot order must not change
    completion_order.clear()
    delays.update({"one": 0.01, "two": 0.03, "three": 0.02})
    second = await app.collect("foo.bar.baz")
    assert second == first
    assert completion_order == ["one", "three", "two"]

    # reverse=True iterates the signals in reverse order
    third = await app.collect("foo.bar.baz", reverse=True)
    assert third == ["three", "two", "one"]


@pytest.mark.asyncio
async def test_collect_false_and_none_are_real_results(app):
    app.add_signal(lambda **_: False, "foo.bar.baz")
    app.add_signal(lambda **_: None, "foo.bar.baz")
    app.add_signal(lambda **_: 0, "foo.bar.baz")

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz")
    assert results == [False, None, 0]


@pytest.mark.asyncio
async def test_collect_sync_and_async_handlers(app):
    def sync_handler(**_):
        return "sync"

    async def async_handler(**_):
        await asyncio.sleep(0)
        return "async"

    app.add_signal(sync_handler, "foo.bar.baz")
    app.add_signal(async_handler, "foo.bar.baz")

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz")
    assert results == ["sync", "async"]


@pytest.mark.asyncio
async def test_collect_max_concurrency(app):
    running = 0
    max_seen = 0

    async def handler(**_):
        nonlocal running, max_seen
        running += 1
        max_seen = max(max_seen, running)
        await asyncio.sleep(0.01)
        running -= 1

    for _ in range(5):
        app.add_signal(handler, "foo.bar.baz")

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz", max_concurrency=2)
    assert results == [None] * 5
    assert max_seen == 2

    max_seen = 0
    await app.collect("foo.bar.baz")
    assert max_seen == 5


@pytest.mark.asyncio
async def test_collect_aggregates_exceptions(app):
    ran = []

    async def fail_one(**_):
        await asyncio.sleep(0.01)
        raise ValueError("one")

    async def succeed(**_):
        ran.append("succeed")
        return "ok"

    async def fail_two(**_):
        raise RuntimeError("two")

    app.add_signal(fail_one, "foo.bar.baz")
    app.add_signal(succeed, "foo.bar.baz")
    app.add_signal(fail_two, "foo.bar.baz")

    app.signal_router.finalize()

    with pytest.raises(SignalCollectError) as excinfo:
        await app.collect("foo.bar.baz")

    errors = excinfo.value.exceptions
    assert len(errors) == 2
    # Exceptions are reported in stable slot order
    assert isinstance(errors[0], ValueError)
    assert isinstance(errors[1], RuntimeError)
    # The healthy handler still ran to completion
    assert ran == ["succeed"]


@pytest.mark.asyncio
async def test_collect_cancel_on_error_cancels_remaining(app):
    cancelled = []

    async def slow(**_):
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.append("slow")
            raise

    async def fail(**_):
        await asyncio.sleep(0.01)
        raise ValueError("boom")

    app.add_signal(slow, "foo.bar.baz")
    app.add_signal(fail, "foo.bar.baz")

    app.signal_router.finalize()

    with pytest.raises(ValueError, match="boom"):
        await app.collect("foo.bar.baz", cancel_on_error=True)

    assert cancelled == ["slow"]
    # No background tasks (with potentially unretrieved exceptions) linger
    await asyncio.sleep(0)
    pending = [
        task
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
    ]
    assert pending == []


@pytest.mark.asyncio
async def test_collect_external_cancellation_waits_for_handlers(app):
    started = []
    exited = []

    def make_handler(name, delay):
        async def handler(**_):
            started.append(name)
            try:
                await asyncio.sleep(delay)
            finally:
                # Use a nested await to prove collect waits for the
                # handler to fully unwind, not just to be cancelled
                await asyncio.sleep(0.01)
                exited.append(name)

        return handler

    app.add_signal(make_handler("one", 10), "foo.bar.baz")
    app.add_signal(make_handler("two", 10), "foo.bar.baz")
    app.add_signal(make_handler("three", 10), "foo.bar.baz")

    app.signal_router.finalize()

    task = asyncio.create_task(app.collect("foo.bar.baz"))
    await asyncio.sleep(0.05)
    assert sorted(started) == ["one", "three", "two"]

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # By the time the cancellation propagates, every started handler
    # has fully exited
    assert sorted(exited) == ["one", "three", "two"]
    await asyncio.sleep(0)
    pending = [
        task
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
    ]
    assert pending == []


@pytest.mark.asyncio
async def test_collect_with_condition(app):
    @app.signal("foo.bar.baz", condition={"one": "two"})
    def conditional(**_):
        return "conditional"

    @app.signal("foo.bar.baz")
    def unconditional(**_):
        return "unconditional"

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz")
    assert results == ["unconditional"]

    results = await app.collect("foo.bar.baz", condition={"one": "two"})
    assert results == ["conditional"]


@pytest.mark.asyncio
async def test_collect_with_context_and_dynamic_event(app):
    @app.signal("foo.bar.<thing>")
    async def handler(thing, amount, **_):
        return f"{thing}:{amount}"

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz", context={"amount": 9})
    assert results == ["baz:9"]


@pytest.mark.asyncio
async def test_collect_nested_dispatch_does_not_corrupt_outer_state(app):
    inner_results = []

    @app.signal("inner.event.here")
    async def inner(**_):
        return "inner-result"

    @app.signal("foo.bar.baz")
    async def outer_one(**_):
        # A handler that dispatches (and collects) again from inside
        inner_results.append(await app.collect("inner.event.here"))
        await app.dispatch("inner.event.here")
        return "outer-one"

    @app.signal("foo.bar.baz")
    async def outer_two(**_):
        await asyncio.sleep(0.01)
        return "outer-two"

    app.signal_router.finalize()

    results = await app.collect("foo.bar.baz")
    assert results == ["outer-one", "outer-two"]
    assert inner_results == [["inner-result"]]

    # Two concurrent collects of the same event stay independent
    first, second = await asyncio.gather(
        app.collect("foo.bar.baz"),
        app.collect("foo.bar.baz"),
    )
    assert first == second == ["outer-one", "outer-two"]


@pytest.mark.asyncio
async def test_collect_not_found(app):
    app.signal_router.finalize()

    with pytest.raises(NotFound):
        await app.collect("foo.bar.baz")

    assert await app.collect("foo.bar.baz", fail_not_found=False) == []


@pytest.mark.asyncio
async def test_collect_triggers_event_waiters(app):
    @app.signal("foo.bar.baz")
    def sync_signal(**_):
        return "ok"

    app.signal_router.finalize()

    event_task = asyncio.create_task(app.event("foo.bar.baz"))
    await asyncio.sleep(0)
    results = await app.collect("foo.bar.baz")
    await asyncio.sleep(0)

    assert results == ["ok"]
    assert event_task.done()
    event_task.result()
