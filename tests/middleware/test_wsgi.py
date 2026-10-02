from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

import pytest
import trio

from hypercorn.middleware import AsyncioWSGIMiddleware, TrioWSGIMiddleware
from hypercorn.middleware.dispatcher import AsyncioDispatcherMiddleware, TrioDispatcherMiddleware
from hypercorn.typing import HTTPScope

BUSY_BODY = b"Service busy, please retry later"


class ControlledWSGIApp:
    """WSGI app whose calls block on threading events, recording order."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []
        self._entered: dict[str, threading.Event] = {}
        self._release: dict[str, threading.Event] = {}

    def control(self, name: str) -> None:
        self._entered[name] = threading.Event()
        self._release[name] = threading.Event()

    def entered(self, name: str) -> threading.Event:
        return self._entered[name]

    def release(self, name: str) -> None:
        self._release[name].set()

    def __call__(self, environ: dict, start_response: Callable) -> list[bytes]:
        name = environ["PATH_INFO"].strip("/")
        self.events.append((name, "start"))
        if name in self._entered:
            self._entered[name].set()
            assert self._release[name].wait(10)
        self.events.append((name, "end"))
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]


class SendCollector:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def __call__(self, message: dict) -> None:
        self.messages.append(message)

    @property
    def status(self) -> int:
        return self.messages[0]["status"]


async def receive() -> dict:
    return {"type": "http.request", "body": b"", "more_body": False}


def scope_with_path(http_scope: HTTPScope, path: str) -> HTTPScope:
    return {**http_scope, "path": path}


async def asyncio_wait_event(event: threading.Event) -> None:
    assert await asyncio.to_thread(event.wait, 10)


async def asyncio_wait_until(predicate: Callable[[], bool]) -> None:
    for _ in range(1000):
        if predicate():
            return
        await asyncio.sleep(0.001)
    raise AssertionError("condition was not met")


async def trio_wait_event(event: threading.Event) -> None:
    assert await trio.to_thread.run_sync(event.wait, 10)


async def trio_wait_until(predicate: Callable[[], bool]) -> None:
    for _ in range(1000):
        if predicate():
            return
        await trio.sleep(0.001)
    raise AssertionError("condition was not met")


@pytest.mark.asyncio
async def test_asyncio_queue_full_returns_busy(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    app.control("b")
    middleware = AsyncioWSGIMiddleware(app, max_concurrency=1, max_queue_size=1)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    task_a = asyncio.create_task(middleware(scope_with_path(http_scope, "/a"), receive, send_a))
    await asyncio_wait_event(app.entered("a"))

    task_b = asyncio.create_task(middleware(scope_with_path(http_scope, "/b"), receive, send_b))
    await asyncio_wait_until(lambda: len(middleware._limiter._queue) == 1)

    await middleware(scope_with_path(http_scope, "/c"), receive, send_c)
    assert send_c.status == 503
    assert send_c.messages[1]["body"] == BUSY_BODY

    app.release("a")
    await asyncio_wait_event(app.entered("b"))
    app.release("b")
    await asyncio.gather(task_a, task_b)

    assert send_a.status == 200
    assert send_b.status == 200
    assert app.events == [("a", "start"), ("a", "end"), ("b", "start"), ("b", "end")]


@pytest.mark.asyncio
async def test_asyncio_queued_request_cancellation(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    app.control("c")
    middleware = AsyncioWSGIMiddleware(app, max_concurrency=1, max_queue_size=1)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    task_a = asyncio.create_task(middleware(scope_with_path(http_scope, "/a"), receive, send_a))
    await asyncio_wait_event(app.entered("a"))

    task_b = asyncio.create_task(middleware(scope_with_path(http_scope, "/b"), receive, send_b))
    await asyncio_wait_until(lambda: len(middleware._limiter._queue) == 1)

    task_b.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task_b
    assert len(middleware._limiter._queue) == 0

    task_c = asyncio.create_task(middleware(scope_with_path(http_scope, "/c"), receive, send_c))
    await asyncio_wait_until(lambda: len(middleware._limiter._queue) == 1)

    app.release("a")
    await asyncio_wait_event(app.entered("c"))
    app.release("c")
    await asyncio.gather(task_a, task_c)

    assert send_a.status == 200
    assert send_c.status == 200
    assert send_b.messages == []
    assert app.events == [("a", "start"), ("a", "end"), ("c", "start"), ("c", "end")]


@pytest.mark.trio
async def test_trio_executing_call_holds_slot_until_exit(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    middleware = TrioWSGIMiddleware(app, max_concurrency=1, max_queue_size=0)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()
    cancel_a = trio.CancelScope()
    done_a = trio.Event()

    async def run_a() -> None:
        with cancel_a:
            await middleware(scope_with_path(http_scope, "/a"), receive, send_a)
        done_a.set()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(run_a)
        await trio_wait_event(app.entered("a"))

        cancel_a.cancel()
        await done_a.wait()

        # The WSGI callable is still blocked, so the slot is still held.
        await middleware(scope_with_path(http_scope, "/b"), receive, send_b)
        assert send_b.status == 503

        app.release("a")
        await trio_wait_until(lambda: ("a", "end") in app.events)

        await middleware(scope_with_path(http_scope, "/c"), receive, send_c)
        assert send_c.status == 200


@pytest.mark.trio
async def test_trio_queue_wait_timeout_returns_busy(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    middleware = TrioWSGIMiddleware(app, max_concurrency=1, max_queue_size=1, queue_timeout=0.05)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(middleware, scope_with_path(http_scope, "/a"), receive, send_a)
        await trio_wait_event(app.entered("a"))

        await middleware(scope_with_path(http_scope, "/b"), receive, send_b)
        assert send_b.status == 503
        assert send_b.messages[1]["body"] == BUSY_BODY
        assert len(middleware._limiter._queue) == 0

        app.release("a")

    assert send_a.status == 200

    await middleware(scope_with_path(http_scope, "/c"), receive, send_c)
    assert send_c.status == 200


@pytest.mark.trio
async def test_trio_slot_held_until_response_iterator_closed(http_scope: HTTPScope) -> None:
    events: list[str] = []
    iterating = threading.Event()
    finish_iteration = threading.Event()

    class Body:
        def __init__(self) -> None:
            self.done = False

        def __iter__(self) -> "Body":
            return self

        def __next__(self) -> bytes:
            if self.done:
                raise StopIteration
            events.append("iterate")
            iterating.set()
            assert finish_iteration.wait(10)
            self.done = True
            return b"chunk"

        def close(self) -> None:
            events.append("close")

    def wsgi_app(environ: dict, start_response: Callable) -> Body:
        events.append("start")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return Body()

    middleware = TrioWSGIMiddleware(wsgi_app, max_concurrency=1, max_queue_size=0)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(middleware, http_scope, receive, send_a)
        await trio_wait_event(iterating)

        # The response iterator is mid-consumption, so the slot is still held.
        await middleware(http_scope, receive, send_b)
        assert send_b.status == 503

        finish_iteration.set()

    assert send_a.status == 200

    await middleware(http_scope, receive, send_c)
    assert send_c.status == 200
    assert events == ["start", "iterate", "close", "start", "iterate", "close"]


@pytest.mark.trio
async def test_trio_asgi_requests_bypass_capacity(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("")
    entered = app.entered("")

    async def asgi_app(scope: dict, receive: Callable, send: Callable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"asgi"})

    dispatcher = TrioDispatcherMiddleware(
        {
            "/wsgi": TrioWSGIMiddleware(app, max_concurrency=1, max_queue_size=0),
            "/asgi": asgi_app,
        }
    )
    send_wsgi, send_asgi, send_busy = SendCollector(), SendCollector(), SendCollector()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(dispatcher, scope_with_path(http_scope, "/wsgi"), receive, send_wsgi)
        await trio_wait_event(entered)

        # Pure ASGI requests are unaffected by the WSGI capacity limits.
        await dispatcher(scope_with_path(http_scope, "/asgi"), receive, send_asgi)
        assert send_asgi.status == 200

        await dispatcher(scope_with_path(http_scope, "/wsgi"), receive, send_busy)
        assert send_busy.status == 503

        app.release("")

    assert send_wsgi.status == 200


@pytest.mark.asyncio
async def test_asyncio_executing_call_holds_slot_until_exit(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    middleware = AsyncioWSGIMiddleware(app, max_concurrency=1, max_queue_size=0)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    task_a = asyncio.create_task(middleware(scope_with_path(http_scope, "/a"), receive, send_a))
    await asyncio_wait_event(app.entered("a"))

    task_a.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task_a

    # The WSGI callable is still blocked, so the slot is still held.
    await middleware(scope_with_path(http_scope, "/b"), receive, send_b)
    assert send_b.status == 503

    app.release("a")
    await asyncio_wait_until(lambda: ("a", "end") in app.events)

    await middleware(scope_with_path(http_scope, "/c"), receive, send_c)
    assert send_c.status == 200


@pytest.mark.asyncio
async def test_asyncio_slot_held_until_response_iterator_closed(
    http_scope: HTTPScope,
) -> None:
    events: list[str] = []
    iterating = threading.Event()
    finish_iteration = threading.Event()

    class Body:
        def __init__(self) -> None:
            self.done = False

        def __iter__(self) -> "Body":
            return self

        def __next__(self) -> bytes:
            if self.done:
                raise StopIteration
            events.append("iterate")
            iterating.set()
            assert finish_iteration.wait(10)
            self.done = True
            return b"chunk"

        def close(self) -> None:
            events.append("close")

    def wsgi_app(environ: dict, start_response: Callable) -> Body:
        events.append("start")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return Body()

    middleware = AsyncioWSGIMiddleware(wsgi_app, max_concurrency=1, max_queue_size=0)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    task_a = asyncio.create_task(middleware(http_scope, receive, send_a))
    await asyncio_wait_event(iterating)

    # The response iterator is mid-consumption, so the slot is still held.
    await middleware(http_scope, receive, send_b)
    assert send_b.status == 503

    finish_iteration.set()
    await task_a
    assert send_a.status == 200

    await middleware(http_scope, receive, send_c)
    assert send_c.status == 200
    assert events == ["start", "iterate", "close", "start", "iterate", "close"]


@pytest.mark.asyncio
async def test_asyncio_asgi_requests_bypass_capacity(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("")
    entered = app.entered("")

    async def asgi_app(scope: dict, receive: Callable, send: Callable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"asgi"})

    dispatcher = AsyncioDispatcherMiddleware(
        {
            "/wsgi": AsyncioWSGIMiddleware(app, max_concurrency=1, max_queue_size=0),
            "/asgi": asgi_app,
        }
    )
    send_wsgi, send_asgi, send_busy = SendCollector(), SendCollector(), SendCollector()

    task = asyncio.create_task(dispatcher(scope_with_path(http_scope, "/wsgi"), receive, send_wsgi))
    await asyncio_wait_event(entered)

    # Pure ASGI requests are unaffected by the WSGI capacity limits.
    await dispatcher(scope_with_path(http_scope, "/asgi"), receive, send_asgi)
    assert send_asgi.status == 200

    await dispatcher(scope_with_path(http_scope, "/wsgi"), receive, send_busy)
    assert send_busy.status == 503

    app.release("")
    await task
    assert send_wsgi.status == 200


@pytest.mark.trio
async def test_trio_queue_full_returns_busy(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    app.control("b")
    middleware = TrioWSGIMiddleware(app, max_concurrency=1, max_queue_size=1)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(middleware, scope_with_path(http_scope, "/a"), receive, send_a)
        await trio_wait_event(app.entered("a"))

        nursery.start_soon(middleware, scope_with_path(http_scope, "/b"), receive, send_b)
        await trio_wait_until(lambda: len(middleware._limiter._queue) == 1)

        await middleware(scope_with_path(http_scope, "/c"), receive, send_c)
        assert send_c.status == 503
        assert send_c.messages[1]["body"] == BUSY_BODY

        app.release("a")
        await trio_wait_event(app.entered("b"))
        app.release("b")

    assert send_a.status == 200
    assert send_b.status == 200
    assert app.events == [("a", "start"), ("a", "end"), ("b", "start"), ("b", "end")]


@pytest.mark.asyncio
async def test_asyncio_queue_wait_timeout_returns_busy(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    middleware = AsyncioWSGIMiddleware(app, max_concurrency=1, max_queue_size=1, queue_timeout=0.05)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()

    task_a = asyncio.create_task(middleware(scope_with_path(http_scope, "/a"), receive, send_a))
    await asyncio_wait_event(app.entered("a"))

    await middleware(scope_with_path(http_scope, "/b"), receive, send_b)
    assert send_b.status == 503
    assert send_b.messages[1]["body"] == BUSY_BODY
    assert len(middleware._limiter._queue) == 0

    app.release("a")
    await task_a
    assert send_a.status == 200

    await middleware(scope_with_path(http_scope, "/c"), receive, send_c)
    assert send_c.status == 200


@pytest.mark.trio
async def test_trio_queued_request_cancellation(http_scope: HTTPScope) -> None:
    app = ControlledWSGIApp()
    app.control("a")
    app.control("c")
    middleware = TrioWSGIMiddleware(app, max_concurrency=1, max_queue_size=1)
    send_a, send_b, send_c = SendCollector(), SendCollector(), SendCollector()
    cancel_b = trio.CancelScope()
    done_b = trio.Event()

    async def run_b() -> None:
        with cancel_b:
            await middleware(scope_with_path(http_scope, "/b"), receive, send_b)
        done_b.set()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(middleware, scope_with_path(http_scope, "/a"), receive, send_a)
        await trio_wait_event(app.entered("a"))

        nursery.start_soon(run_b)
        await trio_wait_until(lambda: len(middleware._limiter._queue) == 1)

        cancel_b.cancel()
        await done_b.wait()
        assert len(middleware._limiter._queue) == 0

        nursery.start_soon(middleware, scope_with_path(http_scope, "/c"), receive, send_c)
        await trio_wait_until(lambda: len(middleware._limiter._queue) == 1)

        app.release("a")
        await trio_wait_event(app.entered("c"))
        app.release("c")

    assert send_a.status == 200
    assert send_c.status == 200
    assert send_b.messages == []
    assert app.events == [("a", "start"), ("a", "end"), ("c", "start"), ("c", "end")]
