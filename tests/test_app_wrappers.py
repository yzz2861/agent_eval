from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from threading import Event
from typing import Any

import pytest
import trio

from hypercorn.app_wrappers import _build_environ, InvalidPathError, WSGIWrapper
from hypercorn.typing import ASGIReceiveEvent, ASGISendEvent, ConnectionState, HTTPScope


def echo_body(environ: dict, start_response: Callable) -> list[bytes]:
    status = "200 OK"
    output = environ["wsgi.input"].read()
    headers = [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(output))),
    ]
    start_response(status, headers)
    return [output]


@pytest.mark.trio
async def test_wsgi_trio() -> None:
    app = WSGIWrapper(echo_body, 2**16)
    scope: HTTPScope = {
        "http_version": "1.1",
        "asgi": {},
        "method": "GET",
        "headers": [],
        "path": "/",
        "root_path": "/",
        "query_string": b"a=b",
        "raw_path": b"/",
        "scheme": "http",
        "type": "http",
        "client": ("localhost", 80),
        "server": None,
        "extensions": {},
        "state": ConnectionState({}),
    }
    send_channel, receive_channel = trio.open_memory_channel[ASGIReceiveEvent](1)
    await send_channel.send({"type": "http.request"})  # type: ignore

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    await app(scope, receive_channel.receive, _send, trio.to_thread.run_sync, trio.from_thread.run)
    assert messages == [
        {
            "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", b"0")],
            "status": 200,
            "type": "http.response.start",
        },
        {"body": bytearray(b""), "type": "http.response.body", "more_body": True},
        {"body": bytearray(b""), "type": "http.response.body", "more_body": False},
    ]


async def _run_app(app: WSGIWrapper, scope: HTTPScope, body: bytes = b"") -> list[ASGISendEvent]:
    queue: asyncio.Queue = asyncio.Queue()
    await queue.put({"type": "http.request", "body": body})

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    event_loop = asyncio.get_running_loop()

    def _call_soon(func: Callable, *args: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(func(*args), event_loop)
        return future.result()

    await app(scope, queue.get, _send, partial(event_loop.run_in_executor, None), _call_soon)
    return messages


@pytest.mark.asyncio
async def test_wsgi_asyncio() -> None:
    app = WSGIWrapper(echo_body, 2**16)
    scope: HTTPScope = {
        "http_version": "1.1",
        "asgi": {},
        "method": "GET",
        "headers": [],
        "path": "/",
        "root_path": "/",
        "query_string": b"a=b",
        "raw_path": b"/",
        "scheme": "http",
        "type": "http",
        "client": ("localhost", 80),
        "server": None,
        "extensions": {},
        "state": ConnectionState({}),
    }
    messages = await _run_app(app, scope)
    assert messages == [
        {
            "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", b"0")],
            "status": 200,
            "type": "http.response.start",
        },
        {"body": bytearray(b""), "type": "http.response.body", "more_body": True},
        {"body": bytearray(b""), "type": "http.response.body", "more_body": False},
    ]


@pytest.mark.asyncio
async def test_max_body_size() -> None:
    app = WSGIWrapper(echo_body, 4)
    scope: HTTPScope = {
        "http_version": "1.1",
        "asgi": {},
        "method": "GET",
        "headers": [],
        "path": "/",
        "root_path": "/",
        "query_string": b"a=b",
        "raw_path": b"/",
        "scheme": "http",
        "type": "http",
        "client": ("localhost", 80),
        "server": None,
        "extensions": {},
        "state": ConnectionState({}),
    }
    messages = await _run_app(app, scope, b"abcde")
    assert messages == [
        {"headers": [], "status": 400, "type": "http.response.start"},
        {"body": bytearray(b""), "type": "http.response.body", "more_body": False},
    ]


def no_start_response(environ: dict, start_response: Callable) -> list[bytes]:
    return [b"result"]


@dataclass
class BlockingResponse:
    started: Event
    finish_iteration: Event = field(default_factory=Event)
    iteration_finished: Event = field(default_factory=Event)
    allow_iteration_exit: Event = field(default_factory=Event)
    close_started: Event = field(default_factory=Event)
    allow_close: Event = field(default_factory=Event)
    closed: Event = field(default_factory=Event)

    def __iter__(self) -> BlockingResponse:
        return self

    def __next__(self) -> bytes:
        self.started.set()
        self.finish_iteration.wait()
        if not self.iteration_finished.is_set():
            self.iteration_finished.set()
            return b"data"
        self.allow_iteration_exit.wait()
        raise StopIteration

    def close(self) -> None:
        self.close_started.set()
        self.allow_close.wait()
        self.closed.set()


def blocking_app(
    response: BlockingResponse,
) -> Callable[[dict, Callable], BlockingResponse]:
    def app(environ: dict, start_response: Callable) -> BlockingResponse:
        start_response("200 OK", [])
        return response

    return app


async def _invoke_wsgi(
    app: WSGIWrapper,
    scope: HTTPScope,
    backend: str,
) -> list[ASGISendEvent]:
    messages: list[ASGISendEvent] = []

    async def receive() -> ASGIReceiveEvent:
        return {"type": "http.request"}

    async def send(message: ASGISendEvent) -> None:
        messages.append(message)

    if backend == "asyncio":
        loop = asyncio.get_running_loop()

        def call_soon(func: Callable, *args: Any) -> Any:
            future = asyncio.run_coroutine_threadsafe(func(*args), loop)
            return future.result()

        await app(
            scope,
            receive,
            send,
            partial(loop.run_in_executor, None),
            call_soon,
        )
    else:
        await app(scope, receive, send, trio.to_thread.run_sync, trio.from_thread.run)
    return messages


async def _start_call(
    app: WSGIWrapper,
    scope: HTTPScope,
    backend: str,
    nursery: Any = None,
) -> Any:
    coroutine = _invoke_wsgi(app, scope, backend)
    if backend == "asyncio":
        return asyncio.ensure_future(coroutine)

    class TrioCall:
        def __init__(self) -> None:
            self.done = trio.Event()
            self.cancel_scope: trio.CancelScope | None = None

        async def run(self) -> None:
            try:
                with trio.CancelScope() as cancel_scope:
                    self.cancel_scope = cancel_scope
                    await coroutine
            except trio.Cancelled:
                pass
            self.done.set()

        def cancel(self) -> None:
            assert self.cancel_scope is not None
            self.cancel_scope.cancel()

        async def wait(self) -> None:
            await self.done.wait()

    handle = TrioCall()
    nursery.start_soon(handle.run)
    return handle


async def _wait_until(event: Event, backend: str) -> None:
    while not event.is_set():
        if backend == "asyncio":
            await asyncio.sleep(0.001)
        else:
            await trio.sleep(0.001)


async def _wait_call(handle: Any, backend: str) -> list[ASGISendEvent] | None:
    if backend == "asyncio":
        try:
            return await handle
        except asyncio.CancelledError:
            return None
    await handle.wait()
    return None


async def _cancel_call(handle: Any, backend: str) -> None:
    handle.cancel()
    if backend == "asyncio":
        await asyncio.sleep(0)
    else:
        await trio.lowlevel.checkpoint()


async def _wait_for_waiters(app: WSGIWrapper, count: int, backend: str) -> None:
    if backend == "asyncio":
        await asyncio.sleep(0)
    else:
        await trio.lowlevel.checkpoint()
    while True:
        if backend == "asyncio":
            waiters = app.concurrency._asyncio_waiters
            await asyncio.sleep(0)
        else:
            waiters = len(app.concurrency._trio_waiter_queue)
            await trio.lowlevel.checkpoint()
        if waiters == count:
            return


def sequence_app(
    responses: tuple[BlockingResponse, ...],
) -> Callable[[dict, Callable], BlockingResponse]:
    response_iter = iter(responses)

    def app(environ: dict, start_response: Callable) -> BlockingResponse:
        start_response("200 OK", [])
        return next(response_iter)

    return app


def finish_response(response: BlockingResponse) -> None:
    response.finish_iteration.set()
    response.allow_iteration_exit.set()
    response.allow_close.set()


async def _assert_wsgi_capacity(
    scope: HTTPScope,
    backend: str,
    nursery: Any = None,
) -> None:
    first = BlockingResponse(Event())
    second = BlockingResponse(Event())
    third = BlockingResponse(Event())
    app = WSGIWrapper(sequence_app((first, second, third)), 2**16, 1, 2)
    first_handle = await _start_call(app, scope, backend, nursery)
    await _wait_until(first.started, backend)

    second_handle = await _start_call(app, scope, backend, nursery)
    third_handle = await _start_call(app, scope, backend, nursery)
    await _wait_for_waiters(app, 2, backend)
    assert not second.started.is_set()
    assert not third.started.is_set()

    busy_messages = await _invoke_wsgi(app, scope, backend)
    assert busy_messages[0]["status"] == 503

    finish_response(first)
    await _wait_call(first_handle, backend)
    await _wait_until(second.started, backend)
    assert not third.started.is_set()

    finish_response(second)
    await _wait_call(second_handle, backend)
    await _wait_until(third.started, backend)

    finish_response(third)
    await _wait_call(third_handle, backend)


@pytest.mark.asyncio
async def test_wsgi_asyncio_capacity(http_scope: HTTPScope) -> None:
    await _assert_wsgi_capacity(http_scope, "asyncio")


@pytest.mark.trio
async def test_wsgi_trio_capacity(http_scope: HTTPScope) -> None:
    async with trio.open_nursery() as nursery:
        await _assert_wsgi_capacity(http_scope, "trio", nursery)


async def _assert_queued_cancel_removes_request(
    scope: HTTPScope,
    backend: str,
    nursery: Any = None,
) -> None:
    active = BlockingResponse(Event())
    app = WSGIWrapper(blocking_app(active), 2**16, 1, 1)
    active_handle = await _start_call(app, scope, backend, nursery)
    await _wait_until(active.started, backend)

    queued = BlockingResponse(Event())
    queued_handle = await _start_call(
        app,
        scope,
        backend,
        nursery,
    )
    await _wait_for_waiters(app, 1, backend)
    assert not queued.started.is_set()
    await _cancel_call(queued_handle, backend)
    await _wait_call(queued_handle, backend)
    await _wait_for_waiters(app, 0, backend)

    finish_response(active)
    await _wait_call(active_handle, backend)


@pytest.mark.asyncio
async def test_wsgi_asyncio_queued_cancel(http_scope: HTTPScope) -> None:
    await _assert_queued_cancel_removes_request(http_scope, "asyncio")


@pytest.mark.trio
async def test_wsgi_trio_queued_cancel(http_scope: HTTPScope) -> None:
    async with trio.open_nursery() as nursery:
        await _assert_queued_cancel_removes_request(http_scope, "trio", nursery)


async def _assert_queue_timeout(
    scope: HTTPScope,
    backend: str,
    nursery: Any = None,
) -> None:
    active = BlockingResponse(Event())
    app = WSGIWrapper(blocking_app(active), 2**16, 1, 1, 0.001)
    active_handle = await _start_call(app, scope, backend, nursery)
    await _wait_until(active.started, backend)

    messages = await _invoke_wsgi(app, scope, backend)
    assert messages[0]["status"] == 503

    finish_response(active)
    await _wait_call(active_handle, backend)


@pytest.mark.asyncio
async def test_wsgi_asyncio_queue_timeout(http_scope: HTTPScope) -> None:
    await _assert_queue_timeout(http_scope, "asyncio")


@pytest.mark.trio
async def test_wsgi_trio_queue_timeout(http_scope: HTTPScope) -> None:
    async with trio.open_nursery() as nursery:
        await _assert_queue_timeout(http_scope, "trio", nursery)


async def _assert_active_cancel_waits_for_close(
    scope: HTTPScope,
    backend: str,
    nursery: Any = None,
) -> None:
    response = BlockingResponse(Event())
    app = WSGIWrapper(blocking_app(response), 2**16, 1, 0)
    handle = await _start_call(app, scope, backend, nursery)
    await _wait_until(response.started, backend)

    response.finish_iteration.set()
    await _wait_until(response.iteration_finished, backend)
    response.allow_iteration_exit.set()
    await _wait_until(response.close_started, backend)
    await _cancel_call(handle, backend)

    busy_messages = await _invoke_wsgi(app, scope, backend)
    assert busy_messages[0]["status"] == 503

    next_response = BlockingResponse(Event())
    next_response.finish_iteration.set()
    next_response.allow_iteration_exit.set()
    next_response.allow_close.set()
    app.app = blocking_app(next_response)

    response.allow_close.set()
    await _wait_until(response.closed, backend)
    await _wait_call(handle, backend)
    messages = await _invoke_wsgi(app, scope, backend)
    assert messages[0]["status"] == 200


@pytest.mark.asyncio
async def test_wsgi_asyncio_active_cancel(http_scope: HTTPScope) -> None:
    await _assert_active_cancel_waits_for_close(http_scope, "asyncio")


@pytest.mark.trio
async def test_wsgi_trio_active_cancel(http_scope: HTTPScope) -> None:
    async with trio.open_nursery() as nursery:
        await _assert_active_cancel_waits_for_close(http_scope, "trio", nursery)


@pytest.mark.asyncio
async def test_no_start_response() -> None:
    app = WSGIWrapper(no_start_response, 2**16)
    scope: HTTPScope = {
        "http_version": "1.1",
        "asgi": {},
        "method": "GET",
        "headers": [],
        "path": "/",
        "root_path": "/",
        "query_string": b"a=b",
        "raw_path": b"/",
        "scheme": "http",
        "type": "http",
        "client": ("localhost", 80),
        "server": None,
        "extensions": {},
        "state": ConnectionState({}),
    }
    with pytest.raises(RuntimeError):
        await _run_app(app, scope)


def test_build_environ_encoding() -> None:
    scope: HTTPScope = {
        "http_version": "1.0",
        "asgi": {},
        "method": "GET",
        "headers": [],
        "path": "/中/文",
        "root_path": "/中",
        "query_string": b"bar=baz",
        "raw_path": "/中/文".encode(),
        "scheme": "http",
        "type": "http",
        "client": ("localhost", 80),
        "server": None,
        "extensions": {},
        "state": ConnectionState({}),
    }
    environ = _build_environ(scope, b"")
    assert environ["SCRIPT_NAME"] == "/中".encode().decode("latin-1")
    assert environ["PATH_INFO"] == "/文".encode().decode("latin-1")


def test_build_environ_root_path() -> None:
    scope: HTTPScope = {
        "http_version": "1.0",
        "asgi": {},
        "method": "GET",
        "headers": [],
        "path": "/中文",
        "root_path": "/中国",
        "query_string": b"bar=baz",
        "raw_path": "/中文".encode(),
        "scheme": "http",
        "type": "http",
        "client": ("localhost", 80),
        "server": None,
        "extensions": {},
        "state": ConnectionState({}),
    }
    with pytest.raises(InvalidPathError):
        _build_environ(scope, b"")
