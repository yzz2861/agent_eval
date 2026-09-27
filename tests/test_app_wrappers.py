from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import partial
from typing import Any

import pytest
import trio

from hypercorn.app_wrappers import (
    _build_environ,
    BodyTooLargeError,
    InvalidPathError,
    WSGIInput,
    WSGIWrapper,
)
from hypercorn.typing import ASGIReceiveEvent, ASGISendEvent, ConnectionState, HTTPScope


def _make_scope() -> HTTPScope:
    return {
        "http_version": "1.1",
        "asgi": {},
        "method": "POST",
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


def _make_input(messages: list[ASGIReceiveEvent], max_body_size: int = 2**16) -> WSGIInput:
    queue = list(messages)

    async def receive() -> ASGIReceiveEvent:
        return queue.pop(0)

    def call_soon(func: Callable) -> Any:
        return asyncio.run(func())

    return WSGIInput(receive, call_soon, max_body_size)


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
    environ = _build_environ(scope, _make_input([]))
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
        _build_environ(scope, _make_input([]))


def test_wsgi_input_read_to_eof() -> None:
    wsgi_input = _make_input(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"def", "more_body": False},
        ]
    )
    assert wsgi_input.read() == b"abcdef"
    assert wsgi_input.read() == b""


def test_wsgi_input_read_size() -> None:
    wsgi_input = _make_input(
        [
            {"type": "http.request", "body": b"ab", "more_body": True},
            {"type": "http.request", "body": b"cdef", "more_body": False},
        ]
    )
    assert wsgi_input.read(3) == b"abc"
    assert wsgi_input.read(3) == b"def"
    assert wsgi_input.read(3) == b""


def test_wsgi_input_read_only_fetches_when_needed() -> None:
    messages: list[ASGIReceiveEvent] = [
        {"type": "http.request", "body": b"abcdef", "more_body": True},
        {"type": "http.request", "body": b"ghijkl", "more_body": False},
    ]
    wsgi_input = _make_input(messages)
    assert wsgi_input.read(2) == b"ab"
    # The second message is not requested until the buffer is drained
    assert messages[1:] == [{"type": "http.request", "body": b"ghijkl", "more_body": False}]
    assert wsgi_input.read() == b"cdefghijkl"


def test_wsgi_input_readline_split_newline() -> None:
    wsgi_input = _make_input(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"def\nghi", "more_body": False},
        ]
    )
    assert wsgi_input.readline() == b"abcdef\n"
    assert wsgi_input.readline() == b"ghi"
    assert wsgi_input.readline() == b""


def test_wsgi_input_readline_size() -> None:
    wsgi_input = _make_input(
        [{"type": "http.request", "body": b"abcdef\ngh", "more_body": False}]
    )
    assert wsgi_input.readline(3) == b"abc"
    assert wsgi_input.readline(10) == b"def\n"
    assert wsgi_input.readline() == b"gh"
    assert wsgi_input.readline() == b""


def test_wsgi_input_iteration() -> None:
    wsgi_input = _make_input(
        [
            {"type": "http.request", "body": b"one\ntwo\n", "more_body": True},
            {"type": "http.request", "body": b"three", "more_body": False},
        ]
    )
    assert list(wsgi_input) == [b"one\n", b"two\n", b"three"]


def test_wsgi_input_close() -> None:
    messages: list[ASGIReceiveEvent] = [
        {"type": "http.request", "body": b"abc", "more_body": True},
        {"type": "http.request", "body": b"def", "more_body": False},
    ]
    wsgi_input = _make_input(messages)
    assert wsgi_input.read(1) == b"a"
    wsgi_input.close()
    assert wsgi_input.closed
    assert wsgi_input.read() == b""
    assert wsgi_input.readline() == b""
    assert list(wsgi_input) == []
    # Closing stops any further requests for body data
    assert len(messages) == 2


def test_wsgi_input_disconnect_is_eof() -> None:
    wsgi_input = _make_input(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.disconnect"},
        ]
    )
    assert wsgi_input.read() == b"abc"
    assert wsgi_input.read() == b""


def test_wsgi_input_max_body_size() -> None:
    wsgi_input = _make_input(
        [{"type": "http.request", "body": b"abcde", "more_body": False}],
        max_body_size=4,
    )
    with pytest.raises(BodyTooLargeError):
        wsgi_input.read()


def reject_after_first_line(environ: dict, start_response: Callable) -> list[bytes]:
    line = environ["wsgi.input"].readline()
    headers = [("Content-Length", str(len(line)))]
    start_response("403 Forbidden", headers)
    return [line]


@pytest.mark.asyncio
async def test_wsgi_asyncio_early_rejection() -> None:
    app = WSGIWrapper(reject_after_first_line, 2**16)
    queue: asyncio.Queue = asyncio.Queue()
    # Only the first line of the body is sent, the rest never arrives
    await queue.put({"type": "http.request", "body": b"first line\n", "more_body": True})

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    event_loop = asyncio.get_running_loop()

    def _call_soon(func: Callable, *args: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(func(*args), event_loop)
        return future.result()

    await app(
        _make_scope(), queue.get, _send, partial(event_loop.run_in_executor, None), _call_soon
    )
    assert messages == [
        {
            "headers": [(b"content-length", b"11")],
            "status": 403,
            "type": "http.response.start",
        },
        {"body": b"first line\n", "type": "http.response.body", "more_body": True},
        {"body": b"", "type": "http.response.body", "more_body": False},
    ]


@pytest.mark.asyncio
async def test_wsgi_asyncio_disconnect_wakes_reader() -> None:
    app = WSGIWrapper(echo_body, 2**16)
    queue: asyncio.Queue = asyncio.Queue()
    await queue.put({"type": "http.request", "body": b"partial", "more_body": True})

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    event_loop = asyncio.get_running_loop()

    def _call_soon(func: Callable, *args: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(func(*args), event_loop)
        return future.result()

    task = event_loop.create_task(
        app(
            _make_scope(),
            queue.get,
            _send,
            partial(event_loop.run_in_executor, None),
            _call_soon,
        )
    )
    await asyncio.sleep(0.1)
    assert not task.done()  # The reader is blocked waiting for more body data
    await queue.put({"type": "http.disconnect"})
    await task
    assert messages == [
        {
            "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", b"7")],
            "status": 200,
            "type": "http.response.start",
        },
        {"body": b"partial", "type": "http.response.body", "more_body": True},
        {"body": b"", "type": "http.response.body", "more_body": False},
    ]


@pytest.mark.trio
async def test_wsgi_trio_early_rejection() -> None:
    app = WSGIWrapper(reject_after_first_line, 2**16)
    send_channel, receive_channel = trio.open_memory_channel[ASGIReceiveEvent](1)
    # Only the first line of the body is sent, the rest never arrives
    await send_channel.send({"type": "http.request", "body": b"first line\n", "more_body": True})

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    await app(
        _make_scope(), receive_channel.receive, _send, trio.to_thread.run_sync, trio.from_thread.run
    )
    assert messages == [
        {
            "headers": [(b"content-length", b"11")],
            "status": 403,
            "type": "http.response.start",
        },
        {"body": b"first line\n", "type": "http.response.body", "more_body": True},
        {"body": b"", "type": "http.response.body", "more_body": False},
    ]


@pytest.mark.trio
async def test_wsgi_trio_disconnect_wakes_reader() -> None:
    app = WSGIWrapper(echo_body, 2**16)
    send_channel, receive_channel = trio.open_memory_channel[ASGIReceiveEvent](1)
    await send_channel.send({"type": "http.request", "body": b"partial", "more_body": True})

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    async with trio.open_nursery() as nursery:
        nursery.start_soon(
            app,
            _make_scope(),
            receive_channel.receive,
            _send,
            trio.to_thread.run_sync,
            trio.from_thread.run,
        )
        await trio.testing.wait_all_tasks_blocked()
        await send_channel.send({"type": "http.disconnect"})
    assert messages == [
        {
            "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", b"7")],
            "status": 200,
            "type": "http.response.start",
        },
        {"body": b"partial", "type": "http.response.body", "more_body": True},
        {"body": b"", "type": "http.response.body", "more_body": False},
    ]
