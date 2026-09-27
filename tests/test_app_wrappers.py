from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import partial
from io import BytesIO
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
    environ = _build_environ(scope, BytesIO(b""))
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
        _build_environ(scope, BytesIO(b""))


def _make_input(messages: list, max_body_size: int = 2**16) -> WSGIInput:
    queue = list(messages)

    async def receive() -> ASGIReceiveEvent:
        return queue.pop(0)

    def call_soon(func: Callable, *args: Any) -> Any:
        return asyncio.run(func(*args))

    return WSGIInput(receive, call_soon, max_body_size)


def test_wsgi_input_read_to_eof() -> None:
    stream = _make_input(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"def", "more_body": False},
        ]
    )
    assert stream.read() == b"abcdef"
    assert stream.read() == b""


def test_wsgi_input_read_size() -> None:
    stream = _make_input(
        [
            {"type": "http.request", "body": b"ab", "more_body": True},
            {"type": "http.request", "body": b"cd", "more_body": False},
        ]
    )
    assert stream.read(3) == b"abc"
    assert stream.read(3) == b"d"
    assert stream.read(3) == b""


def test_wsgi_input_readline_split_newline() -> None:
    # The newline is split across two receive messages
    stream = _make_input(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"\ndef", "more_body": False},
        ]
    )
    assert stream.readline() == b"abc\n"
    assert stream.readline() == b"def"
    assert stream.readline() == b""


def test_wsgi_input_readline_size() -> None:
    stream = _make_input(
        [{"type": "http.request", "body": b"abc\ndef", "more_body": False}]
    )
    assert stream.readline(2) == b"ab"
    assert stream.readline() == b"c\n"


def test_wsgi_input_iteration() -> None:
    stream = _make_input(
        [{"type": "http.request", "body": b"a\nb\nc", "more_body": False}]
    )
    assert list(stream) == [b"a\n", b"b\n", b"c"]


def test_wsgi_input_disconnect_is_eof() -> None:
    stream = _make_input(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.disconnect"},
        ]
    )
    assert stream.read() == b"abc"
    assert stream.read() == b""


def test_wsgi_input_close() -> None:
    stream = _make_input(
        [{"type": "http.request", "body": b"abc", "more_body": True}]
    )
    stream.close()
    assert stream.closed
    assert stream.read() == b""
    assert stream.readline() == b""


def test_wsgi_input_max_body_size() -> None:
    stream = _make_input(
        [{"type": "http.request", "body": b"abcde", "more_body": False}],
        max_body_size=4,
    )
    with pytest.raises(BodyTooLargeError):
        stream.read()


def reject_after_first_line(environ: dict, start_response: Callable) -> list[bytes]:
    line = environ["wsgi.input"].readline()
    start_response("403 Forbidden", [("Content-Type", "text/plain")])
    return [b"rejected: " + line.rstrip()]


def _rejection_scope() -> HTTPScope:
    return {
        "http_version": "1.1",
        "asgi": {},
        "method": "POST",
        "headers": [],
        "path": "/",
        "root_path": "/",
        "query_string": b"",
        "raw_path": b"/",
        "scheme": "http",
        "type": "http",
        "client": ("localhost", 80),
        "server": None,
        "extensions": {},
        "state": ConnectionState({}),
    }


@pytest.mark.asyncio
async def test_wsgi_asyncio_early_rejection() -> None:
    # The app responds after reading only the first line, whilst the
    # remainder of the body is never sent (the upload is still in
    # progress).
    app = WSGIWrapper(reject_after_first_line, 2**16)
    queue: asyncio.Queue = asyncio.Queue()
    await queue.put({"type": "http.request", "body": b"bad\n", "more_body": True})

    receive_calls = 0

    async def _receive() -> ASGIReceiveEvent:
        nonlocal receive_calls
        receive_calls += 1
        return await queue.get()

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    event_loop = asyncio.get_running_loop()

    def _call_soon(func: Callable, *args: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(func(*args), event_loop)
        return future.result()

    await asyncio.wait_for(
        app(
            _rejection_scope(),
            _receive,
            _send,
            partial(event_loop.run_in_executor, None),
            _call_soon,
        ),
        5,
    )
    assert messages == [
        {
            "headers": [(b"content-type", b"text/plain")],
            "status": 403,
            "type": "http.response.start",
        },
        {"body": b"rejected: bad", "type": "http.response.body", "more_body": True},
        {"body": b"", "type": "http.response.body", "more_body": False},
    ]
    # Only the first chunk was pulled from the receive channel
    assert receive_calls == 1


@pytest.mark.trio
async def test_wsgi_trio_early_rejection() -> None:
    app = WSGIWrapper(reject_after_first_line, 2**16)
    send_channel, receive_channel = trio.open_memory_channel[ASGIReceiveEvent](1)
    await send_channel.send(
        {"type": "http.request", "body": b"bad\n", "more_body": True}  # type: ignore
    )

    messages = []

    async def _send(message: ASGISendEvent) -> None:
        messages.append(message)

    with trio.fail_after(5):
        await app(
            _rejection_scope(),
            receive_channel.receive,
            _send,
            trio.to_thread.run_sync,
            trio.from_thread.run,
        )
    assert messages[0]["status"] == 403  # type: ignore
    assert messages[1]["body"] == b"rejected: bad"  # type: ignore


@pytest.mark.asyncio
async def test_wsgi_response_error_closes_input() -> None:
    captured = {}

    def raising_app(environ: dict, start_response: Callable) -> Any:
        captured["input"] = environ["wsgi.input"]
        start_response("200 OK", [])
        yield b"chunk"
        raise ValueError("boom")

    app = WSGIWrapper(raising_app, 2**16)
    with pytest.raises(ValueError):
        await _run_app(app, _rejection_scope())
    assert captured["input"].closed
