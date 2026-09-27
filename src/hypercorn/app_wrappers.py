from __future__ import annotations

import sys
from collections.abc import Callable
from functools import partial
from typing import Any

from .typing import (
    ASGIFramework,
    ASGIReceiveCallable,
    ASGIReceiveEvent,
    ASGISendCallable,
    HTTPScope,
    Scope,
    WSGIFramework,
)


class InvalidPathError(Exception):
    pass


class BodyTooLargeError(Exception):
    pass


class WSGIInput:
    """A synchronous file-like view over the ASGI receive channel.

    Data is only pulled from the receive channel when the WSGI app
    actually reads, so an app can inspect the start of a request body
    and reject it without waiting for the whole upload. At most one
    received message is buffered ahead of what the app has consumed.
    All the blocking happens in the WSGI worker thread (via
    call_soon), never in the event loop.
    """

    def __init__(
        self,
        receive: ASGIReceiveCallable,
        call_soon: Callable,
        max_body_size: int,
    ) -> None:
        self._receive = receive
        self._call_soon = call_soon
        self._max_body_size = max_body_size
        self._buffer = bytearray()
        self._received = 0
        self._more_body = True
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        # Stop pulling from the receive channel and drop anything buffered.
        self._closed = True
        self._buffer.clear()

    def read(self, size: int | None = -1) -> bytes:
        if self._closed:
            return b""
        if size is None or size < 0:
            while self._more_body:
                self._fetch()
            data = bytes(self._buffer)
            self._buffer.clear()
        else:
            while len(self._buffer) < size and self._more_body:
                self._fetch()
            data = bytes(self._buffer[:size])
            del self._buffer[:size]
        return data

    def readline(self, size: int | None = -1) -> bytes:
        if self._closed:
            return b""
        limit = size if size is not None and size >= 0 else None
        while True:
            if limit is None:
                index = self._buffer.find(b"\n")
            else:
                index = self._buffer.find(b"\n", 0, limit)
            if index != -1:
                end = index + 1
                break
            elif limit is not None and len(self._buffer) >= limit:
                end = limit
                break
            elif not self._more_body:
                end = len(self._buffer)
                break
            self._fetch()
        data = bytes(self._buffer[:end])
        del self._buffer[:end]
        return data

    def readlines(self, hint: int | None = -1) -> list[bytes]:
        lines = []
        total = 0
        for line in self:
            lines.append(line)
            total += len(line)
            if hint is not None and hint > 0 and total >= hint:
                break
        return lines

    def __iter__(self) -> WSGIInput:
        return self

    def __next__(self) -> bytes:
        line = self.readline()
        if line == b"":
            raise StopIteration
        return line

    def _fetch(self) -> None:
        # Block this (worker) thread until the event loop returns the
        # next message. A disconnect wakes the reader and is treated
        # as the end of the body.
        message: ASGIReceiveEvent = self._call_soon(self._receive)
        if message["type"] == "http.disconnect":
            self._more_body = False
            return
        body = message.get("body", b"")  # type: ignore
        self._received += len(body)
        self._more_body = message.get("more_body", False)  # type: ignore
        if self._received > self._max_body_size:
            self._more_body = False
            raise BodyTooLargeError()
        self._buffer.extend(body)


class ASGIWrapper:
    def __init__(self, app: ASGIFramework) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable,
        sync_spawn: Callable,
        call_soon: Callable,
    ) -> None:
        await self.app(scope, receive, send)


class WSGIWrapper:
    def __init__(self, app: WSGIFramework, max_body_size: int) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(
        self,
        scope: Scope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable,
        sync_spawn: Callable,
        call_soon: Callable,
    ) -> None:
        if scope["type"] == "http":
            await self.handle_http(scope, receive, send, sync_spawn, call_soon)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close"})  # type: ignore
        elif scope["type"] == "lifespan":
            return
        else:
            raise Exception(f"Unknown scope type, {scope['type']}")

    async def handle_http(
        self,
        scope: HTTPScope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable,
        sync_spawn: Callable,
        call_soon: Callable,
    ) -> None:
        wsgi_input = WSGIInput(receive, call_soon, self.max_body_size)
        try:
            environ = _build_environ(scope, wsgi_input)
        except InvalidPathError:
            await send({"type": "http.response.start", "status": 404, "headers": []})
        else:
            await sync_spawn(self.run_app, environ, partial(call_soon, send))
        finally:
            # Ensure no more body data is requested once the app is done.
            wsgi_input.close()
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    def run_app(self, environ: dict, send: Callable) -> None:
        headers: list[tuple[bytes, bytes]]
        response_started = False
        status_code: int | None = None
        response_body: Any = None

        def start_response(
            status: str,
            response_headers: list[tuple[str, str]],
            exc_info: Exception | None = None,
        ) -> None:
            nonlocal headers, response_started, status_code

            raw, _ = status.split(" ", 1)
            status_code = int(raw)
            headers = [
                (name.lower().encode("latin-1"), value.encode("latin-1"))
                for name, value in response_headers
            ]
            response_started = True

        try:
            response_body = self.app(environ, start_response)

            first_chunk = True
            for output in response_body:
                if first_chunk:
                    if not response_started:
                        raise RuntimeError("WSGI app did not call start_response")

                    send({"type": "http.response.start", "status": status_code, "headers": headers})
                    first_chunk = False

                send({"type": "http.response.body", "body": output, "more_body": True})
        except BodyTooLargeError:
            if response_started:
                raise
            send({"type": "http.response.start", "status": 400, "headers": []})
        finally:
            if response_body is not None and hasattr(response_body, "close"):
                response_body.close()


def _build_environ(scope: HTTPScope, wsgi_input: WSGIInput) -> dict:
    server = scope.get("server") or ("localhost", 80)
    path = scope["path"]
    script_name = scope.get("root_path", "")
    if path.startswith(script_name):
        path = path[len(script_name) :]
        path = path if path != "" else "/"
    else:
        raise InvalidPathError()

    environ = {
        "REQUEST_METHOD": scope["method"],
        "SCRIPT_NAME": script_name.encode("utf8").decode("latin1"),
        "PATH_INFO": path.encode("utf8").decode("latin1"),
        "QUERY_STRING": scope["query_string"].decode("ascii"),
        "SERVER_NAME": server[0],
        "SERVER_PORT": server[1],
        "SERVER_PROTOCOL": "HTTP/%s" % scope["http_version"],
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": scope.get("scheme", "http"),
        "wsgi.input": wsgi_input,
        "wsgi.errors": sys.stdout,
        "wsgi.multithread": True,
        "wsgi.multiprocess": True,
        "wsgi.run_once": False,
    }

    if scope.get("client") is not None:
        environ["REMOTE_ADDR"] = scope["client"][0]

    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin1")
        if name == "content-length":
            corrected_name = "CONTENT_LENGTH"
        elif name == "content-type":
            corrected_name = "CONTENT_TYPE"
        else:
            corrected_name = "HTTP_%s" % name.upper().replace("-", "_")
        # HTTPbis say only ASCII chars are allowed in headers, but we latin1 just in case
        value = raw_value.decode("latin1")
        if corrected_name in environ:
            value = environ[corrected_name] + "," + value  # type: ignore
        environ[corrected_name] = value
    return environ
