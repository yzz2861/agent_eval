from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
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
    """Bridge the async receive channel to the sync WSGI app.

    Data is only pulled from the client (via the receive callable)
    when the application reads from the stream, allowing
    applications to respond without waiting for the full request
    body. Buffering is bounded as at most max_body_size bytes are
    received in total. All blocking takes place in the WSGI
    application's worker thread (via call_soon), never in the event
    loop.
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
        self._body_size = 0
        self._eof = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True
        self._buffer.clear()

    def _receive_more(self) -> None:
        if self._eof or self._closed:
            return
        message: ASGIReceiveEvent = self._call_soon(self._receive)
        if message["type"] == "http.disconnect":
            # The client has gone away, wake up as if at EOF rather
            # than wait forever for the next chunk.
            self._eof = True
            return
        body = message.get("body", b"")  # type: ignore
        self._body_size += len(body)
        if self._body_size > self._max_body_size:
            self._eof = True
            raise BodyTooLargeError()
        self._buffer.extend(body)
        if not message.get("more_body", False):  # type: ignore
            self._eof = True

    def read(self, size: int = -1) -> bytes:
        if self._closed:
            return b""
        if size is None or size < 0:
            while not self._eof:
                self._receive_more()
            data = bytes(self._buffer)
            self._buffer.clear()
            return data
        while len(self._buffer) < size and not self._eof:
            self._receive_more()
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def readline(self, size: int = -1) -> bytes:
        if self._closed:
            return b""
        while True:
            index = self._buffer.find(b"\n")
            if index != -1:
                end = index + 1
                if 0 <= size < end:
                    end = size
                break
            if 0 <= size <= len(self._buffer):
                end = size
                break
            if self._eof:
                end = len(self._buffer) if size < 0 else min(size, len(self._buffer))
                break
            self._receive_more()
        data = bytes(self._buffer[:end])
        del self._buffer[:end]
        return data

    def readlines(self, hint: int = -1) -> list[bytes]:
        lines = []
        total = 0
        while True:
            line = self.readline()
            if line == b"":
                break
            lines.append(line)
            total += len(line)
            if 0 < hint <= total:
                break
        return lines

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        line = self.readline()
        if line == b"":
            raise StopIteration
        return line


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
            try:
                await sync_spawn(self.run_app, environ, partial(call_soon, send))
            finally:
                # Ensure no further body data is pulled once the app
                # has returned (or errored).
                wsgi_input.close()
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    def run_app(self, environ: dict, send: Callable) -> None:
        headers: list[tuple[bytes, bytes]]
        response_started = False
        status_code: int | None = None

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
            try:
                first_chunk = True
                for output in response_body:
                    if first_chunk:
                        if not response_started:
                            raise RuntimeError("WSGI app did not call start_response")

                        send(
                            {
                                "type": "http.response.start",
                                "status": status_code,
                                "headers": headers,
                            }
                        )
                        first_chunk = False

                    send({"type": "http.response.body", "body": output, "more_body": True})
            finally:
                if hasattr(response_body, "close"):
                    response_body.close()
        except BodyTooLargeError:
            if response_started:
                raise
            send({"type": "http.response.start", "status": 400, "headers": []})


def _build_environ(scope: HTTPScope, wsgi_input: Any) -> dict:
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
