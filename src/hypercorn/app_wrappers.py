from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from collections import deque
from functools import partial
from io import BytesIO
from typing import TYPE_CHECKING

from .typing import (
    ASGIFramework,
    ASGIReceiveCallable,
    ASGISendCallable,
    HTTPScope,
    Scope,
    WSGIFramework,
)

if TYPE_CHECKING:
    import trio


class InvalidPathError(Exception):
    pass


class WSGIServerBusyError(Exception):
    pass


class WSGIConcurrency:
    def __init__(
        self,
        max_concurrency: int | None,
        max_queue_size: int | None,
        queue_timeout: float | None,
    ) -> None:
        self.max_concurrency = max_concurrency
        self.max_queue_size = max_queue_size
        self.queue_timeout = queue_timeout

        self._asyncio_value: int | None = None
        self._asyncio_waiter_queue: deque[asyncio.Future[bool]] | None = None
        self._asyncio_lock: asyncio.Lock | None = None
        self._asyncio_waiters = 0

        self._trio_value: int | None = None
        self._trio_waiter_queue: deque[trio.Event] | None = None
        self._trio_lock: trio.Lock | None = None
        self._trio_thread_limit: trio.CapacityLimiter | None = None

    async def run(self, sync_spawn: Callable, func: Callable, *args: object) -> None:
        if self.max_concurrency is None:
            await sync_spawn(func, *args)
            return

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            await self._run_trio(func, *args)
        else:
            await self._run_asyncio(sync_spawn, func, *args)

    async def _run_asyncio(self, sync_spawn: Callable, func: Callable, *args: object) -> None:
        if self._asyncio_value is None:
            self._asyncio_value = self.max_concurrency
            self._asyncio_waiter_queue = deque()
            self._asyncio_lock = asyncio.Lock()
        assert self._asyncio_value is not None
        assert self._asyncio_waiter_queue is not None
        assert self._asyncio_lock is not None

        await self._acquire_asyncio()
        task = asyncio.ensure_future(sync_spawn(func, *args))
        loop = asyncio.get_running_loop()
        released = loop.create_future()

        def release_completed(_: asyncio.Future[object]) -> None:
            self._release_asyncio_locked()
            released.set_result(True)

        task.add_done_callback(release_completed)
        waiter = asyncio.ensure_future(released)
        try:
            await asyncio.shield(waiter)
            task.result()
        except BaseException:
            if not waiter.done():
                await asyncio.shield(waiter)
            raise

    async def _acquire_asyncio(self) -> None:
        assert self._asyncio_lock is not None
        assert self._asyncio_waiter_queue is not None
        assert self._asyncio_value is not None
        async with self._asyncio_lock:
            if self._asyncio_waiters == 0 and self._asyncio_value > 0:
                self._asyncio_value -= 1
                return

            if self.max_queue_size is not None and self._asyncio_waiters >= self.max_queue_size:
                raise WSGIServerBusyError()
            self._asyncio_waiters += 1
            waiter = asyncio.get_running_loop().create_future()
            self._asyncio_waiter_queue.append(waiter)

        try:
            await self._wait_asyncio(waiter)
        except (asyncio.TimeoutError, TimeoutError) as error:
            async with self._asyncio_lock:
                self._asyncio_waiters -= 1
            raise WSGIServerBusyError() from error
        except BaseException:
            async with self._asyncio_lock:
                self._asyncio_waiters -= 1
            raise
        else:
            async with self._asyncio_lock:
                self._asyncio_waiters -= 1

    async def _wait_asyncio(self, waiter: asyncio.Future[bool]) -> None:
        try:
            if self.queue_timeout is None:
                await waiter
            else:
                await asyncio.wait_for(asyncio.shield(waiter), self.queue_timeout)
        except BaseException:
            async with self._asyncio_lock:
                if waiter.done() and not waiter.cancelled():
                    self._release_asyncio_locked()
                else:
                    self._asyncio_waiter_queue.remove(waiter)
            raise

    def _release_asyncio_locked(self) -> None:
        assert self._asyncio_waiter_queue is not None
        assert self._asyncio_value is not None
        while self._asyncio_waiter_queue:
            waiter = self._asyncio_waiter_queue.popleft()
            if waiter.done():
                continue
            waiter.set_result(True)
            return
        self._asyncio_value += 1

    async def _run_trio(self, func: Callable, *args: object) -> None:
        import trio

        if self._trio_value is None:
            self._trio_value = self.max_concurrency
            self._trio_waiter_queue = deque()
            self._trio_lock = trio.Lock()
            self._trio_thread_limit = trio.CapacityLimiter(self.max_concurrency)
        assert self._trio_thread_limit is not None

        await self._acquire_trio()
        try:
            await trio.to_thread.run_sync(func, *args, limiter=self._trio_thread_limit)
        finally:
            with trio.CancelScope(shield=True):
                await self._release_trio()

    async def _acquire_trio(self) -> None:
        import trio

        assert self._trio_waiter_queue is not None
        assert self._trio_value is not None

        async with self._trio_lock:
            if not self._trio_waiter_queue and self._trio_value > 0:
                self._trio_value -= 1
                return

            if (
                self.max_queue_size is not None
                and len(self._trio_waiter_queue) >= self.max_queue_size
            ):
                raise WSGIServerBusyError()
            waiter = trio.Event()
            self._trio_waiter_queue.append(waiter)

        try:
            if self.queue_timeout is None:
                await waiter.wait()
            else:
                with trio.fail_after(self.queue_timeout):
                    await waiter.wait()
        except trio.TooSlowError as error:
            self._cancel_trio_waiter(waiter)
            raise WSGIServerBusyError() from error
        except BaseException:
            self._cancel_trio_waiter(waiter)
            raise

    def _cancel_trio_waiter(self, waiter: trio.Event) -> None:
        if waiter.statistics().tasks_waiting:
            self._release_trio_locked()
        else:
            self._trio_waiter_queue.remove(waiter)

    def _release_trio_locked(self) -> None:
        assert self._trio_waiter_queue is not None
        assert self._trio_value is not None
        while self._trio_waiter_queue:
            waiter = self._trio_waiter_queue.popleft()
            if not waiter.is_set():
                waiter.set()
                return
        self._trio_value += 1

    async def _release_trio(self) -> None:
        async with self._trio_lock:
            self._release_trio_locked()


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
    def __init__(
        self,
        app: WSGIFramework,
        max_body_size: int,
        max_concurrency: int | None = None,
        max_queue_size: int | None = None,
        queue_timeout: float | None = None,
        wsgi_max_concurrency: int | None = None,
        wsgi_max_queue_size: int | None = None,
        wsgi_queue_timeout: float | None = None,
    ) -> None:
        self.app = app
        self.max_body_size = max_body_size
        self.concurrency = WSGIConcurrency(
            wsgi_max_concurrency if wsgi_max_concurrency is not None else max_concurrency,
            wsgi_max_queue_size if wsgi_max_queue_size is not None else max_queue_size,
            wsgi_queue_timeout if wsgi_queue_timeout is not None else queue_timeout,
        )

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
        body = bytearray()
        while True:
            message = await receive()
            body.extend(message.get("body", b""))  # type: ignore
            if len(body) > self.max_body_size:
                await send({"type": "http.response.start", "status": 400, "headers": []})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                return
            if not message.get("more_body"):
                break

        try:
            environ = _build_environ(scope, bytes(body))
        except InvalidPathError:
            await send({"type": "http.response.start", "status": 404, "headers": []})
        else:
            try:
                await self.concurrency.run(
                    sync_spawn, self.run_app, environ, partial(call_soon, send)
                )
            except WSGIServerBusyError:
                await self._send_server_busy(send)
                return
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _send_server_busy(self, send: ASGISendCallable) -> None:
        body = b"Service Unavailable"
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    def run_app(self, environ: dict, send: Callable) -> None:
        headers: list[tuple[bytes, bytes]] = []
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

        response_body = self.app(environ, start_response)

        try:
            first_chunk = True
            for output in response_body:
                if first_chunk:
                    if not response_started:
                        raise RuntimeError("WSGI app did not call start_response")

                    send({"type": "http.response.start", "status": status_code, "headers": headers})
                    first_chunk = False

                send({"type": "http.response.body", "body": output, "more_body": True})
        finally:
            if hasattr(response_body, "close"):
                response_body.close()


def _build_environ(scope: HTTPScope, body: bytes) -> dict:
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
        "wsgi.input": BytesIO(body),
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
