from __future__ import annotations

import collections
import typing

import anyio

from .._models import Request, Response
from .._types import AsyncByteStream
from .base import AsyncBaseTransport

if typing.TYPE_CHECKING:  # pragma: no cover
    import asyncio

    import trio


_Message = typing.MutableMapping[str, typing.Any]
_Receive = typing.Callable[[], typing.Awaitable[_Message]]
_Send = typing.Callable[
    [typing.MutableMapping[str, typing.Any]], typing.Awaitable[None]
]
_ASGIApp = typing.Callable[
    [typing.MutableMapping[str, typing.Any], _Receive, _Send], typing.Awaitable[None]
]

__all__ = ["ASGITransport"]


def is_running_trio() -> bool:
    try:
        # sniffio is a dependency of trio.

        # See https://github.com/python-trio/trio/issues/2802
        import sniffio

        if sniffio.current_async_library() == "trio":
            return True
    except ImportError:  # pragma: nocover
        pass

    return False


class _ClientDisconnected(Exception):
    """
    Raised within the ASGI application if it attempts to send response
    body data after the client has closed the response stream.
    """


class _AppTask:
    """
    Runs an ASGI application in a background task, so that the response
    can be returned as soon as the response headers arrive, with the
    response body streaming as the application produces it.

    Works on both asyncio and Trio.
    """

    def __init__(self, coro: typing.Callable[[], typing.Awaitable[None]]) -> None:
        self._done = anyio.Event()
        self._cancel_scope: trio.CancelScope | None = None
        self._task: asyncio.Task[None] | None = None

        if is_running_trio():
            import trio

            cancel_scope = self._cancel_scope = trio.CancelScope()

            async def runner() -> None:
                try:
                    with cancel_scope:
                        await coro()
                finally:
                    self._done.set()

            trio.lowlevel.spawn_system_task(runner)
        else:
            import asyncio

            self._task = asyncio.ensure_future(coro())
            # A done-callback is used rather than a try/finally in the
            # coroutine, since a task that is cancelled before it starts
            # running never executes any of the coroutine body.
            self._task.add_done_callback(lambda task: self._done.set())

    def cancel(self) -> None:
        if self._cancel_scope is not None:
            self._cancel_scope.cancel()
        elif self._task is not None:
            self._task.cancel()

    async def wait(self) -> None:
        await self._done.wait()


class _ResponseChannel:
    """
    A byte-bounded buffer, passing response body parts from the ASGI
    application to the client. If the client is slow to consume the
    response body then the application blocks on send() once the
    buffer is full, applying backpressure.
    """

    def __init__(self, max_buffer_bytes: int) -> None:
        self._max_buffer_bytes = max_buffer_bytes
        self._chunks: collections.deque[bytes] = collections.deque()
        self._buffered_bytes = 0
        self._condition = anyio.Condition()
        self._finished = False
        self._closed = False
        self._exception: Exception | None = None

    async def put(self, chunk: bytes) -> None:
        async with self._condition:
            while (
                self._chunks
                and self._buffered_bytes >= self._max_buffer_bytes
                and not self._closed
            ):
                await self._condition.wait()
            if self._closed:
                raise _ClientDisconnected()
            self._chunks.append(chunk)
            self._buffered_bytes += len(chunk)
            self._condition.notify_all()

    async def finish(self, exc: Exception | None = None) -> None:
        async with self._condition:
            if exc is not None:
                self._exception = exc
            self._finished = True
            self._condition.notify_all()

    async def close(self) -> None:
        async with self._condition:
            self._closed = True
            self._condition.notify_all()

    async def get(self) -> bytes | None:
        async with self._condition:
            while not self._chunks and not self._finished and not self._closed:
                await self._condition.wait()
            if self._chunks:
                chunk = self._chunks.popleft()
                self._buffered_bytes -= len(chunk)
                self._condition.notify_all()
                return chunk
            if self._exception is not None:
                raise self._exception
            return None


class ASGIResponseStream(AsyncByteStream):
    """
    Streams the response body as it is produced by the ASGI application.

    Closing the stream disconnects the client, ending the background
    task that is running the application.
    """

    def __init__(
        self,
        channel: _ResponseChannel,
        app_task: _AppTask,
        disconnected: anyio.Event,
        open_streams: set[ASGIResponseStream],
    ) -> None:
        self._channel = channel
        self._app_task = app_task
        self._disconnected = disconnected
        self._open_streams = open_streams
        self._closed = False

    def __aiter__(self) -> typing.AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        try:
            chunk = await self._channel.get()
        except BaseException:
            await self.aclose()
            raise
        if chunk is None:
            await self.aclose()
            raise StopAsyncIteration
        return chunk

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._open_streams.discard(self)
        with anyio.CancelScope(shield=True):
            await self._channel.close()
            self._disconnected.set()
            self._app_task.cancel()
            await self._app_task.wait()


class ASGITransport(AsyncBaseTransport):
    """
    A custom AsyncTransport that handles sending requests directly to an ASGI app.

    ```python
    transport = httpx.ASGITransport(
        app=app,
        root_path="/submount",
        client=("1.2.3.4", 123)
    )
    client = httpx.AsyncClient(transport=transport)
    ```

    Arguments:

    * `app` - The ASGI application.
    * `raise_app_exceptions` - Boolean indicating if exceptions in the application
       should be raised. Default to `True`. Can be set to `False` for use cases
       such as testing the content of a client 500 response.
    * `root_path` - The root path on which the ASGI application should be mounted.
    * `client` - A two-tuple indicating the client IP and port of incoming requests.
    * `max_buffer_bytes` - The maximum number of response body bytes to buffer
       between the application and the client. If the client is slow to consume
       the response body then the application blocks on `send()` once this
       limit is reached. Defaults to 64 KiB.
    ```
    """

    def __init__(
        self,
        app: _ASGIApp,
        raise_app_exceptions: bool = True,
        root_path: str = "",
        client: tuple[str, int] = ("127.0.0.1", 123),
        max_buffer_bytes: int = 64 * 1024,
    ) -> None:
        self.app = app
        self.raise_app_exceptions = raise_app_exceptions
        self.root_path = root_path
        self.client = client
        self.max_buffer_bytes = max_buffer_bytes
        self._response_streams: set[ASGIResponseStream] = set()

    async def handle_async_request(
        self,
        request: Request,
    ) -> Response:
        assert isinstance(request.stream, AsyncByteStream)

        # ASGI scope.
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": request.method,
            "headers": [(k.lower(), v) for (k, v) in request.headers.raw],
            "scheme": request.url.scheme,
            "path": request.url.path,
            "raw_path": request.url.raw_path.split(b"?")[0],
            "query_string": request.url.query,
            "server": (request.url.host, request.url.port),
            "client": self.client,
            "root_path": self.root_path,
        }

        # Request.
        request_body_chunks = request.stream.__aiter__()
        request_complete = False

        # Response.
        status_code: int | None = None
        response_headers: list[tuple[bytes, bytes]] | None = None
        response_started = False
        app_exception: Exception | None = None

        channel = _ResponseChannel(max_buffer_bytes=self.max_buffer_bytes)
        response_ready = anyio.Event()
        disconnected = anyio.Event()

        # ASGI callables.

        async def receive() -> dict[str, typing.Any]:
            nonlocal request_complete

            if request_complete:
                await disconnected.wait()
                return {"type": "http.disconnect"}

            try:
                body = await request_body_chunks.__anext__()
            except StopAsyncIteration:
                request_complete = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.request", "body": body, "more_body": True}

        async def send(message: typing.MutableMapping[str, typing.Any]) -> None:
            nonlocal status_code, response_headers, response_started

            if message["type"] == "http.response.start":
                assert not response_started

                status_code = message["status"]
                response_headers = message.get("headers", [])
                response_started = True
                response_ready.set()

            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)

                if body and request.method != "HEAD":
                    await channel.put(body)

                if not more_body:
                    disconnected.set()

        async def run_app() -> None:
            nonlocal app_exception

            try:
                await self.app(scope, receive, send)
            except _ClientDisconnected:
                pass
            except Exception as exc:  # noqa: PIE-786
                app_exception = exc
            finally:
                error = app_exception if self.raise_app_exceptions else None
                with anyio.CancelScope(shield=True):
                    await channel.finish(error)
                response_ready.set()
                disconnected.set()

        app_task = _AppTask(run_app)

        try:
            await response_ready.wait()
        except BaseException:
            # The request was cancelled before the response started.
            with anyio.CancelScope(shield=True):
                await channel.close()
                disconnected.set()
                app_task.cancel()
                await app_task.wait()
            raise

        if not response_started:
            # The application exited without sending a response.
            if app_exception is not None and self.raise_app_exceptions:
                raise app_exception
            status_code = 500
            response_headers = []

        assert status_code is not None
        assert response_headers is not None

        stream = ASGIResponseStream(
            channel, app_task, disconnected, self._response_streams
        )
        self._response_streams.add(stream)

        return Response(status_code, headers=response_headers, stream=stream)

    async def aclose(self) -> None:
        for stream in list(self._response_streams):
            await stream.aclose()
