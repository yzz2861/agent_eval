from __future__ import annotations

import typing

import anyio

from .._models import Request, Response
from .._types import AsyncByteStream
from .base import AsyncBaseTransport

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


# The maximum number of ASGI messages that may be buffered in-between
# the application and the client. Once the buffer is full, the application
# blocks on send() until the client consumes more of the response.
# This provides backpressure, so that slow clients cause slow applications,
# rather than unbounded buffering.
_MAX_BUFFERED_MESSAGES = 1


class _AppTask:
    """
    A handle to a background task running an ASGI application,
    allowing the task to be cancelled and awaited.
    """

    def __init__(self) -> None:
        self._completed = anyio.Event()
        self._cancel: typing.Callable[[], None] = lambda: None

    @classmethod
    def spawn(
        cls,
        run_app: typing.Callable[[], typing.Coroutine[typing.Any, typing.Any, None]],
    ) -> "_AppTask":
        self = cls()
        if is_running_trio():
            import trio

            cancel_scope = trio.CancelScope()

            async def runner() -> None:
                try:
                    with cancel_scope:
                        await run_app()
                finally:
                    self._completed.set()

            trio.lowlevel.spawn_system_task(runner)
            self._cancel = cancel_scope.cancel
        else:
            import asyncio

            task = asyncio.get_running_loop().create_task(run_app())
            task.add_done_callback(lambda task: self._completed.set())
            self._cancel = task.cancel

        return self

    def cancel(self) -> None:
        self._cancel()

    async def wait(self) -> None:
        # Shielded, so that the background task is always awaited,
        # even when cleaning up during cancellation.
        with anyio.CancelScope(shield=True):
            await self._completed.wait()


class _ASGIRequestState:
    """
    State shared between a background ASGI application task and the
    response stream that is consuming its messages.
    """

    def __init__(self) -> None:
        # Set once the application has sent a final http.response.body
        # message, or once the response stream is closed. Any receive()
        # calls in the application then return an http.disconnect.
        self.response_complete = anyio.Event()
        # Set if the application raised an exception.
        self.app_exception: BaseException | None = None


class ASGIResponseStream(AsyncByteStream):
    """
    A byte stream that delivers the response body of an ASGI application
    as the application produces it, rather than once it has completed.

    Closing the stream shuts down the background task that is running
    the application, cancelling it if it has not completed yet.
    """

    def __init__(
        self,
        receive_stream: anyio.abc.ObjectReceiveStream[_Message],
        app_task: _AppTask,
        state: _ASGIRequestState,
        raise_app_exceptions: bool,
        on_close: typing.Callable[["ASGIResponseStream"], None],
    ) -> None:
        self._receive_stream = receive_stream
        self._app_task = app_task
        self._state = state
        self._raise_app_exceptions = raise_app_exceptions
        self._on_close = on_close
        self._body_complete = False
        self._closed = False
        self._final_message_seen = False
        self._completed = False

    def __aiter__(self) -> "ASGIResponseStream":
        return self

    async def __anext__(self) -> bytes:
        if self._completed or self._closed:
            raise StopAsyncIteration

        if not self._final_message_seen:
            try:
                while True:
                    message = await self._receive_stream.receive()
                    if message["type"] != "http.response.body":
                        continue

                    body = message.get("body", b"")
                    if not message.get("more_body", False):
                        self._final_message_seen = True
                    if body:
                        return body
                    if self._final_message_seen:
                        break
            except anyio.EndOfStream:
                self._final_message_seen = True
            except BaseException:
                await self.aclose()
                raise

        self._completed = True
        self._body_complete = True
        await self.aclose()

        exception = self._state.app_exception
        if (
            self._raise_app_exceptions
            and exception is not None
            and not isinstance(exception, anyio.get_cancelled_exc_class())
        ):
            # The application raised after the response had started.
            raise exception
        raise StopAsyncIteration

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            # Allow any receive() calls in the application to complete
            # with an http.disconnect message.
            self._state.response_complete.set()
            if not self._body_complete:
                # The response is being closed before the body completed,
                # so any remaining application work is no longer required.
                self._app_task.cancel()
            self._receive_stream.close()
            # Wait for the background application task to exit.
            await self._app_task.wait()
        finally:
            self._on_close(self)


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

    Responses are streamed: the response is returned as soon as the application
    sends the response status and headers, and the response body is consumed
    from the application as it is produced, with a bounded buffer applying
    backpressure to the application if the client is slow to read.
    ```
    """

    def __init__(
        self,
        app: _ASGIApp,
        raise_app_exceptions: bool = True,
        root_path: str = "",
        client: tuple[str, int] = ("127.0.0.1", 123),
    ) -> None:
        self.app = app
        self.raise_app_exceptions = raise_app_exceptions
        self.root_path = root_path
        self.client = client
        self._open_streams: set[ASGIResponseStream] = set()

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
        is_head_request = request.method == "HEAD"

        # The application runs in a background task, communicating with the
        # client through a bounded message stream, so that responses are
        # streamed rather than buffered until the application completes.
        state = _ASGIRequestState()
        send_stream, receive_stream = anyio.create_memory_object_stream[_Message](
            _MAX_BUFFERED_MESSAGES
        )

        # ASGI callables.

        async def receive() -> dict[str, typing.Any]:
            nonlocal request_complete

            if request_complete:
                await state.response_complete.wait()
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
                await send_stream.send(message)

            elif message["type"] == "http.response.body":
                assert response_started
                assert not state.response_complete.is_set()
                more_body = message.get("more_body", False)

                if not more_body:
                    state.response_complete.set()

                # HEAD responses must not include a body, but the application
                # is still allowed to send body messages without blocking.
                if not is_head_request:
                    await send_stream.send(message)

        async def run_app() -> None:
            try:
                await self.app(scope, receive, send)
            except BaseException as exc:  # noqa: PIE-786
                state.app_exception = exc
            finally:
                send_stream.close()

        app_task = _AppTask.spawn(run_app)
        try:
            # Wait until the application has sent the response status and
            # headers, or until it completes without starting the response.
            try:
                first_message: _Message | None = await receive_stream.receive()
            except anyio.EndOfStream:
                first_message = None
        except BaseException:
            app_task.cancel()
            receive_stream.close()
            send_stream.close()
            await app_task.wait()
            raise

        if first_message is None:
            # The application completed without sending a response.
            if self.raise_app_exceptions:
                receive_stream.close()
                await app_task.wait()
                if state.app_exception is not None:
                    raise state.app_exception
                raise RuntimeError(
                    "ASGI application completed without sending a response."
                )

            status_code = 500
            response_headers = []

        assert status_code is not None
        assert response_headers is not None

        stream = ASGIResponseStream(
            receive_stream=receive_stream,
            app_task=app_task,
            state=state,
            raise_app_exceptions=self.raise_app_exceptions,
            on_close=self._open_streams.discard,
        )
        self._open_streams.add(stream)

        return Response(status_code, headers=response_headers, stream=stream)

    async def aclose(self) -> None:
        # Close any responses that are still being streamed, shutting down
        # the background application tasks that are producing them.
        while self._open_streams:
            stream = next(iter(self._open_streams))
            await stream.aclose()
