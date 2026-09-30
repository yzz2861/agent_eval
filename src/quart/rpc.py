from __future__ import annotations

import asyncio
from collections.abc import Callable
from inspect import isawaitable
from typing import Any
from typing import TYPE_CHECKING

from .wrappers.base import ClientDisconnectedError

if TYPE_CHECKING:
    from .wrappers.websocket import Websocket


class RPCProtocolError(Exception):
    """Raised when a client message violates the RPC protocol."""


class WebsocketRPC:
    """A lightweight JSON-RPC style dispatcher for a websocket route.

    This is an optional helper, it plugs into an existing websocket
    route without requiring a separate server::

        @app.websocket("/rpc")
        async def rpc() -> None:
            dispatcher = WebsocketRPC(websocket, max_concurrent=4)

            @dispatcher.method("echo")
            async def echo(params: Any) -> Any:
                return params

            await dispatcher.run()

    Clients send {"id": ..., "method": ..., "params": ...} and receive
    {"id": ..., "result": ...} or {"id": ..., "error": {...}} with the
    matching id. Calls with distinct ids are handled in parallel.
    Sending {"cancel": id} cancels only that call. The raw receive and
    send API of the websocket remains available alongside the
    dispatcher.

    Arguments:
        websocket: The websocket for the current connection.
        max_concurrent: Maximum number of calls handled in parallel,
            additional calls receive a "busy" error rather than being
            queued.
    """

    def __init__(self, websocket: Websocket, *, max_concurrent: int = 8) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self._websocket = websocket
        self._max_concurrent = max_concurrent
        self._handlers: dict[str, Callable[[Any], Any]] = {}
        self._tasks: dict[Any, asyncio.Task[None]] = {}
        self._responded: set[Any] = set()
        self._send_lock = asyncio.Lock()
        self._closed = False

    def method(
        self, name: str | None = None
    ) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
        """Register a handler, usable as a decorator."""

        def decorator(func: Callable[[Any], Any]) -> Callable[[Any], Any]:
            self._handlers[name if name is not None else func.__name__] = func
            return func

        return decorator

    async def run(self) -> None:
        """Serve messages until disconnect or a protocol error.

        On return all in-flight calls have been cancelled and awaited,
        and the dispatcher will no longer use the websocket.
        """
        try:
            while True:
                raw = await self._websocket.receive()
                await self._handle(raw)
        except ClientDisconnectedError:
            pass
        except asyncio.CancelledError:
            # Quart cancels the route task when the client disconnects,
            # treat this as the end of the connection.
            self._uncancel()
        except RPCProtocolError as error:
            try:
                await self._websocket.close(1002, str(error))
            except (ClientDisconnectedError, asyncio.CancelledError):
                self._uncancel()
        finally:
            await self._shutdown()

    @staticmethod
    def _uncancel() -> None:
        task = asyncio.current_task()
        if task is not None:
            task.uncancel()

    async def _handle(self, raw: str | bytes) -> None:
        try:
            message = self._websocket.json_module.loads(raw)
        except Exception:
            raise RPCProtocolError("Message is not valid JSON") from None
        if not isinstance(message, dict):
            raise RPCProtocolError("Message must be a JSON object")

        if "cancel" in message:
            call_id = message["cancel"]
            if isinstance(call_id, bool) or not isinstance(call_id, (str, int)):
                raise RPCProtocolError("Cancel id must be a string or an integer")
            task = self._tasks.get(call_id)
            if task is not None:
                task.cancel()
                await self._respond(
                    call_id,
                    error={"code": "cancelled", "message": "Call was cancelled"},
                )
            return

        call_id = message.get("id")
        if isinstance(call_id, bool) or not isinstance(call_id, (str, int)):
            raise RPCProtocolError("Call id must be a string or an integer")
        if call_id in self._tasks:
            raise RPCProtocolError(f"Duplicate in-flight id {call_id!r}")
        method = message.get("method")
        if not isinstance(method, str):
            raise RPCProtocolError("Call method must be a string")
        params = message.get("params")

        handler = self._handlers.get(method)
        if handler is None:
            await self._respond(
                call_id,
                error={
                    "code": "method_not_found",
                    "message": f"Unknown method {method!r}",
                },
            )
            return
        if len(self._tasks) >= self._max_concurrent:
            await self._respond(
                call_id,
                error={"code": "busy", "message": "No concurrency slot available"},
            )
            return

        task = asyncio.ensure_future(self._run_call(call_id, handler, params))
        self._tasks[call_id] = task
        task.add_done_callback(lambda _: self._call_done(call_id))

    def _call_done(self, call_id: str | int) -> None:
        self._tasks.pop(call_id, None)
        self._responded.discard(call_id)

    async def _run_call(
        self, call_id: str | int, handler: Callable[[Any], Any], params: Any
    ) -> None:
        try:
            result = handler(params)
            if isawaitable(result):
                result = await result
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await self._respond(
                call_id, error={"code": "internal", "message": str(error)}
            )
        else:
            await self._respond(call_id, result=result)

    async def _respond(
        self, call_id: str | int, *, result: Any = None, error: dict | None = None
    ) -> None:
        if self._closed or call_id in self._responded:
            return
        self._responded.add(call_id)
        message: dict[str, Any] = {"id": call_id}
        if error is not None:
            message["error"] = error
        else:
            message["result"] = result
        async with self._send_lock:
            if self._closed:
                return
            try:
                await self._websocket.send_json(message)
            except ClientDisconnectedError:
                self._closed = True

    async def _shutdown(self) -> None:
        self._closed = True
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        pending = [task for task in tasks if not task.done()]
        while pending:
            try:
                await asyncio.gather(*pending, return_exceptions=True)
            except asyncio.CancelledError:
                # The route task itself was cancelled while waiting,
                # keep waiting for the children to finish.
                self._uncancel()
                pending = [task for task in pending if not task.done()]
            else:
                break
