from __future__ import annotations

import asyncio
from collections.abc import Callable
from collections.abc import Coroutine
from collections.abc import Mapping
from typing import Any
from typing import TYPE_CHECKING

from werkzeug.datastructures import Headers

from .ctx import copy_current_websocket_context
from .wrappers import ClientDisconnectedError

if TYPE_CHECKING:
    from .wrappers import Websocket

CallHandler = Callable[..., Any]
CallParams = list[Any] | Mapping[str, Any]
ScalarId = str | int | float | bool | None


class WebsocketCallClosedError(ClientDisconnectedError):
    """Raised when a handler writes after its websocket has closed."""


class WebsocketCallConnection:
    """Serialise writes and reject use after the connection closes."""

    def __init__(self, websocket: Websocket, send_lock: asyncio.Lock) -> None:
        self._websocket = websocket
        self._send_lock = send_lock
        self.closed = False

    async def accept(
        self, headers: dict | Headers | None = None, subprotocol: str | None = None
    ) -> None:
        if self.closed:
            raise WebsocketCallClosedError()
        async with self._send_lock:
            if self.closed:
                raise WebsocketCallClosedError()
            await self._websocket.accept(headers, subprotocol)

    async def send(self, data: str | bytes) -> None:
        if self.closed:
            raise WebsocketCallClosedError()
        async with self._send_lock:
            if self.closed:
                raise WebsocketCallClosedError()
            await self._websocket.send(data)

    async def send_json(self, *args: Any, **kwargs: Any) -> None:
        if args and kwargs:
            raise TypeError("Behavior undefined when passed both args and kwargs")
        if len(args) == 1:
            data = args[0]
        else:
            data = args or kwargs
        await self.send(self._websocket.json_module.dumps(data))


class _ProtocolError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _is_scalar_id(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


class WebsocketCallDispatcher:
    """Dispatch JSON websocket request messages to concurrent handlers.

    Request messages must contain exactly ``id``, ``method`` and ``params``.
    A request with method ``cancel`` cancels only the call using the same
    ``id``. This is an optional helper and does not replace the underlying
    websocket's raw send and receive methods.
    """

    def __init__(
        self,
        websocket: Websocket,
        handlers: Mapping[str, CallHandler],
        *,
        max_concurrency: int = 32,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least one")

        self._websocket = websocket
        self._handlers = dict(handlers)
        self._max_concurrency = max_concurrency
        self._active_calls = 0
        self._send_lock = asyncio.Lock()
        self._connection = WebsocketCallConnection(websocket, self._send_lock)
        self._pending: dict[ScalarId, asyncio.Task[None]] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._closing = False

    async def serve(self) -> None:
        """Read control messages and dispatch calls until the connection ends."""

        try:
            while True:
                message = await self._websocket.receive_json()
                self._validate_message(message)
                call_id = message["id"]
                if message["method"] == "cancel":
                    self._cancel(call_id)
                else:
                    self._start_call(
                        call_id, message["method"], message["params"]
                    )
        except _ProtocolError as error:
            await self._shutdown(1008, error.message)
        except (asyncio.CancelledError, ClientDisconnectedError):
            await self._shutdown()
            raise
        except Exception:
            await self._shutdown(1008, "Invalid protocol message")

    def _validate_message(self, message: Any) -> None:
        if not isinstance(message, dict):
            raise _ProtocolError("Message must be an object")
        if set(message) != {"id", "method", "params"}:
            raise _ProtocolError("Message must contain id, method and params")
        if not isinstance(message["method"], str):
            raise _ProtocolError("Method must be a string")
        if not isinstance(message["params"], (list, dict)):
            raise _ProtocolError("Params must be a list or object")
        if not _is_scalar_id(message["id"]):
            raise _ProtocolError("Id must be a JSON scalar")

        call_id = message["id"]
        if message["method"] == "cancel":
            if call_id not in self._pending:
                raise _ProtocolError("Cannot cancel an unknown call")
        elif call_id in self._pending:
            raise _ProtocolError("Call id is already pending")

    def _cancel(self, call_id: ScalarId) -> None:
        self._pending[call_id].cancel()

    def _start_call(
        self, call_id: ScalarId, method: str, params: CallParams
    ) -> None:
        handler = self._handlers.get(method)
        if handler is None:
            task = self._create_task(self._send_unknown_method(call_id))
        elif self._active_calls >= self._max_concurrency:
            task = self._create_task(self._send_busy(call_id))
        else:
            self._active_calls += 1
            task = self._create_task(self._run_call(call_id, handler, params))
        self._track(call_id, task)

    def _create_task(
        self, coroutine: Coroutine[Any, Any, None]
    ) -> asyncio.Task[None]:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _track(self, call_id: ScalarId, task: asyncio.Task[None]) -> None:
        self._pending[call_id] = task

        def discard(_: asyncio.Task[None]) -> None:
            if self._pending.get(call_id) is task:
                del self._pending[call_id]

        task.add_done_callback(discard)

    async def _run_call(
        self,
        call_id: ScalarId,
        handler: CallHandler,
        params: CallParams,
    ) -> None:
        cancellation_reported = False
        try:
            context_handler = copy_current_websocket_context(handler)
            if isinstance(params, list):
                result = await context_handler(self._connection, *params)
            else:
                result = await context_handler(self._connection, **params)
            await self._send_result(call_id, result)
        except asyncio.CancelledError:
            if self._closing:
                raise
            if cancellation_reported:
                raise
            cancellation_reported = True
            current_task = asyncio.current_task()
            if current_task is not None:
                current_task.uncancel()
            await self._send_error(call_id, -32800, "Call cancelled")
        except Exception as error:
            await self._send_error(call_id, -32000, str(error))
        finally:
            self._active_calls -= 1

    async def _send_busy(self, call_id: ScalarId) -> None:
        await self._send_error(call_id, -32000, "Server is busy")

    async def _send_unknown_method(self, call_id: ScalarId) -> None:
        await self._send_error(call_id, -32601, "Method not found")

    async def _send_result(self, call_id: ScalarId, result: Any) -> None:
        await self._send({"id": call_id, "result": result})

    async def _send_error(
        self, call_id: ScalarId, code: int, message: str
    ) -> None:
        await self._send(
            {"id": call_id, "error": {"code": code, "message": message}}
        )

    async def _send(self, payload: dict[str, Any]) -> None:
        if self._closing:
            return
        async with self._send_lock:
            if self._closing:
                return
            await self._websocket.send_json(payload)

    async def _shutdown(self, code: int | None = None, reason: str = "") -> None:
        if self._closing:
            await self._wait_for_pending()
            return

        self._closing = True
        self._connection.closed = True
        for task in self._pending.values():
            task.cancel()
        await self._wait_for_pending()

        if code is not None:
            try:
                await self._websocket.close(code, reason)
            except (ClientDisconnectedError, RuntimeError):
                pass

    async def _wait_for_pending(self) -> None:
        if self._pending:
            pending = list(self._pending.values())
            await asyncio.gather(*pending, return_exceptions=True)
