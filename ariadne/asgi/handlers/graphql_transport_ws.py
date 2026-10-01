import asyncio
from collections.abc import AsyncGenerator
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import timedelta
from inspect import isawaitable
from typing import Any, cast

from graphql import GraphQLError
from graphql.language import OperationType
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from ...graphql import parse_query, subscribe, validate_data
from ...logger import log_error
from ...types import (
    ExecutionResult,
    OnSubscriptionAuthorize,
    Operation,
)
from ...utils import get_operation_type
from .base import GraphQLWebsocketHandlerBase


@dataclass
class _OperationState:
    operation: Operation
    task: asyncio.Task[None] | None = None
    rechecks: asyncio.Queue[None] | None = None
    finishing: bool = False
    client_stopped: bool = False
    cleaned: bool = False
    finished: asyncio.Event = field(default_factory=asyncio.Event)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class _SubscriptionWaitResult:
    result: ExecutionResult | None = None
    exhausted: bool = False
    recheck_requested: bool = False


class ClientContext:
    def __init__(self, websocket: WebSocket | None = None) -> None:
        self.connection_acknowledged: bool = False
        self.connection_init_timeout_task: asyncio.Task | None = None
        self.connection_init_received: bool = False
        self.operations: dict[str, Operation] = {}
        self.operation_states: dict[str, _OperationState] = {}
        self.websocket: WebSocket | None = websocket


class GraphQLTransportWSHandler(GraphQLWebsocketHandlerBase):
    """Implementation of the (newer) graphql-transport-ws subprotocol
    from the graphql-ws library.

    For more details see it's GH page:

    https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md
    """

    GQL_CONNECTION_INIT = "connection_init"  # Client -> Server
    GQL_CONNECTION_ACK = "connection_ack"  # Server -> Client
    GQL_PING = "ping"  # Client -> Server, Server -> Client
    GQL_PONG = "pong"  # Client -> Server, Server -> Client
    GQL_SUBSCRIBE = "subscribe"  # Client -> Server
    GQL_NEXT = "next"  # Server -> Client
    GQL_ERROR = "error"  # Server -> Client
    GQL_COMPLETE = "complete"  # Client -> Server, Server -> Client

    def __init__(
        self,
        *args,
        connection_init_wait_timeout: timedelta = timedelta(minutes=1),
        on_subscription_authorize: OnSubscriptionAuthorize | None = None,
        **kwargs,
    ) -> None:
        """Initializes the websocket handler.

        # Optional arguments

        `connection_init_wait_timeout`: a `timedelta` with timeout for new
        websocket connections before first message is received. Defaults to
        60 seconds.

        `on_subscription_authorize`: an optional sync or async callback called
        before each subscription event. A falsey result stops only that
        subscription.
        """
        super().__init__(*args, **kwargs)

        self.connection_init_wait_timeout = connection_init_wait_timeout
        self.on_subscription_authorize = on_subscription_authorize
        self.client_contexts: dict[int, ClientContext] = {}

    async def handle(self, scope: Scope, receive: Receive, send: Send):
        """An entrypoint for the GraphQL WebSocket handler.

        This method is called by the Ariadne ASGI GraphQL application to handle
        the websocket connections.

        It creates the `starlette.websockets.WebSocket` instance and calls
        `handle_websocket` method with it.

        # Required arguments

        `scope`: The connection scope information, a dictionary that contains
        at least a type key specifying the protocol that is incoming.

        `receive`: an awaitable callable that will yield a new event dictionary
        when one is available.

        `send`: an awaitable callable taking a single event dictionary as a
        positional argument that will return once the send has been completed
        or the connection has been closed.

        Details about the arguments and their usage are described in the
        ASGI specification:

        https://asgi.readthedocs.io/en/latest/specs/main.html
        """
        websocket = WebSocket(scope=scope, receive=receive, send=send)
        await self.handle_websocket(websocket)

    async def handle_websocket(self, websocket: WebSocket):
        """Handle GraphQL the WebSocket connection.

        Is called by the `handle` method and `handle_websocket` method of the
        ASGI GraphQL application.

        # Required arguments:

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.
        """
        await websocket.accept("graphql-transport-ws")

        client_context = ClientContext(websocket)
        self.client_contexts[id(websocket)] = client_context
        timeout_handler = self.handle_connection_init_timeout(websocket, client_context)
        timeout_task = asyncio.create_task(timeout_handler)
        client_context.connection_init_timeout_task = timeout_task

        try:
            while WebSocketState.DISCONNECTED not in (
                websocket.client_state,
                websocket.application_state,
            ):
                message = await websocket.receive_json()
                await self.handle_websocket_message(websocket, message, client_context)
        except WebSocketDisconnect:
            pass
        finally:
            try:
                for operation_id in list(client_context.operations.keys()):
                    await self.stop_websocket_operation(
                        websocket, operation_id, client_context
                    )
            finally:
                self.client_contexts.pop(id(websocket), None)
                timeout_task.cancel()
                with suppress(asyncio.CancelledError):
                    await timeout_task

                try:
                    if self.on_disconnect:
                        result = self.on_disconnect(websocket)
                        if result and isawaitable(result):
                            await result
                except Exception as error:
                    if not isinstance(error, GraphQLError):
                        error = GraphQLError(str(error), original_error=error)
                    log_error(error, self.logger)

    def notify_subscription_authorization_changed(
        self,
        websocket: WebSocket,
        operation_id: str | None = None,
    ) -> None:
        """Schedules an authorization re-check for one or all subscriptions.

        Re-checks are coalesced. While one check is already waiting, at most
        one additional check can be queued for an operation, so its source
        iterator cannot accumulate an unbounded number of events.

        Call this method on the WebSocket's event loop. From another thread,
        use `loop.call_soon_threadsafe(...)`.
        """
        client_context = self.client_contexts.get(id(websocket))
        if client_context is None:
            return

        operation_ids = (
            (operation_id,) if operation_id is not None else client_context.operations
        )
        for current_id in operation_ids:
            state = client_context.operation_states.get(current_id)
            if state is None or state.rechecks is None:
                continue
            with suppress(asyncio.QueueFull):
                state.rechecks.put_nowait(None)

    async def handle_connection_init_timeout(
        self, websocket: WebSocket, client_context: ClientContext
    ):
        delay = self.connection_init_wait_timeout.total_seconds()
        await asyncio.sleep(delay=delay)
        if client_context.connection_init_received:
            return
        if WebSocketState.DISCONNECTED not in (
            websocket.client_state,
            websocket.application_state,
        ):
            # 4408: Connection initialisation timeout
            await websocket.close(code=4408)

    async def handle_websocket_message(
        self,
        websocket: WebSocket,
        message: dict,
        client_context: ClientContext,
    ):
        """Handles new message from websocket connection.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `message`: a `dict` with message payload.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        operation_id = cast(str, message.get("id"))
        message_type = cast(str, message.get("type"))

        if message_type == GraphQLTransportWSHandler.GQL_CONNECTION_INIT:
            await self.handle_websocket_connection_init_message(
                websocket, message, client_context
            )
        elif message_type == GraphQLTransportWSHandler.GQL_PING:
            await self.handle_websocket_ping_message(websocket, client_context)
        elif message_type == GraphQLTransportWSHandler.GQL_PONG:
            await self.handle_websocket_pong_message(websocket, client_context)
        elif message_type == GraphQLTransportWSHandler.GQL_COMPLETE:
            await self.handle_websocket_complete_message(
                websocket, operation_id, client_context
            )
        elif message_type == GraphQLTransportWSHandler.GQL_SUBSCRIBE:
            await self.handle_websocket_subscribe(
                websocket, message.get("payload"), operation_id, client_context
            )
        else:
            await self.handle_websocket_invalid_type(websocket)

    async def handle_websocket_connection_init_message(
        self,
        websocket: WebSocket,
        message: dict,
        client_context: ClientContext,
    ):
        """Handles `connection_init` websocket message.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `message`: a `dict` with message payload.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        if client_context.connection_init_received:
            # 4429: Too many initialisation requests
            await websocket.close(code=4429)
            return

        client_context.connection_init_received = True

        try:
            if self.on_connect:
                result = self.on_connect(websocket, message.get("payload"))
                if result and isawaitable(result):
                    await result

            await websocket.send_json(
                {"type": GraphQLTransportWSHandler.GQL_CONNECTION_ACK}
            )
            client_context.connection_acknowledged = True
        except Exception as error:
            log_error(error, self.logger)
            await websocket.close()

    async def handle_websocket_ping_message(
        self,
        websocket: WebSocket,
        client_context: ClientContext,
    ):
        """Handles `ping` websocket message, answering with `pong` message.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        await websocket.send_json({"type": GraphQLTransportWSHandler.GQL_PONG})

    async def handle_websocket_pong_message(
        self,
        websocket: WebSocket,
        client_context: ClientContext,
    ):
        """Handles `pong` websocket message.

        Unlike `ping` message, `pong` is unidirectional heartbeat sent by the
        client to the server. It doesn't require a result.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """

    async def handle_websocket_complete_message(
        self,
        websocket: WebSocket,
        operation_id: str,
        client_context: ClientContext,
    ):
        """Handles `complete` websocket message.

        `complete` message tells the GraphQL server to stop sending events for
        GraphQL operation specified in the message

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `operation_id`: a `str` with id of operation that should be stopped.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        await self.stop_websocket_operation(websocket, operation_id, client_context)

    async def handle_websocket_subscribe(
        self,
        websocket: WebSocket,
        data: Any,
        operation_id: str,
        client_context: ClientContext,
    ):
        """Handles `subscribe` websocket message.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `data`: any data from `subscribe` message.

        `operation_id`: a `str` with id of new subscribe operation.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        if not client_context.connection_acknowledged:
            await websocket.close(code=4401)
            return

        if operation_id in client_context.operations:
            await websocket.close(code=4409)
            return

        validate_data(data)

        context_value = await self.get_context_for_request(websocket, data)

        try:
            query_document = parse_query(context_value, self.query_parser, data)
            operation_type = get_operation_type(
                query_document, data.get("operationName")
            )
        except GraphQLError as error:
            log_error(error, self.logger)
            await websocket.send_json(
                {
                    "type": GraphQLTransportWSHandler.GQL_ERROR,
                    "id": operation_id,
                    "payload": [self.error_formatter(error, self.debug)],
                }
            )
            return

        if operation_type == OperationType.SUBSCRIPTION:
            if self.schema is None:
                raise TypeError(
                    "schema is not set, call configure method to initialize it"
                )

            success, results_producer = await subscribe(
                self.schema,
                data,
                context_value=context_value,
                root_value=self.root_value,
                query_document=query_document,
                query_validator=self.query_validator,
                validation_rules=self.validation_rules,
                debug=self.debug,
                introspection=self.introspection,
                logger=self.logger,
                error_formatter=self.error_formatter,
            )
        else:
            if self.http_handler is None:
                raise TypeError(
                    "http_handler is not set, call configure method to initialize it"
                )

            success, result = await self.http_handler.execute_graphql_query(
                websocket,
                data,
                context_value=context_value,
                query_document=query_document,
            )

            async def get_results():
                yield result

            # if success then AsyncGenerator is expected, for error it will be List
            if success:
                results_producer = get_results()
            else:
                results_producer = result["errors"]

        if not success:
            if not isinstance(results_producer, list):
                error_payload = cast(list[dict], [results_producer])
            else:
                error_payload = results_producer

            await websocket.send_json(
                {
                    "type": GraphQLTransportWSHandler.GQL_ERROR,
                    "id": operation_id,
                    "payload": error_payload,
                }
            )
        else:
            results_producer = cast(
                AsyncGenerator[ExecutionResult, None], results_producer
            )
            client_context.operations[operation_id] = Operation(
                id=operation_id,
                name=data.get("operationName"),
                generator=results_producer,
                context_value=context_value,
            )
            state = _OperationState(
                operation=client_context.operations[operation_id],
                rechecks=(
                    asyncio.Queue(maxsize=1)
                    if operation_type == OperationType.SUBSCRIPTION
                    else None
                ),
            )
            client_context.operation_states[operation_id] = state

            if self.on_operation:
                try:
                    result = self.on_operation(
                        websocket, client_context.operations[operation_id]
                    )
                    if result and isawaitable(result):
                        await result
                except Exception as error:
                    if not isinstance(error, GraphQLError):
                        error = GraphQLError(str(error), original_error=error)
                    log_error(error, self.logger)

            state.task = asyncio.ensure_future(
                self.observe_async_results(
                    websocket,
                    results_producer,
                    operation_id,
                    client_context,
                    subscription=operation_type == OperationType.SUBSCRIPTION,
                )
            )

    async def handle_websocket_invalid_type(self, websocket: WebSocket):
        """Handles unsupported or invalid websocket message.

        Closes open websocket connection with error code `4400`.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.
        """
        await websocket.close(code=4400)

    async def handle_on_complete(
        self,
        websocket: WebSocket,
        operation: Operation,
    ):
        """Handles completed websocket operation.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `operation`: a completed `Operation`.
        """
        if self.on_complete:
            try:
                result = self.on_complete(websocket, operation)
                if result and isawaitable(result):
                    await result
            except Exception as error:
                if not isinstance(error, GraphQLError):
                    error = GraphQLError(str(error), original_error=error)
                log_error(error, self.logger)

    async def stop_websocket_operation(
        self,
        websocket: WebSocket,
        operation_id: str,
        client_context: ClientContext,
    ) -> None:
        """Stops specified GraphQL operation for given connection and context.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `operation_id`: a `str` with id of operation to stop.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        if operation_id not in client_context.operations:
            return

        state = client_context.operation_states.get(operation_id)
        if state is None:
            return

        async with state.lock:
            if state.cleaned:
                await state.finished.wait()
                return
            if state.finishing:
                await state.finished.wait()
                return

            state.finishing = True
            state.client_stopped = True
            operation = client_context.operations.pop(operation_id)
            client_context.operation_states.pop(operation_id, None)

        task = state.task
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

        await self._cleanup_operation(
            websocket,
            operation,
            state,
            send_complete=False,
        )

    async def observe_async_results(
        self,
        websocket: WebSocket,
        results_producer: AsyncGenerator,
        operation_id: str,
        client_context: ClientContext,
        subscription: bool = False,
    ) -> None:
        """Converts results from Ariadne's `subscribe` generator into websocket
        messages it next sends to the client.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `results_producer`: the `AsyncGenerator` returned from Ariadne's
        `subscribe` function.

        `operation_id`: a `str` with id of operation.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        state = client_context.operation_states[operation_id]
        try:
            if subscription:
                await self._observe_subscription_results(
                    websocket, results_producer, state
                )
            else:
                async for result in results_producer:
                    await self._send_operation_result(
                        websocket, state.operation, result
                    )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if not isinstance(error, GraphQLError):
                error = GraphQLError(str(error), original_error=error)
            log_error(error, self.logger)
            payload = {"errors": [self.error_formatter(error, self.debug)]}
            await self._send_json_if_connected(
                websocket,
                {
                    "type": GraphQLTransportWSHandler.GQL_NEXT,
                    "id": operation_id,
                    "payload": payload,
                },
            )
        finally:
            async with state.lock:
                natural_finish = not state.finishing
                if natural_finish:
                    state.finishing = True
                    operation = client_context.operations.pop(operation_id)
                    client_context.operation_states.pop(operation_id, None)

            if natural_finish:
                await self._cleanup_operation(
                    websocket,
                    operation,
                    state,
                    send_complete=not state.client_stopped,
                )

    async def _observe_subscription_results(
        self,
        websocket: WebSocket,
        results_producer: AsyncGenerator[ExecutionResult, None],
        state: _OperationState,
    ) -> None:
        pending_result: ExecutionResult | None = None
        source_task: asyncio.Task[ExecutionResult] | None = None
        recheck_task: asyncio.Task[None] | None = None

        try:
            while True:
                if self._consume_recheck_request(state):
                    continue

                if pending_result is not None:
                    await self._send_operation_result(
                        websocket, state.operation, pending_result
                    )
                    pending_result = None
                    continue

                authorized = await self._authorize_subscription(
                    websocket, state.operation
                )
                if not authorized:
                    return
                if self._consume_recheck_request(state):
                    continue

                source_task = asyncio.ensure_future(results_producer.__anext__())
                if state.rechecks is not None:
                    recheck_task = asyncio.ensure_future(state.rechecks.get())
                wait_result = await self._wait_for_subscription_event(
                    source_task, recheck_task
                )
                source_task = None
                recheck_task = None

                if wait_result.exhausted:
                    return
                if wait_result.recheck_requested:
                    continue
                pending_result = wait_result.result
        finally:
            await self._cancel_pending_tasks(source_task, recheck_task)

    def _consume_recheck_request(self, state: _OperationState) -> bool:
        if state.rechecks is None:
            return False
        try:
            state.rechecks.get_nowait()
        except asyncio.QueueEmpty:
            return False
        return True

    async def _wait_for_subscription_event(
        self,
        source_task: asyncio.Task[ExecutionResult],
        recheck_task: asyncio.Task[None] | None,
    ) -> _SubscriptionWaitResult:
        tasks = {source_task, *([recheck_task] if recheck_task is not None else [])}
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        if source_task not in done:
            await self._cancel_pending_tasks(source_task, recheck_task)
            return _SubscriptionWaitResult(recheck_requested=True)

        try:
            result = await source_task
        except StopAsyncIteration:
            await self._cancel_pending_tasks(recheck_task)
            return _SubscriptionWaitResult(exhausted=True)

        if recheck_task is not None and recheck_task.done():
            await recheck_task
            return _SubscriptionWaitResult(result=result, recheck_requested=True)

        await self._cancel_pending_tasks(recheck_task)
        return _SubscriptionWaitResult(result=result)

    async def _cancel_pending_tasks(self, *tasks: asyncio.Task | None) -> None:
        pending_tasks = [task for task in tasks if task is not None and not task.done()]
        for task in pending_tasks:
            task.cancel()
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)

    async def _authorize_subscription(
        self, websocket: WebSocket, operation: Operation
    ) -> bool:
        if self.on_subscription_authorize is None:
            return True

        try:
            result = self.on_subscription_authorize(websocket, operation)
            if isawaitable(result):
                result = await result
            return bool(result)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if not isinstance(error, GraphQLError):
                error = GraphQLError(str(error), original_error=error)
            log_error(error, self.logger)
            return False

    async def _send_operation_result(
        self,
        websocket: WebSocket,
        operation: Operation,
        result: ExecutionResult | dict,
    ) -> None:
        if not isinstance(result, dict):
            payload = {}
            if result.data:
                payload["data"] = result.data
            if result.errors:
                for error in result.errors:
                    log_error(error, self.logger)
                payload["errors"] = [
                    self.error_formatter(error, self.debug) for error in result.errors
                ]
        else:
            payload = result

        await websocket.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_NEXT,
                "id": operation.id,
                "payload": payload,
            }
        )

    async def _send_json_if_connected(
        self, websocket: WebSocket, message: dict
    ) -> None:
        if WebSocketState.DISCONNECTED not in (
            websocket.client_state,
            websocket.application_state,
        ):
            await websocket.send_json(message)

    async def _cleanup_operation(
        self,
        websocket: WebSocket,
        operation: Operation,
        state: _OperationState,
        *,
        send_complete: bool,
    ) -> None:
        if state.cleaned:
            return
        state.cleaned = True

        try:
            await self.handle_on_complete(websocket, operation)
            await operation.generator.aclose()
            if send_complete:
                await self._send_json_if_connected(
                    websocket,
                    {
                        "type": GraphQLTransportWSHandler.GQL_COMPLETE,
                        "id": operation.id,
                    },
                )
        except asyncio.CancelledError:
            raise
        except WebSocketDisconnect:
            pass
        except Exception as error:
            if not isinstance(error, GraphQLError):
                error = GraphQLError(str(error), original_error=error)
            log_error(error, self.logger)
        finally:
            state.finished.set()
