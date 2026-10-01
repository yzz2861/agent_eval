import asyncio
from collections.abc import AsyncGenerator
from contextlib import suppress
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
    Operation,
    SubscriptionAuthorizer,
)
from ...utils import get_operation_type
from .base import GraphQLWebsocketHandlerBase


class ClientContext:
    def __init__(self) -> None:
        self.connection_acknowledged: bool = False
        self.connection_init_timeout_task: asyncio.Task | None = None
        self.connection_init_received: bool = False
        self.operations: dict[str, Operation] = {}
        self.operation_tasks: dict[str, asyncio.Task] = {}
        self.recheck_events: dict[str, asyncio.Event] = {}
        self.websocket: WebSocket


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
        subscription_authorizer: SubscriptionAuthorizer | None = None,
        **kwargs,
    ) -> None:
        """Initializes the websocket handler.

        # Optional arguments

        `connection_init_wait_timeout`: a `timedelta` with timeout for new
        websocket connections before first message is received. Defaults to
        60 seconds.

        `subscription_authorizer`: a `SubscriptionAuthorizer` callback used
        to recheck if individual subscriptions are still authorized to receive
        events. It's called before each event is sent to the client and each
        time the application requests a recheck through the
        `request_authorization_recheck` method. Defaults to `None`.
        """
        super().__init__(*args, **kwargs)

        self.connection_init_wait_timeout = connection_init_wait_timeout
        self.subscription_authorizer = subscription_authorizer
        self._client_contexts: dict[WebSocket, ClientContext] = {}

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

        client_context = ClientContext()
        self._client_contexts[websocket] = client_context
        timeout_handler = self.handle_connection_init_timeout(websocket, client_context)
        client_context.connection_init_timeout_task = asyncio.create_task(
            timeout_handler
        )

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
            self._client_contexts.pop(websocket, None)
            for operation_id in list(client_context.operations.keys()):
                await self.stop_websocket_operation(
                    websocket, operation_id, client_context
                )

            try:
                if self.on_disconnect:
                    result = self.on_disconnect(websocket)
                    if result and isawaitable(result):
                        await result
            except Exception as error:
                if not isinstance(error, GraphQLError):
                    error = GraphQLError(str(error), original_error=error)
                log_error(error, self.logger)

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
            )

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

            # store Task in the operation_tasks list so that we can cancel such task
            # if client sends the "complete" message
            client_context.operation_tasks[operation_id] = asyncio.ensure_future(
                self.observe_async_results(
                    websocket,
                    results_producer,
                    operation_id,
                    client_context,
                    is_subscription=operation_type == OperationType.SUBSCRIPTION,
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
        operation = client_context.operations.pop(operation_id, None)
        if operation is None:
            # Operation was already stopped by a concurrent code path
            # (results observer, connection close or earlier "complete"
            # message). Its cleanup is handled there, exactly once.
            return

        await self.handle_on_complete(websocket, operation)

        client_context.recheck_events.pop(operation_id, None)
        otask = client_context.operation_tasks.pop(operation_id, None)
        if otask is not None:
            otask.cancel()
            with suppress(asyncio.CancelledError):
                await otask
        await operation.generator.aclose()

    def request_authorization_recheck(
        self,
        websocket: WebSocket,
        operation_id: str | None = None,
    ) -> None:
        """Requests an authorization recheck for active subscriptions.

        Schedules a `subscription_authorizer` recheck for a single operation
        (when `operation_id` is given) or for all active subscriptions of
        given websocket connection. Subscriptions that are no longer
        authorized are terminated with an `error` message, without affecting
        other operations on the same connection.

        Should be called from the event loop running the websocket handler.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        # Optional arguments

        `operation_id`: a `str` with id of operation to recheck. When not
        set, all active subscriptions of the connection are rechecked.
        """
        client_context = self._client_contexts.get(websocket)
        if client_context is None:
            return

        if operation_id is not None:
            recheck_event = client_context.recheck_events.get(operation_id)
            if recheck_event is not None:
                recheck_event.set()
        else:
            for recheck_event in client_context.recheck_events.values():
                recheck_event.set()

    async def check_subscription_authorization(
        self,
        websocket: WebSocket,
        operation_id: str,
        client_context: ClientContext,
    ) -> GraphQLError | None:
        """Evaluates `subscription_authorizer` for a single operation.

        Returns `None` if the operation is still authorized (or there's no
        authorizer to check against) and a `GraphQLError` describing the
        denial otherwise.

        # Required arguments

        `websocket`: the `WebSocket` instance from Starlette or FastAPI.

        `operation_id`: a `str` with id of operation to authorize.

        `client_context`: a `ClientContext` object with extra state of current
        websocket connection.
        """
        operation = client_context.operations.get(operation_id)
        if operation is None or self.subscription_authorizer is None:
            return None

        try:
            result = self.subscription_authorizer(websocket, operation)
            if isawaitable(result):
                result = await result
        except Exception as error:
            if not isinstance(error, GraphQLError):
                error = GraphQLError(str(error), original_error=error)
            log_error(error, self.logger)
            return error

        if not result:
            return GraphQLError("Subscription is not authorized.")

        return None

    async def observe_async_results(
        self,
        websocket: WebSocket,
        results_producer: AsyncGenerator,
        operation_id: str,
        client_context: ClientContext,
        is_subscription: bool = False,
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

        # Optional arguments

        `is_subscription`: a `bool` controlling if operation should be
        rechecked against the `subscription_authorizer`. Defaults to
        `False`.
        """
        recheck_event: asyncio.Event | None = None
        if is_subscription and self.subscription_authorizer is not None:
            recheck_event = asyncio.Event()
            client_context.recheck_events[operation_id] = recheck_event

        anext_task: asyncio.Task | None = None
        recheck_task: asyncio.Task | None = None
        auth_error: GraphQLError | None = None
        try:
            while True:
                if recheck_event is not None:
                    auth_error = await self.check_subscription_authorization(
                        websocket, operation_id, client_context
                    )
                    if auth_error is not None:
                        break

                # At most one event is pulled from the results producer ahead
                # of its delivery, so events don't pile up on this subscription
                # while an asynchronous authorization recheck is in progress.
                if anext_task is None:
                    anext_task = asyncio.ensure_future(results_producer.__anext__())

                if recheck_event is not None:
                    recheck_task = asyncio.ensure_future(recheck_event.wait())
                    done, _ = await asyncio.wait(
                        (anext_task, recheck_task),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if recheck_task in done:
                        # Authorization recheck was requested by the
                        # application. Keep the pending event pull and go back
                        # to the recheck at the top of the loop.
                        recheck_event.clear()
                        recheck_task = None
                        continue
                    recheck_task.cancel()
                    recheck_task = None
                    try:
                        result = anext_task.result()
                    except StopAsyncIteration:
                        break
                else:
                    try:
                        result = await anext_task
                    except StopAsyncIteration:
                        break

                anext_task = None

                if not isinstance(result, dict):
                    payload = {}
                    if result.data:
                        payload["data"] = result.data
                    if result.errors:
                        for error in result.errors:
                            log_error(error, self.logger)
                        payload["errors"] = [
                            self.error_formatter(error, self.debug)
                            for error in result.errors
                        ]
                else:
                    payload = result

                await websocket.send_json(
                    {
                        "type": GraphQLTransportWSHandler.GQL_NEXT,
                        "id": operation_id,
                        "payload": payload,
                    }
                )
        except asyncio.CancelledError:
            # if asyncio Task is cancelled then CancelledError
            # is thrown in the coroutine. Pending event pulls and recheck
            # waits have to be cancelled too, so the results producer is not
            # running when it's closed by the stopping code path.
            client_context.recheck_events.pop(operation_id, None)
            for pending_task in (anext_task, recheck_task):
                if pending_task is not None and not pending_task.done():
                    pending_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await pending_task
            raise
        except Exception as error:
            if not isinstance(error, GraphQLError):
                error = GraphQLError(str(error), original_error=error)
            log_error(error, self.logger)
            payload = {"errors": [self.error_formatter(error, self.debug)]}

            await websocket.send_json(
                {
                    "type": GraphQLTransportWSHandler.GQL_NEXT,
                    "id": operation_id,
                    "payload": payload,
                }
            )

        if anext_task is not None and not anext_task.done():
            anext_task.cancel()
            with suppress(asyncio.CancelledError):
                await anext_task

        # Cleanup is owned by whoever removes the operation from the client
        # context first, so the source generator and the recheck event are
        # cleaned up exactly once even if a denial, an error, a client
        # "complete" message and a connection close happen at the same time.
        operation = client_context.operations.pop(operation_id, None)
        client_context.operation_tasks.pop(operation_id, None)
        client_context.recheck_events.pop(operation_id, None)
        if operation is None:
            return

        await self.handle_on_complete(websocket, operation)
        await operation.generator.aclose()

        if WebSocketState.DISCONNECTED not in (
            websocket.client_state,
            websocket.application_state,
        ):
            if auth_error is not None:
                await websocket.send_json(
                    {
                        "type": GraphQLTransportWSHandler.GQL_ERROR,
                        "id": operation_id,
                        "payload": [self.error_formatter(auth_error, self.debug)],
                    }
                )
            else:
                await websocket.send_json(
                    {
                        "type": GraphQLTransportWSHandler.GQL_COMPLETE,
                        "id": operation_id,
                    }
                )
