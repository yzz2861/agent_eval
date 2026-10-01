from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from http import HTTPStatus
from inspect import isawaitable
from typing import TYPE_CHECKING, Any, cast

from graphql import (
    DocumentNode,
    GraphQLError,
    MiddlewareManager,
    OperationType,
    get_operation_ast,
)
from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.types import Receive, Scope, Send

from ...constants import (
    DATA_TYPE_JSON,
    DATA_TYPE_MULTIPART,
)
from ...exceptions import HttpBadRequestError, HttpError
from ...explorer import Explorer
from ...file_uploads import combine_multipart_data
from ...graphql import (
    graphql,
    parse_query,
    validate_data,
    validate_operation_is_not_subscription,
)
from ...logger import log_error
from ...types import (
    ContextValue,
    ExtensionList,
    Extensions,
    GraphQLResult,
    MiddlewareList,
    Middlewares,
)
from .base import GraphQLHttpHandlerBase

if TYPE_CHECKING:
    from ...subscription_handlers import SubscriptionHandler


@dataclass
class BatchOperation:
    """Single operation from a batched GraphQL request, prepared for execution."""

    data: Any
    context_value: Any = None
    query_document: DocumentNode | None = None
    is_mutation: bool = False
    error: dict | None = None


class GraphQLHTTPHandler(GraphQLHttpHandlerBase):
    """Default ASGI handler for HTTP requests.

    Supports the `Query` and `Mutation` operations. Can also handle
    subscriptions when configured with `subscription_handlers`.
    """

    def __init__(
        self,
        extensions: Extensions | None = None,
        middleware: Middlewares | None = None,
        middleware_manager_class: type[MiddlewareManager] | None = None,
        subscription_handlers: list[SubscriptionHandler] | None = None,
        batching_enabled: bool = False,
        max_batch_size: int = 10,
        batch_query_concurrency: int = 5,
    ) -> None:
        """Initializes the HTTP handler.

        # Optional arguments

        `extensions`: an `Extensions` list or callable returning a
        list of extensions server should use during query execution. Defaults
        to no extensions.

        `middleware`: a `Middlewares` list or callable returning a list of
        middlewares server should use during query execution. Defaults to no
        middlewares.

        `middleware_manager_class`: a `MiddlewareManager` type or subclass to
        use for combining provided middlewares into single wrapper for resolvers
        by the server. Defaults to `graphql.MiddlewareManager`. Is only used
        if `extensions` or `middleware` options are set.

        `subscription_handlers`: a list of `SubscriptionHandler` instances to
        handle GraphQL subscriptions. Handlers are tried in order; the first
        handler whose `supports()` method returns `True` handles the request.

        `batching_enabled`: a `bool` controlling if the server should accept
        JSON batch requests (POST body with an array of GraphQL operations).
        Defaults to `False`.

        `max_batch_size`: an `int` with maximum number of operations allowed
        in a single batch request. Batches that are empty or exceed this limit
        are rejected before any operation is executed. Defaults to `10`.

        `batch_query_concurrency`: an `int` with maximum number of `query`
        operations from a single batch that are executed concurrently.
        `mutation` operations are always executed serially, in the order they
        appear in the batch. Defaults to `5`.
        """
        super().__init__()

        self.extensions = extensions
        self.middleware = middleware
        self.middleware_manager_class = middleware_manager_class or MiddlewareManager
        self.subscription_handlers: list[SubscriptionHandler] = (
            subscription_handlers or []
        )

        if max_batch_size < 1:
            raise ValueError("max_batch_size must be at least 1")
        if batch_query_concurrency < 1:
            raise ValueError("batch_query_concurrency must be at least 1")

        self.batching_enabled = batching_enabled
        self.max_batch_size = max_batch_size
        self.batch_query_concurrency = batch_query_concurrency

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        """An entrypoint for the GraphQL HTTP handler.

        This method is called by the Ariadne ASGI GraphQL application to execute
        queries done using the HTTP protocol.

        It creates the `starlette.requests.Request` instance, calls
        `handle_request` method with it, then sends the response back to the client.

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
        request = Request(scope=scope, receive=receive)
        response = await self.handle_request(request)
        await response(scope, receive, send)

    async def handle_request_override(self, request: Request) -> Response | None:
        """Override the default request handling logic in subclasses.
        Is called in the `handle_request` method before the default logic.
        If None is returned, the default logic is executed.

         # Required arguments:
         `request`: the `Request` instance from Starlette or FastAPI.
        """
        return None

    async def handle_request(self, request: Request) -> Response:
        """Handle GraphQL request and return a response for the client.

        Is called by the `handle` method and `handle_request` method of the
        ASGI GraphQL application.

        Handles three HTTP methods:

        `GET`: returns GraphQL explorer or 405 error response if explorer or
        introspection is disabled.

        `POST`: executes the GraphQL query from either `application/json` or
        `multipart/form-data` requests.

        `OPTIONS`: returns supported HTTP methods.

        Returns Starlette's `Response` instance, which is also works in FastAPI.

        # Required arguments:

        `request`: the `Request` instance from Starlette or FastAPI.
        """
        response = await self.handle_request_override(request)
        if response is not None:
            return response

        if request.method == "GET":
            if self.execute_get_queries and request.query_params.get("query"):
                return await self.graphql_http_server(request)
            if self.introspection and self.explorer:
                # only render explorer when introspection is enabled
                return await self.render_explorer(request, self.explorer)

        if request.method == "POST":
            return await self.graphql_http_server(request)

        return self.handle_not_allowed_method(request)

    async def render_explorer(self, request: Request, explorer: Explorer) -> Response:
        """Return an HTML response with GraphQL explorer.

        # Required arguments:

        `request`: the `Request` instance from Starlette or FastAPI.

        `explorer`: an `Explorer` instance that implements the
        `html(request: Request)` method which returns either the `str` with HTML
        or `None`. If the explorer returns `None`, `405` method not allowed response
        is returned instead.
        """
        explorer_html = explorer.html(request)
        if isawaitable(explorer_html):
            explorer_html = await explorer_html
        if explorer_html:
            return HTMLResponse(explorer_html)

        return self.handle_not_allowed_method(request)

    async def graphql_http_server(self, request: Request) -> Response:
        """Handles the HTTP request with GraphQL query.

        Extracts GraphQL query data from requests and then executes it using
        the `execute_graphql_query` method. If subscription handlers are
        configured and one of them supports the request, delegates to that
        handler instead.

        Returns the JSON response from Starlette, or a response from a
        subscription handler.

        If the request's data was invalid or missing, a plaintext response with an
        error message and 400 status code is returned instead.

        # Required arguments:

        `request`: the `Request` instance from Starlette or FastAPI.
        """
        try:
            data = await self.extract_data_from_request(request)
        except HttpError as error:
            return PlainTextResponse(
                error.message or error.status, status_code=HTTPStatus.BAD_REQUEST
            )

        # Check if any subscription handler can handle this request
        if self.subscription_handlers and isinstance(data, dict) and self.schema:
            for handler in self.subscription_handlers:
                if handler.supports(request, data):
                    context_value = await self.get_context_for_request(request, data)
                    return await handler.handle(
                        request,
                        data,
                        schema=self.schema,
                        context_value=context_value,
                        root_value=self.root_value,
                        query_parser=self.query_parser,
                        query_validator=self.query_validator,
                        validation_rules=self.validation_rules,
                        debug=self.debug,
                        introspection=self.introspection,
                        logger=self.logger,
                        error_formatter=self.error_formatter,
                    )

        if isinstance(data, list):
            return await self.graphql_http_server_batch(request, data)

        success, result = await self.execute_graphql_query(request, data)
        return await self.create_json_response(request, result, success)

    async def graphql_http_server_batch(self, request: Request, data: list) -> Response:
        """Handles the HTTP request with a batch of GraphQL operations.

        Rejects the request with a 400 response before executing anything if
        batching is disabled, the batch is empty, or it exceeds the
        `max_batch_size` limit.

        Otherwise executes every operation in the batch and returns a JSON
        response with an array of results, one per operation, in the same
        order as operations appeared in the request.

        If the client disconnects while the batch is being executed, remaining
        operations are cancelled and their contexts are cleaned up.

        # Required arguments:

        `request`: the `Request` instance from Starlette or FastAPI.

        `data`: a `list` with GraphQL operations data.
        """
        if not self.batching_enabled:
            return PlainTextResponse(
                "Batch requests are not enabled on this server.",
                status_code=HTTPStatus.BAD_REQUEST,
            )
        if not data:
            return PlainTextResponse(
                "Batch request must contain at least one operation.",
                status_code=HTTPStatus.BAD_REQUEST,
            )
        if len(data) > self.max_batch_size:
            return PlainTextResponse(
                f"Batch of {len(data)} operations exceeds the maximum "
                f"allowed batch size of {self.max_batch_size}.",
                status_code=HTTPStatus.BAD_REQUEST,
            )

        execution_task = asyncio.ensure_future(self.execute_batch(request, data))
        disconnect_task = asyncio.ensure_future(
            self.cancel_batch_on_disconnect(request, execution_task)
        )
        try:
            results = await execution_task
        finally:
            disconnect_task.cancel()

        return JSONResponse(results)

    async def cancel_batch_on_disconnect(
        self, request: Request, execution_task: asyncio.Task[list]
    ) -> None:
        """Cancels the batch execution task when client disconnects.

        Polls the `request.is_disconnected()` until either the client
        disconnects (cancelling the `execution_task`) or the task
        completes on its own.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `execution_task`: an `asyncio.Task` running the batch execution.
        """
        while not execution_task.done():
            if await request.is_disconnected():
                execution_task.cancel()
                return
            await asyncio.sleep(0.1)

    async def execute_batch(self, request: Request, data: list) -> list:
        """Executes a batch of GraphQL operations.

        Every operation is validated and gets its own context value, extensions
        and middleware, so no state (eg. DataLoaders or extension instances) is
        shared between operations through the shared `request` object.

        `query` operations are executed concurrently, with concurrency
        limited by the `batch_query_concurrency` option. `mutation`
        operations are executed serially, in the order they appear in the
        batch. Operations that fail validation or use the `subscription`
        operation type produce individual error results without affecting
        other operations in the batch.

        Returns a `list` with one result per operation, in the same order
        as operations appeared in the batch.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `data`: a `list` with GraphQL operations data.
        """
        semaphore = asyncio.Semaphore(self.batch_query_concurrency)
        results: list[dict | None] = [None] * len(data)
        query_tasks: list[tuple[int, asyncio.Task[dict]]] = []

        try:
            for index, operation_data in enumerate(data):
                operation = await self.prepare_batch_operation(request, operation_data)
                if operation.error is not None:
                    results[index] = operation.error
                elif operation.is_mutation:
                    results[index] = await self.execute_batch_operation(
                        request, operation
                    )
                else:
                    task = asyncio.ensure_future(
                        self.execute_batch_query(semaphore, request, operation)
                    )
                    query_tasks.append((index, task))

            for index, task in query_tasks:
                results[index] = await task
        finally:
            pending_tasks = [task for _, task in query_tasks if not task.done()]
            for task in pending_tasks:
                task.cancel()
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)

        return cast(list, results)

    async def prepare_batch_operation(
        self, request: Request, data: Any
    ) -> BatchOperation:
        """Validates and prepares a single operation from a batch.

        Validates the operation data, creates its context value and parses its
        GraphQL query. Operations that fail validation, can't be parsed, or
        use the `subscription` operation type are returned with an error
        result set instead.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `data`: a GraphQL operation data from the batch.
        """
        try:
            validate_data(data)
        except GraphQLError as error:
            return BatchOperation(data=data, error=self.format_batch_error(error))

        context_value = await self.get_context_for_request(request, data)

        try:
            query_document = parse_query(context_value, self.query_parser, data)
        except GraphQLError as error:
            return BatchOperation(data=data, error=self.format_batch_error(error))

        operation_name = data.get("operationName")
        operation_ast = get_operation_ast(query_document, operation_name)

        if (
            operation_ast is not None
            and operation_ast.operation == OperationType.SUBSCRIPTION
        ):
            try:
                validate_operation_is_not_subscription(query_document, operation_name)
            except GraphQLError as error:
                return BatchOperation(data=data, error=self.format_batch_error(error))

        return BatchOperation(
            data=data,
            context_value=context_value,
            query_document=query_document,
            is_mutation=(
                operation_ast is not None
                and operation_ast.operation == OperationType.MUTATION
            ),
        )

    def format_batch_error(self, error: GraphQLError) -> dict:
        """Formats a GraphQL error into a batch operation result.

        # Required arguments

        `error`: a `GraphQLError` instance to format.
        """
        log_error(error, self.logger)
        return {"errors": [self.error_formatter(error, self.debug)]}

    async def execute_batch_operation(
        self, request: Request, operation: BatchOperation
    ) -> dict:
        """Executes a single prepared operation from a batch.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `operation`: a `BatchOperation` prepared by the
        `prepare_batch_operation` method.
        """
        _, result = await self.execute_graphql_query(
            request,
            operation.data,
            context_value=operation.context_value,
            query_document=operation.query_document,
        )
        return result

    async def execute_batch_query(
        self,
        semaphore: asyncio.Semaphore,
        request: Request,
        operation: BatchOperation,
    ) -> dict:
        """Executes a `query` operation from a batch.

        Uses the `semaphore` to limit the number of `query` operations
        executed concurrently.

        # Required arguments

        `semaphore`: an `asyncio.Semaphore` limiting queries concurrency.

        `request`: the `Request` instance from Starlette or FastAPI.

        `operation`: a `BatchOperation` prepared by the
        `prepare_batch_operation` method.
        """
        async with semaphore:
            return await self.execute_batch_operation(request, operation)

    async def extract_data_from_request(self, request: Request) -> Any:
        """Extracts GraphQL request data from request.

        Returns GraphQL query data that was not yet validated.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.
        """
        content_type = request.headers.get("Content-Type", "")
        content_type = content_type.split(";")[0]

        if content_type == DATA_TYPE_JSON:
            return await self.extract_data_from_json_request(request)
        if content_type == DATA_TYPE_MULTIPART:
            return await self.extract_data_from_multipart_request(request)
        if (
            request.method == "GET"
            and self.execute_get_queries
            and request.query_params.get("query")
        ):
            return self.extract_data_from_get_request(request)

        raise HttpBadRequestError(
            f"Posted content must be of type {DATA_TYPE_JSON} or {DATA_TYPE_MULTIPART}"
        )

    async def extract_data_from_json_request(self, request: Request) -> Any:
        """Extracts GraphQL data from JSON request.

        Returns GraphQL query data that was not yet validated.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.
        """
        try:
            return await request.json()
        except (TypeError, ValueError) as ex:
            raise HttpBadRequestError("Request body is not a valid JSON") from ex

    async def extract_data_from_multipart_request(
        self, request: Request
    ) -> dict | list:
        """Extracts GraphQL data from `multipart/form-data` request.

        Returns an unvalidated `dict` or `list` with GraphQL query data.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.
        """
        try:
            request_body = await request.form()
        except ValueError as ex:
            raise HttpBadRequestError(
                "Request body is not a valid multipart/form-data"
            ) from ex

        try:
            operations = json.loads(cast(Any, request_body.get("operations")))
        except (TypeError, ValueError) as ex:
            raise HttpBadRequestError(
                "Request 'operations' multipart field is not a valid JSON"
            ) from ex
        try:
            files_map = json.loads(cast(Any, request_body.get("map")))
        except (TypeError, ValueError) as ex:
            raise HttpBadRequestError(
                "Request 'map' multipart field is not a valid JSON"
            ) from ex

        request_files = {
            key: value
            for key, value in request_body.items()
            if isinstance(value, UploadFile)
        }

        return combine_multipart_data(operations, files_map, request_files)

    def extract_data_from_get_request(self, request: Request) -> dict:
        """Extracts GraphQL data from GET request's querystring.

        Returns a `dict` with GraphQL query data that was not yet validated.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.
        """
        query = request.query_params["query"].strip()
        operation_name = request.query_params.get("operationName", "").strip()
        variables = request.query_params.get("variables", "").strip()

        clean_variables = None

        if variables:
            try:
                clean_variables = json.loads(variables)
            except (TypeError, ValueError) as ex:
                raise HttpBadRequestError(
                    "Variables query arg is not a valid JSON"
                ) from ex

        return {
            "query": query,
            "operationName": operation_name or None,
            "variables": clean_variables,
        }

    async def execute_graphql_query(
        self,
        request: Any,
        data: Any,
        *,
        context_value: Any = None,
        query_document: DocumentNode | None = None,
    ) -> GraphQLResult:
        """Executes GraphQL query from `request` and returns `GraphQLResult`.

        Creates GraphQL `ContextValue`, initializes extensions and middlewares,
        then runs the `graphql` function from Ariadne to execute the query.

        # Requires arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `data`: a GraphQL data.

        # Optional arguments

        `context_value`: a `ContextValue` for this request.

        `query_document`: an already parsed GraphQL query. Setting this option
        will prevent `graphql` from parsing `query` string from `data` second time.
        """
        if context_value is None:
            context_value = await self.get_context_for_request(request, data)

        extensions = await self.get_extensions_for_request(request, context_value)
        middleware = await self.get_middleware_for_request(request, context_value)

        if self.schema is None:
            raise TypeError("schema is not set, call configure method to initialize it")

        if isinstance(request, Request):
            require_query = request.method == "GET"
        else:
            require_query = False

        return await graphql(
            self.schema,
            data,
            context_value=context_value,
            root_value=self.root_value,
            query_parser=self.query_parser,
            query_validator=self.query_validator,
            query_document=query_document,
            validation_rules=self.validation_rules,
            require_query=require_query,
            debug=self.debug,
            introspection=self.introspection,
            logger=self.logger,
            error_formatter=self.error_formatter,
            extensions=extensions,
            middleware=middleware,
            middleware_manager_class=self.middleware_manager_class,
            execution_context_class=self.execution_context_class,
        )

    async def get_extensions_for_request(
        self, request: Any, context: ContextValue | None
    ) -> ExtensionList:
        """Returns extensions to use when handling the GraphQL request.

        Returns `ExtensionList`, a list of extensions to use or `None`.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `context`: a `ContextValue` for this request.
        """
        if callable(self.extensions):
            extensions = self.extensions(request, context)  # ty: ignore
            if isawaitable(extensions):
                extensions = await extensions
            return cast(ExtensionList, extensions)
        return self.extensions

    async def get_middleware_for_request(
        self, request: Any, context: ContextValue | None
    ) -> MiddlewareList:
        """Returns GraphQL middlewares to use when handling the GraphQL request.

        Returns `MiddlewareList`, a list of middlewares to use or `None`.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `context`: a `ContextValue` for this request.
        """
        middleware = self.middleware
        if callable(middleware):
            middleware = middleware(request, context)  # ty: ignore
            if isawaitable(middleware):
                middleware = await middleware
        if middleware:
            return cast(MiddlewareList, middleware)
        return None

    async def create_json_response(
        self,
        request: Request,
        result: dict,
        success: bool,
    ) -> Response:
        """Creates JSON response from GraphQL's query result.

        Returns Starlette's `JSONResponse` instance that's also compatible
        with FastAPI. If `success` is `True` or the result contains non-null
        'data' (indicating execution was attempted and produced results),
        response's status code is 200. Status code 400 is used otherwise.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.

        `result`: a JSON-serializable `dict` with query result.

        `success`: a `bool` specifying if query execution was successful.
        """
        if success or result.get("data") is not None:
            status_code = HTTPStatus.OK
        else:
            status_code = HTTPStatus.BAD_REQUEST
        return JSONResponse(result, status_code=status_code)

    def handle_not_allowed_method(self, request: Request):
        """Handles request for unsupported HTTP method.

        Returns 200 response for `OPTIONS` request and 405 response for other
        methods. All responses have empty body.

        # Required arguments

        `request`: the `Request` instance from Starlette or FastAPI.
        """
        allowed_methods = ["OPTIONS", "POST"]
        if self.introspection:
            allowed_methods.append("GET")
        allow_header = {"Allow": ", ".join(allowed_methods)}

        if request.method == "OPTIONS":
            return Response(headers=allow_header)

        return Response(status_code=HTTPStatus.METHOD_NOT_ALLOWED, headers=allow_header)
