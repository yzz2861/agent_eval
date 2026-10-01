from __future__ import annotations

import asyncio
import json
from http import HTTPStatus
from inspect import isawaitable
from typing import TYPE_CHECKING, Any, cast

from graphql import DocumentNode, GraphQLError, MiddlewareManager, get_operation_ast
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
from ...graphql import graphql, handle_graphql_errors, parse_query, validate_data
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
        batch_requests: bool = True,
        max_batch_size: int = 10,
        batch_query_concurrency: int = 10,
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

        `batch_requests`: a `bool` controlling if JSON request bodies containing
        a list of operations are executed as a batch. Defaults to `True`.

        `max_batch_size`: an `int` with maximum number of operations allowed in
        one batch request. Defaults to `10`.

        `batch_query_concurrency`: an `int` with maximum number of query
        operations from a batch that can execute concurrently. Mutations always
        execute serially in their input order. Defaults to `10`.
        """
        super().__init__()

        self.extensions = extensions
        self.middleware = middleware
        self.middleware_manager_class = middleware_manager_class or MiddlewareManager
        self.subscription_handlers: list[SubscriptionHandler] = (
            subscription_handlers or []
        )
        self.batch_requests = batch_requests
        self.max_batch_size = max_batch_size
        self.batch_query_concurrency = batch_query_concurrency

        if max_batch_size < 1:
            raise ValueError("max_batch_size must be greater than 0")
        if batch_query_concurrency < 1:
            raise ValueError("batch_query_concurrency must be greater than 0")

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
            try:
                content_type = request.headers.get("Content-Type", "")
                content_type = content_type.split(";")[0]
                if not self.batch_requests:
                    raise HttpBadRequestError("Batch requests are disabled")
                if content_type != DATA_TYPE_JSON:
                    raise HttpBadRequestError(
                        f"Batch requests must use {DATA_TYPE_JSON}"
                    )
                if not data:
                    raise HttpBadRequestError(
                        "Batch request must contain at least one operation"
                    )
                if len(data) > self.max_batch_size:
                    raise HttpBadRequestError(
                        "Batch request exceeds the maximum of "
                        f"{self.max_batch_size} operations"
                    )
                return await self.execute_batch_graphql_request(request, data)
            except HttpError as error:
                return PlainTextResponse(
                    error.message or error.status,
                    status_code=HTTPStatus.BAD_REQUEST,
                )

        success, result = await self.execute_graphql_query(request, data)
        return await self.create_json_response(request, result, success)

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
        if self.schema is None:
            raise TypeError("schema is not set, call configure method to initialize it")

        if context_value is None:
            context_value = await self.get_context_for_request(request, data)

        extensions = await self.get_extensions_for_request(request, context_value)
        middleware = await self.get_middleware_for_request(request, context_value)

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

    async def execute_batch_graphql_request(
        self,
        request: Request,
        data: list[Any],
    ) -> Response:
        if self.schema is None:
            raise TypeError("schema is not set, call configure method to initialize it")

        prepared_operations = []
        results: list[dict | None] = [None] * len(data)

        for index, operation_data in enumerate(data):
            try:
                validate_data(operation_data)
                query_document = self.parse_batch_operation(operation_data)
                operation = get_operation_ast(
                    query_document,
                    operation_data.get("operationName"),
                )
            except GraphQLError as error:
                _, results[index] = self.handle_batch_graphql_error(error)
                continue

            prepared_operations.append(
                {
                    "index": index,
                    "data": operation_data,
                    "document": query_document if self.query_parser is None else None,
                    "is_mutation": bool(
                        operation and operation.operation.name == "MUTATION"
                    ),
                }
            )

        execute_task = asyncio.create_task(
            self.execute_batch_graphql_queries(request, prepared_operations, results)
        )

        async def wait_for_disconnect() -> None:
            while True:
                message = await request.receive()
                if message["type"] == "http.disconnect":
                    return

        disconnect_task = asyncio.create_task(wait_for_disconnect())

        try:
            done, _ = await asyncio.wait(
                {execute_task, disconnect_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
        except BaseException:
            execute_task.cancel()
            disconnect_task.cancel()
            await asyncio.gather(
                execute_task,
                disconnect_task,
                return_exceptions=True,
            )
            raise

        if disconnect_task.done() and not disconnect_task.exception():
            execute_task.cancel()
            await execute_task
            raise asyncio.CancelledError()

        disconnect_task.cancel()
        await asyncio.gather(disconnect_task, return_exceptions=True)
        await execute_task

        return JSONResponse(cast(list[dict], results))

    async def execute_batch_graphql_queries(
        self,
        request: Request,
        operations: list[dict[str, Any]],
        results: list[dict | None],
    ) -> None:
        query_semaphore = asyncio.Semaphore(self.batch_query_concurrency)
        mutation_lock = asyncio.Lock()
        query_tasks: list[asyncio.Task[None]] = []
        mutation_tasks: list[asyncio.Task[None]] = []

        async def execute_query(operation: dict[str, Any]) -> None:
            async with query_semaphore:
                await execute_batch_operation(operation)

        async def execute_mutation(operation: dict[str, Any]) -> None:
            async with mutation_lock:
                await execute_batch_operation(operation)

        async def execute_batch_operation(operation: dict[str, Any]) -> None:
            _, result = await self.execute_graphql_query(
                request,
                operation["data"],
                query_document=operation["document"],
            )
            results[operation["index"]] = result

        for operation in operations:
            if operation["is_mutation"]:
                mutation_tasks.append(asyncio.create_task(execute_mutation(operation)))
            else:
                query_tasks.append(asyncio.create_task(execute_query(operation)))

        await asyncio.gather(*query_tasks, *mutation_tasks)

    def parse_batch_operation(self, data: dict[str, Any]) -> DocumentNode:
        return parse_query(None, None, data)

    def handle_batch_graphql_error(self, error: GraphQLError) -> GraphQLResult:
        return handle_graphql_errors(
            [error],
            logger=self.logger,
            error_formatter=self.error_formatter,
            debug=self.debug,
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
