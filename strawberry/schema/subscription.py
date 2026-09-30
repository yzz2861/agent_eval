from __future__ import annotations

import contextlib
import inspect
import sys
from typing import TYPE_CHECKING, Any, Protocol

from graphql import ExecutionResult as OriginalExecutionResult
from graphql import GraphQLError

from strawberry.execution import optimized_is_awaitable
from strawberry.utils.await_maybe import AwaitableOrValue, await_maybe

if TYPE_CHECKING:
    from collections.abc import AsyncIterable, AsyncIterator, Callable

    from graphql.execution.middleware import MiddlewareManager

    from strawberry.types.execution import ExecutionContext


class _SyncSubscriptionEventContextManager(Protocol):
    def __enter__(self) -> Any: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _AsyncSubscriptionEventContextManager(Protocol):
    async def __aenter__(self) -> Any: ...

    async def __aexit__(self, *args: object) -> bool | None: ...


SubscriptionEventContextManager = (
    _SyncSubscriptionEventContextManager | _AsyncSubscriptionEventContextManager
)


class SubscriptionEventContextGetter(Protocol):
    def __call__(
        self, connection_context: Any, event: Any
    ) -> AwaitableOrValue[SubscriptionEventContextManager]: ...


class SubscriptionSourceError(OriginalExecutionResult):
    """An error returned while establishing the subscription source stream."""


class ActiveSubscriptionEvent:
    """A completed GraphQL event with its per-event context still open."""

    __slots__ = ("_closed", "_exit_stack", "result")

    def __init__(
        self,
        result: OriginalExecutionResult,
        exit_stack: contextlib.AsyncExitStack,
    ) -> None:
        self.result = result
        self._closed = False
        self._exit_stack = exit_stack

    async def __aenter__(self) -> OriginalExecutionResult:
        return self.result

    async def __aexit__(self, *args: object) -> bool | None:
        if self._closed:
            return None

        self._closed = True
        if args == (None, None, None) and self.result.errors:
            error = self.result.errors[0]
            args = (type(error), error, error.__traceback__)
        return await self._exit_stack.__aexit__(*args)

    async def aclose(self) -> None:
        if not self._closed:
            await self.__aexit__(None, None, None)


def _coerce_error(error: Exception) -> GraphQLError:
    if isinstance(error, GraphQLError):
        return error
    return GraphQLError(str(error), original_error=error)


def _supported_kwargs(
    function: Callable[..., Any], kwargs: dict[str, Any]
) -> dict[str, Any]:
    signature = inspect.signature(function)
    if any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ):
        return kwargs
    return {key: value for key, value in kwargs.items() if key in signature.parameters}


def _has_method(value: Any, name: str) -> bool:
    return callable(getattr(type(value), name, None))


async def _enter_context_manager(
    exit_stack: contextlib.AsyncExitStack, context_manager: Any
) -> Any:
    if _has_method(context_manager, "__aenter__"):
        return await exit_stack.enter_async_context(context_manager)
    if _has_method(context_manager, "__enter__"):
        return exit_stack.enter_context(context_manager)

    msg = (
        "Subscription event context getter must return a synchronous or "
        "asynchronous context manager."
    )
    raise TypeError(msg)


async def run_subscription(
    *,
    schema: Any,
    execution_context: ExecutionContext,
    middleware_manager: MiddlewareManager,
    operation_extensions: dict[str, Any] | None,
    is_gql_32: bool,
    create_source_event_stream: Callable[..., Any],
    execute_subscription_event: Callable[..., Any],
    execution_context_class: type[Any] | None,
    event_context_getter: Callable[[Any, Any], Any],
) -> AsyncIterator[OriginalExecutionResult | ActiveSubscriptionEvent]:
    source_kwargs: dict[str, Any] = {
        "root_value": execution_context.root_value,
        "variable_values": execution_context.variables,
        "operation_name": execution_context.operation_name,
        "context_value": execution_context.context,
    }
    event_kwargs: dict[str, Any] = {
        "execution_context_class": execution_context_class,
        "is_awaitable": optimized_is_awaitable,
    }
    if not is_gql_32:
        source_kwargs.update(
            {
                "middleware": middleware_manager,
                "operation_extensions": operation_extensions,
                "execution_context_class": execution_context_class,
            }
        )
        event_kwargs.update(
            {
                "middleware": middleware_manager,
                "operation_extensions": operation_extensions,
            }
        )

    source_supported_kwargs = _supported_kwargs(
        create_source_event_stream, source_kwargs
    )
    event_supported_kwargs = _supported_kwargs(execute_subscription_event, event_kwargs)

    try:
        result_or_stream = await await_maybe(
            create_source_event_stream(
                schema,
                execution_context.graphql_document,
                **source_supported_kwargs,
            )
        )
    except Exception as exc:  # noqa: BLE001
        yield SubscriptionSourceError(data=None, errors=[_coerce_error(exc)])
        return

    if isinstance(result_or_stream, OriginalExecutionResult):
        yield SubscriptionSourceError(data=None, errors=list(result_or_stream.errors))
        return

    source_stream: AsyncIterable[Any] = result_or_stream
    connection_context = execution_context.context

    async with contextlib.aclosing(source_stream) as events:
        async for event in events:
            try:
                context_manager = await await_maybe(
                    event_context_getter(connection_context, event)
                )
            except Exception as exc:  # noqa: BLE001
                yield OriginalExecutionResult(data=None, errors=[_coerce_error(exc)])
                continue

            exit_stack = contextlib.AsyncExitStack()
            await exit_stack.__aenter__()

            try:
                event_context = await _enter_context_manager(
                    exit_stack, context_manager
                )
            except Exception as exc:  # noqa: BLE001
                await exit_stack.aclose()
                yield OriginalExecutionResult(data=None, errors=[_coerce_error(exc)])
                continue

            execution_context.context = event_context
            try:
                try:
                    result = await await_maybe(
                        execute_subscription_event(
                            schema,
                            execution_context.graphql_document,
                            root_value=event,
                            context_value=event_context,
                            variable_values=execution_context.variables,
                            operation_name=execution_context.operation_name,
                            **event_supported_kwargs,
                        )
                    )
                except Exception:
                    # Unexpected execution faults terminate the subscription,
                    # matching graphql-core's default mapping; give the context
                    # the exception so transactions can roll back.
                    await exit_stack.__aexit__(*sys.exc_info())
                    raise
                except BaseException:
                    await exit_stack.aclose()
                    raise

                active_event = ActiveSubscriptionEvent(result, exit_stack)
                try:
                    yield active_event
                finally:
                    await active_event.aclose()
            finally:
                execution_context.context = connection_context
