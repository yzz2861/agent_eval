from collections.abc import Awaitable
from contextlib import contextmanager
from inspect import isawaitable
from typing import Any

from graphql import GraphQLError, OperationType
from graphql.execution import MiddlewareManager

from .types import (
    ContextValue,
    Extension,
    ExtensionList,
    MiddlewareList,
    Transaction,
    TransactionFactory,
)


class ExtensionManager:
    """Container and runner for extensions and middleware, used by the GraphQL servers.

    # Attributes

    `context`: the `ContextValue` of type specific to the server.

    `extensions`: a `tuple` with instances of initialized extensions.

    `extensions_reversed`: a `tuple` created from reversing `extensions`.
    """

    __slots__ = ("context", "extensions", "extensions_reversed")

    def __init__(
        self,
        extensions: ExtensionList | None = None,
        context: ContextValue | None = None,
    ) -> None:
        """Initializes extensions and stores them with context on instance.

        # Optional arguments

        `extensions`: a `list` of `Extension` types to initialize.

        `context`: the `ContextValue` of type specific to the server.
        """
        self.context = context

        if extensions:
            self.extensions = tuple(ext() for ext in extensions)
            self.extensions_reversed = tuple(reversed(self.extensions))
        else:
            self.extensions_reversed = self.extensions = tuple()

    def as_middleware_manager(
        self,
        middleware: MiddlewareList = None,
        manager_class: type[MiddlewareManager] | None = None,
    ) -> MiddlewareManager | None:
        """Creates middleware manager instance combining middleware and extensions.

        Returns instance of the type passed in `manager_class` argument
        or `MiddlewareManager` that query executor then uses.

        # Optional arguments

        `middleware`: a `list` of `Middleware` instances

        `manager_class` a `type` of middleware manager to use. `MiddlewareManager`
        is used if this argument is passed `None` or omitted.
        """
        if not middleware and not self.extensions:
            return None

        middleware = middleware or []
        if manager_class:
            return manager_class(*middleware, *self.extensions)

        return MiddlewareManager(*middleware, *self.extensions)

    @contextmanager
    def request(self):
        """A context manager that should wrap request processing.

        Runs `request_started` hook at beginning and `request_finished` at
        the end of request processing, enabling APM extensions like ApolloTracing.
        """
        for ext in self.extensions:
            ext.request_started(self.context)
        try:
            yield
        finally:
            for ext in self.extensions_reversed:
                ext.request_finished(self.context)

    def has_errors(self, errors: list[GraphQLError]):
        """Propagates GraphQL errors returned by GraphQL server to extensions.

        Should be called only when there are errors.
        """
        for ext in self.extensions:
            ext.has_errors(errors, self.context)

    def operation_started(self, operation_type: OperationType | None) -> None:
        """Runs `operation_started` hook for all extensions.

        Should be called after query's validation, before its execution.
        Raises `RuntimeError` if a hook returns an awaitable.
        """
        for ext in self.extensions:
            result = ext.operation_started(self.context, operation_type)
            if isawaitable(result):
                _close_awaitable(result)
                raise RuntimeError(
                    "Extensions can't return awaitables from "
                    "'operation_started' hook in synchronous query executor."
                )

    async def aoperation_started(self, operation_type: OperationType | None) -> None:
        """Asynchronously runs `operation_started` hook for all extensions.

        Should be called after query's validation, before its execution.
        Awaits awaitables returned from hooks.
        """
        for ext in self.extensions:
            result = ext.operation_started(self.context, operation_type)
            if isawaitable(result):
                await result

    def operation_finished(
        self,
        operation_type: OperationType | None,
        errors: list[GraphQLError] | None,
    ) -> None:
        """Runs `operation_finished` hook for all extensions.

        Should be called after operation's execution. `errors` should be
        a list of GraphQL errors from the execution result, or `None` if
        the execution itself raised an exception.
        Raises `RuntimeError` if a hook returns an awaitable.
        """
        for ext in self.extensions:
            result = ext.operation_finished(self.context, operation_type, errors)
            if isawaitable(result):
                _close_awaitable(result)
                raise RuntimeError(
                    "Extensions can't return awaitables from "
                    "'operation_finished' hook in synchronous query executor."
                )

    async def aoperation_finished(
        self,
        operation_type: OperationType | None,
        errors: list[GraphQLError] | None,
    ) -> None:
        """Asynchronously runs `operation_finished` hook for all extensions.

        Should be called after operation's execution. `errors` should be
        a list of GraphQL errors from the execution result, or `None` if
        the execution itself raised an exception.
        Awaits awaitables returned from hooks.
        """
        for ext in self.extensions:
            result = ext.operation_finished(self.context, operation_type, errors)
            if isawaitable(result):
                await result

    def format(self) -> dict:
        """Gathers data from extensions for inclusion in server's response JSON.

        This data can be retrieved from the `extensions` key in response JSON.

        Returns `dict` with JSON-serializable data.
        """
        data = {}
        for ext in self.extensions:
            ext_data = ext.format(self.context)
            if ext_data:
                data.update(ext_data)
        return data


def _close_awaitable(awaitable: Any) -> None:
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()


class _PendingTransaction:
    """Awaitable resolving a transaction from an async transaction factory.

    Exposes `close` so the synchronous query executor can dispose of
    the underlying awaitable when it can't be awaited.
    """

    def __init__(
        self,
        extension: "TransactionExtension",
        awaitable: Awaitable[Transaction],
    ) -> None:
        self.extension = extension
        self.awaitable = awaitable

    def __await__(self):
        return self._resolve().__await__()

    async def _resolve(self) -> None:
        try:
            self.extension.transaction = await self.awaitable
        except Exception as exc:
            raise GraphQLError(
                f"Transaction failed to start: {exc}", original_error=exc
            ) from exc

    def close(self) -> None:
        _close_awaitable(self.awaitable)


class TransactionExtension(Extension):
    """Extension wrapping mutation operations in transactions.

    Transaction is started after the query is parsed and validated, and
    covers the whole mutation execution. It's committed only when the
    execution completes without errors, and rolled back when any resolver
    error occurs or the execution is interrupted (including cancellation).
    Queries and subscriptions are not wrapped in transactions.

    The extension is ORM-agnostic: the application provides a transaction
    factory which is a callable taking the GraphQL context value and
    returning a transaction object with `commit` and `rollback` methods
    (or an awaitable resolving to one, in asynchronous query executor).

    # Example

    ```python
    from ariadne import TransactionExtension

    def transaction_factory(context):
        return context["db_session"]  # has commit() and rollback()

    extensions = [lambda: TransactionExtension(transaction_factory)]
    ```
    """

    def __init__(self, transaction_factory: TransactionFactory) -> None:
        self.transaction_factory = transaction_factory
        self.transaction: Transaction | None = None

    def operation_started(
        self, context: ContextValue, operation_type: OperationType | None
    ) -> Any:
        """Starts the transaction for mutation operations."""
        if operation_type != OperationType.MUTATION:
            return None

        try:
            transaction = self.transaction_factory(context)
        except Exception as exc:
            raise GraphQLError(
                f"Transaction failed to start: {exc}", original_error=exc
            ) from exc

        if isawaitable(transaction):
            return _PendingTransaction(self, transaction)

        self.transaction = transaction
        return None

    def operation_finished(
        self,
        context: ContextValue,
        operation_type: OperationType | None,
        errors: list[GraphQLError] | None,
    ) -> Any:
        """Commits the transaction or rolls it back, depending on `errors`."""
        transaction, self.transaction = self.transaction, None
        if transaction is None:
            return None

        if errors is None or errors:
            return self._rollback(transaction)

        return self._commit(transaction)

    def _commit(self, transaction: Transaction) -> Any:
        try:
            result = transaction.commit()
        except Exception as exc:
            raise GraphQLError(
                f"Transaction commit failed: {exc}", original_error=exc
            ) from exc

        if isawaitable(result):
            return self._await_commit(result)

        return None

    async def _await_commit(self, awaitable: Awaitable[Any]) -> None:
        try:
            await awaitable
        except Exception as exc:
            raise GraphQLError(
                f"Transaction commit failed: {exc}", original_error=exc
            ) from exc

    def _rollback(self, transaction: Transaction) -> Any:
        result = transaction.rollback()
        if isawaitable(result):
            return self._await_rollback(result)

        return None

    async def _await_rollback(self, awaitable: Awaitable[Any]) -> None:
        await awaitable
