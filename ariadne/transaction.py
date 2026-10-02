from collections.abc import Awaitable, Callable
from inspect import isawaitable, iscoroutine
from typing import Any, Protocol

from graphql import DocumentNode, GraphQLError, OperationType, get_operation_ast

from .extensions import ExtensionManager
from .types import ContextValue, Extension


class Transaction(Protocol):
    """Protocol for transaction objects used by `TransactionExtension`.

    Transaction objects are returned by the transaction factory and are
    expected to provide `commit` and `rollback` methods. Both methods may
    be synchronous or asynchronous, but asynchronous methods are only
    supported by the asynchronous `graphql` query executor.
    """

    def commit(self) -> Any:
        """Commits the transaction."""

    def rollback(self) -> Any:
        """Rolls the transaction back."""


TransactionFactory = Callable[
    [ContextValue | None], Transaction | Awaitable[Transaction]
]
"""Type for transaction factories used by `TransactionExtension`.

It's a callable called with the GraphQL context value that returns
a `Transaction` object or an awaitable resolving to one.
"""


class TransactionExtension(Extension):
    """Extension that runs mutations inside an application-provided transaction.

    The transaction is started after the operation was parsed and validated,
    and only for mutations. Queries and subscriptions are executed without
    a transaction.

    If the mutation result contains any errors (for example because one of
    the resolvers raised an exception), the transaction is rolled back
    instead of being committed, even though such response may still be
    returned to the client with a success HTTP status code.

    # Required arguments

    `transaction_factory`: a `TransactionFactory` called with the GraphQL
    context value at the start of mutation's execution. Should return
    a transaction object implementing `commit` and `rollback` methods
    (or an awaitable resolving to one).

    # Example

    ```python
    from functools import partial

    from ariadne import TransactionExtension

    extensions = [partial(TransactionExtension, session.begin)]
    ```
    """

    def __init__(self, transaction_factory: TransactionFactory) -> None:
        """Initializes the extension with a transaction factory.

        # Required arguments

        `transaction_factory`: a `TransactionFactory` used to create
        transactions for executed mutations.
        """
        self.transaction_factory = transaction_factory


class OperationTransaction:
    """Group of transactions opened for a single GraphQL operation.

    Commits and rollbacks are applied to all transactions in the group.
    Rollbacks are applied in reversed order of transaction creation.
    """

    def __init__(self, transactions: list[Transaction]) -> None:
        self._transactions = transactions

    async def commit(self) -> None:
        """Commits all transactions, awaiting asynchronous commits.

        Raises `GraphQLError` if any of the commits fails.
        """
        for transaction in self._transactions:
            try:
                result = transaction.commit()
                if isawaitable(result):
                    await result
            except Exception as error:
                raise GraphQLError(
                    f"Transaction commit failed: {error}", original_error=error
                ) from error

    async def rollback(self) -> None:
        """Rolls all transactions back, awaiting asynchronous rollbacks."""
        for transaction in reversed(self._transactions):
            result = transaction.rollback()
            if isawaitable(result):
                await result

    def commit_sync(self) -> None:
        """Commits all transactions synchronously.

        Raises `GraphQLError` if any of the commits fails and `RuntimeError`
        if any of the commits is asynchronous.
        """
        for transaction in self._transactions:
            try:
                result = transaction.commit()
            except Exception as error:
                raise GraphQLError(
                    f"Transaction commit failed: {error}", original_error=error
                ) from error
            _raise_if_awaitable(result, "commit")

    def rollback_sync(self) -> None:
        """Rolls all transactions back synchronously.

        Raises `RuntimeError` if any of the rollbacks is asynchronous.
        """
        for transaction in reversed(self._transactions):
            _raise_if_awaitable(transaction.rollback(), "rollback")


async def begin_transaction(
    extension_manager: ExtensionManager,
    context_value: ContextValue | None,
    operation_name: str | None,
    document: DocumentNode,
) -> OperationTransaction:
    """Starts transactions for mutation operation, asynchronously.

    Returns an `OperationTransaction` group with transactions created by
    `TransactionExtension` instances. Returns an empty group if operation
    is not a mutation or no transaction extensions are enabled.

    Raises `GraphQLError` if any of the transaction factories fails.
    """
    extensions = _get_transaction_extensions(
        extension_manager, document, operation_name
    )
    transactions: list[Transaction] = []
    try:
        for extension in extensions:
            transaction = extension.transaction_factory(context_value)
            if isawaitable(transaction):
                transaction = await transaction
            transactions.append(transaction)
    except Exception as error:
        await _rollback_started_transactions(transactions)
        raise GraphQLError(
            f"Transaction failed to start: {error}", original_error=error
        ) from error

    return OperationTransaction(transactions)


def begin_transaction_sync(
    extension_manager: ExtensionManager,
    context_value: ContextValue | None,
    operation_name: str | None,
    document: DocumentNode,
) -> OperationTransaction:
    """Starts transactions for mutation operation, synchronously.

    Returns an `OperationTransaction` group with transactions created by
    `TransactionExtension` instances. Returns an empty group if operation
    is not a mutation or no transaction extensions are enabled.

    Raises `GraphQLError` if any of the transaction factories fails and
    `RuntimeError` if any of them is asynchronous.
    """
    extensions = _get_transaction_extensions(
        extension_manager, document, operation_name
    )
    transactions: list[Transaction] = []
    for extension in extensions:
        try:
            transaction = extension.transaction_factory(context_value)
        except Exception as error:
            _rollback_started_transactions_sync(transactions)
            raise GraphQLError(
                f"Transaction failed to start: {error}", original_error=error
            ) from error

        try:
            _raise_if_awaitable(transaction, "factory")
        except RuntimeError:
            _rollback_started_transactions_sync(transactions)
            raise

        transactions.append(transaction)

    return OperationTransaction(transactions)


def _get_transaction_extensions(
    extension_manager: ExtensionManager,
    document: DocumentNode,
    operation_name: str | None,
) -> list[TransactionExtension]:
    operation = get_operation_ast(document, operation_name)
    if not operation or operation.operation != OperationType.MUTATION:
        return []

    return [
        extension
        for extension in extension_manager.extensions
        if isinstance(extension, TransactionExtension)
    ]


async def _rollback_started_transactions(
    transactions: list[Transaction],
) -> None:
    for transaction in reversed(transactions):
        try:
            result = transaction.rollback()
            if isawaitable(result):
                await result
        except Exception:  # noqa: BLE001
            pass  # don't mask the original error


def _rollback_started_transactions_sync(
    transactions: list[Transaction],
) -> None:
    for transaction in reversed(transactions):
        try:
            _raise_if_awaitable(transaction.rollback(), "rollback")
        except Exception:  # noqa: BLE001
            pass  # don't mask the original error


def _raise_if_awaitable(result: Any, action: str) -> None:
    if isawaitable(result):
        if iscoroutine(result):
            result.close()
        raise RuntimeError(
            f"Transaction {action} can't be asynchronous in synchronous query executor."
        )
