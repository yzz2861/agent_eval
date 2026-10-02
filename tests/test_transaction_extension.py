import asyncio
import sqlite3
from functools import partial
from unittest.mock import Mock

import pytest

from ariadne import (
    MutationType,
    QueryType,
    TransactionExtension,
    graphql,
    graphql_sync,
    make_executable_schema,
)

type_defs = """
    type Query {
        noop: Boolean
    }

    type Mutation {
        createUser(name: String!): Boolean
        fail: Boolean
    }
"""


@pytest.fixture
def connection():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    yield connection
    connection.close()


@pytest.fixture
def schema(connection):
    query = QueryType()
    mutation = MutationType()

    @mutation.field("createUser")
    def resolve_create_user(*_, name):
        connection.execute("INSERT INTO users (name) VALUES (?)", (name,))
        return True

    @mutation.field("fail")
    def resolve_fail(*_):
        raise ValueError("Mutation failed!")

    return make_executable_schema(type_defs, query, mutation)


@pytest.fixture
def transaction_factory(connection):
    return Mock(wraps=lambda context: connection)


@pytest.fixture
def extensions(transaction_factory):
    return [partial(TransactionExtension, transaction_factory)]


def get_user_names(connection):
    cursor = connection.execute("SELECT name FROM users")
    return [row[0] for row in cursor.fetchall()]


def test_successful_mutation_is_committed(connection, schema, extensions):
    success, result = graphql_sync(
        schema,
        {"query": 'mutation { createUser(name: "Alice") }'},
        extensions=extensions,
    )

    assert success is True
    assert result == {"data": {"createUser": True}}
    assert get_user_names(connection) == ["Alice"]


def test_mutation_is_rolled_back_when_other_field_fails(connection, schema, extensions):
    _, result = graphql_sync(
        schema,
        {"query": 'mutation { createUser(name: "Alice") fail }'},
        extensions=extensions,
    )

    assert result["errors"]
    assert get_user_names(connection) == []


def test_transaction_is_not_started_for_query(schema, extensions, transaction_factory):
    success, _ = graphql_sync(
        schema,
        {"query": "{ noop }"},
        extensions=extensions,
    )

    assert success is True
    transaction_factory.assert_not_called()


def test_transaction_is_not_started_for_invalid_operation(
    schema, extensions, transaction_factory
):
    success, _ = graphql_sync(
        schema,
        {"query": "mutation { notAField }"},
        extensions=extensions,
    )

    assert success is False
    transaction_factory.assert_not_called()


def test_transaction_is_not_started_for_subscription(
    schema, extensions, transaction_factory
):
    success, _ = graphql_sync(
        schema,
        {"query": "subscription { noop }"},
        extensions=extensions,
    )

    assert success is False
    transaction_factory.assert_not_called()


def test_transaction_is_started_for_named_mutation(connection, schema, extensions):
    success, _ = graphql_sync(
        schema,
        {
            "query": """
                mutation CreateUser { createUser(name: "Alice") }
                query Noop { noop }
            """,
            "operationName": "CreateUser",
        },
        extensions=extensions,
    )

    assert success is True
    assert get_user_names(connection) == ["Alice"]


def test_transaction_is_not_started_for_named_query(
    schema, extensions, transaction_factory
):
    success, _ = graphql_sync(
        schema,
        {
            "query": """
                mutation CreateUser { createUser(name: "Alice") }
                query Noop { noop }
            """,
            "operationName": "Noop",
        },
        extensions=extensions,
    )

    assert success is True
    transaction_factory.assert_not_called()


def test_commit_error_is_returned_as_graphql_error(schema):
    class FailingCommitTransaction:
        def commit(self):
            raise RuntimeError("Commit failed!")

        def rollback(self):
            pass

    success, result = graphql_sync(
        schema,
        {"query": 'mutation { createUser(name: "Alice") }'},
        extensions=[
            partial(
                TransactionExtension,
                lambda context: FailingCommitTransaction(),
            )
        ],
    )

    assert success is False
    assert "Transaction commit failed" in result["errors"][0]["message"]


def test_transaction_factory_error_is_returned_as_graphql_error(schema):
    def failing_factory(context):
        raise RuntimeError("No connection!")

    success, result = graphql_sync(
        schema,
        {"query": 'mutation { createUser(name: "Alice") }'},
        extensions=[partial(TransactionExtension, failing_factory)],
    )

    assert success is False
    assert "Transaction failed to start" in result["errors"][0]["message"]


def test_async_transaction_factory_is_not_supported_by_sync_executor(schema):
    async def async_factory(context):
        return Mock()

    with pytest.raises(RuntimeError, match="can't be asynchronous"):
        graphql_sync(
            schema,
            {"query": 'mutation { createUser(name: "Alice") }'},
            extensions=[partial(TransactionExtension, async_factory)],
        )


def test_async_transaction_commit_is_not_supported_by_sync_executor(schema):
    class AsyncCommitTransaction:
        async def commit(self):
            pass

        def rollback(self):
            pass

    with pytest.raises(RuntimeError, match="can't be asynchronous"):
        graphql_sync(
            schema,
            {"query": 'mutation { createUser(name: "Alice") }'},
            extensions=[
                partial(
                    TransactionExtension,
                    lambda context: AsyncCommitTransaction(),
                )
            ],
        )


class AsyncTransaction:
    def __init__(self, connection):
        self.connection = connection
        self.committed = False
        self.rolled_back = False

    async def commit(self):
        self.committed = True
        self.connection.commit()

    async def rollback(self):
        self.rolled_back = True
        self.connection.rollback()


@pytest.fixture
def async_transactions(connection):
    transactions = []

    async def async_factory(context):
        transaction = AsyncTransaction(connection)
        transactions.append(transaction)
        return transaction

    return transactions, async_factory


@pytest.mark.asyncio
async def test_async_mutation_is_committed(connection, schema, async_transactions):
    transactions, async_factory = async_transactions

    success, _ = await graphql(
        schema,
        {"query": 'mutation { createUser(name: "Alice") }'},
        extensions=[partial(TransactionExtension, async_factory)],
    )

    assert success is True
    assert transactions[0].committed is True
    assert transactions[0].rolled_back is False
    assert get_user_names(connection) == ["Alice"]


@pytest.mark.asyncio
async def test_async_mutation_is_rolled_back_when_other_field_fails(
    connection, schema, async_transactions
):
    transactions, async_factory = async_transactions

    _, result = await graphql(
        schema,
        {"query": 'mutation { createUser(name: "Alice") fail }'},
        extensions=[partial(TransactionExtension, async_factory)],
    )

    assert result["errors"]
    assert transactions[0].committed is False
    assert transactions[0].rolled_back is True
    assert get_user_names(connection) == []


@pytest.mark.asyncio
async def test_async_transaction_is_not_started_for_query(schema, async_transactions):
    transactions, async_factory = async_transactions
    factory_mock = Mock(wraps=lambda context: async_factory(context))

    success, _ = await graphql(
        schema,
        {"query": "{ noop }"},
        extensions=[partial(TransactionExtension, factory_mock)],
    )

    assert success is True
    factory_mock.assert_not_called()
    assert transactions == []


@pytest.mark.asyncio
async def test_async_commit_error_is_returned_as_graphql_error(connection, schema):
    class FailingAsyncCommitTransaction:
        async def commit(self):
            raise RuntimeError("Commit failed!")

        async def rollback(self):
            pass

    async def async_factory(context):
        return FailingAsyncCommitTransaction()

    success, result = await graphql(
        schema,
        {"query": 'mutation { createUser(name: "Alice") }'},
        extensions=[partial(TransactionExtension, async_factory)],
    )

    assert success is False
    assert "Transaction commit failed" in result["errors"][0]["message"]


@pytest.mark.asyncio
async def test_cancelled_mutation_is_rolled_back(connection, async_transactions):
    transactions, async_factory = async_transactions
    mutation = MutationType()

    @mutation.field("createUser")
    async def resolve_create_user(*_, name):
        raise asyncio.CancelledError()

    schema = make_executable_schema(type_defs, QueryType(), mutation)

    with pytest.raises(asyncio.CancelledError):
        await graphql(
            schema,
            {"query": 'mutation { createUser(name: "Alice") }'},
            extensions=[partial(TransactionExtension, async_factory)],
        )

    assert transactions[0].committed is False
    assert transactions[0].rolled_back is True
