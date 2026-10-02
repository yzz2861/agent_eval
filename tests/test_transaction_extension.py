import asyncio
import sqlite3
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


@pytest.fixture
def db_connection():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)")
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def schema(db_connection):
    type_defs = """
        type Query {
            notes: [String!]!
        }

        type Mutation {
            addNote(text: String!): Boolean!
            fail: Boolean!
            slow: Boolean!
        }
    """

    query_type = QueryType()
    mutation_type = MutationType()

    @query_type.field("notes")
    def resolve_notes(*_):
        rows = db_connection.execute("SELECT text FROM notes").fetchall()
        return [row[0] for row in rows]

    @mutation_type.field("addNote")
    def resolve_add_note(*_, text):
        db_connection.execute("INSERT INTO notes (text) VALUES (?)", (text,))
        return True

    @mutation_type.field("fail")
    def resolve_fail(*_):
        raise ValueError("Mutation failed!")

    @mutation_type.field("slow")
    async def resolve_slow(*_):
        await asyncio.sleep(60)
        return True

    return make_executable_schema(type_defs, query_type, mutation_type)


def get_notes(db_connection):
    rows = db_connection.execute("SELECT text FROM notes").fetchall()
    return [row[0] for row in rows]


def sync_extensions(db_connection):
    return [lambda: TransactionExtension(lambda _: db_connection)]


def test_sync_mutation_is_committed_when_there_are_no_errors(
    schema, db_connection
):
    success, result = graphql_sync(
        schema,
        {"query": 'mutation { addNote(text: "first") }'},
        extensions=sync_extensions(db_connection),
    )

    assert success
    assert result["data"] == {"addNote": True}
    assert get_notes(db_connection) == ["first"]


def test_sync_mutation_is_rolled_back_when_later_field_fails(schema, db_connection):
    success, result = graphql_sync(
        schema,
        {"query": 'mutation { addNote(text: "first") fail }'},
        extensions=sync_extensions(db_connection),
    )

    assert result["errors"]
    assert result["data"] is None
    assert get_notes(db_connection) == []


@pytest.mark.asyncio
async def test_async_mutation_is_committed_when_there_are_no_errors(
    schema, db_connection
):
    success, result = await graphql(
        schema,
        {"query": 'mutation { addNote(text: "first") }'},
        extensions=sync_extensions(db_connection),
    )

    assert success
    assert result["data"] == {"addNote": True}
    assert get_notes(db_connection) == ["first"]


@pytest.mark.asyncio
async def test_async_mutation_is_rolled_back_when_later_field_fails(
    schema, db_connection
):
    success, result = await graphql(
        schema,
        {"query": 'mutation { addNote(text: "first") fail }'},
        extensions=sync_extensions(db_connection),
    )

    assert result["errors"]
    assert result["data"] is None
    assert get_notes(db_connection) == []


def test_query_does_not_start_transaction(schema, db_connection):
    factory = Mock(return_value=db_connection)
    success, result = graphql_sync(
        schema,
        {"query": "{ notes }"},
        extensions=[lambda: TransactionExtension(factory)],
    )

    assert success
    factory.assert_not_called()


def test_transaction_is_not_started_for_invalid_mutation(schema, db_connection):
    factory = Mock(return_value=db_connection)
    success, result = graphql_sync(
        schema,
        {"query": "mutation { notAField }"},
        extensions=[lambda: TransactionExtension(factory)],
    )

    assert not success
    factory.assert_not_called()


@pytest.mark.asyncio
async def test_async_transaction_factory_is_supported(schema, db_connection):
    async def factory(_):
        return db_connection

    success, result = await graphql(
        schema,
        {"query": 'mutation { addNote(text: "async") }'},
        extensions=[lambda: TransactionExtension(factory)],
    )

    assert success
    assert get_notes(db_connection) == ["async"]


@pytest.mark.asyncio
async def test_async_transaction_factory_failure_is_returned_as_graphql_error(
    schema, db_connection
):
    async def factory(_):
        raise RuntimeError("no db")

    success, result = await graphql(
        schema,
        {"query": 'mutation { addNote(text: "first") }'},
        extensions=[lambda: TransactionExtension(factory)],
    )

    assert not success
    assert result["errors"][0]["message"] == "Transaction failed to start: no db"


class AsyncTransaction:
    def __init__(self, connection):
        self.connection = connection

    async def commit(self):
        self.connection.commit()

    async def rollback(self):
        self.connection.rollback()


@pytest.mark.asyncio
async def test_async_transaction_is_rolled_back_on_error(schema, db_connection):
    success, result = await graphql(
        schema,
        {"query": 'mutation { addNote(text: "first") fail }'},
        extensions=[
            lambda: TransactionExtension(lambda _: AsyncTransaction(db_connection))
        ],
    )

    assert result["errors"]
    assert get_notes(db_connection) == []


@pytest.mark.asyncio
async def test_async_transaction_is_committed_when_there_are_no_errors(
    schema, db_connection
):
    success, result = await graphql(
        schema,
        {"query": 'mutation { addNote(text: "first") }'},
        extensions=[
            lambda: TransactionExtension(lambda _: AsyncTransaction(db_connection))
        ],
    )

    assert success
    assert get_notes(db_connection) == ["first"]


@pytest.mark.asyncio
async def test_cancelled_mutation_is_rolled_back(schema, db_connection):
    task = asyncio.ensure_future(
        graphql(
            schema,
            {"query": 'mutation { addNote(text: "first") slow }'},
            extensions=sync_extensions(db_connection),
        )
    )
    await asyncio.sleep(0.1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert get_notes(db_connection) == []


class FailingCommitTransaction:
    def __init__(self, connection):
        self.connection = connection

    def commit(self):
        raise RuntimeError("commit exploded")

    def rollback(self):
        self.connection.rollback()


def test_sync_commit_failure_is_returned_as_graphql_error(schema, db_connection):
    success, result = graphql_sync(
        schema,
        {"query": 'mutation { addNote(text: "first") }'},
        extensions=[
            lambda: TransactionExtension(
                lambda _: FailingCommitTransaction(db_connection)
            )
        ],
    )

    assert not success
    assert "data" not in result
    assert result["errors"][0]["message"] == (
        "Transaction commit failed: commit exploded"
    )


@pytest.mark.asyncio
async def test_async_commit_failure_is_returned_as_graphql_error(
    schema, db_connection
):
    class AsyncFailingCommitTransaction:
        async def commit(self):
            raise RuntimeError("commit exploded")

        async def rollback(self):
            pass

    success, result = await graphql(
        schema,
        {"query": 'mutation { addNote(text: "first") }'},
        extensions=[
            lambda: TransactionExtension(lambda _: AsyncFailingCommitTransaction())
        ],
    )

    assert not success
    assert "data" not in result
    assert result["errors"][0]["message"] == (
        "Transaction commit failed: commit exploded"
    )


def test_transaction_start_failure_is_returned_as_graphql_error(
    schema, db_connection
):
    def factory(_):
        raise RuntimeError("no db")

    success, result = graphql_sync(
        schema,
        {"query": 'mutation { addNote(text: "first") }'},
        extensions=[lambda: TransactionExtension(factory)],
    )

    assert not success
    assert result["errors"][0]["message"] == "Transaction failed to start: no db"


def test_sync_executor_raises_for_async_transaction_factory(schema, db_connection):
    async def factory(_):
        return db_connection

    with pytest.raises(RuntimeError, match="operation_started"):
        graphql_sync(
            schema,
            {"query": 'mutation { addNote(text: "first") }'},
            extensions=[lambda: TransactionExtension(factory)],
        )
