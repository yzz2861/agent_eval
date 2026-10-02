import pytest

from strawberry.asgi import GraphQL
from strawberry.http import GraphQLRequestData
from strawberry.http.persisted_queries import (
    PersistedQueryMode,
    PersistedQueriesConfig,
    query_sha256,
)
from tests.views.schema import schema


def test_manifest_hit_uses_current_operation_name_and_variables() -> None:
    document = (
        "query GreetWorld { hello }\n"
        "query GreetName($name: String!) { hello(name: $name) }"
    )
    query_hash = query_sha256(document)
    view = GraphQL(
        schema,
        persisted_queries=PersistedQueriesConfig(
            mode=PersistedQueryMode.MANIFEST_ONLY,
            preloaded_queries={query_hash: document},
        ),
    )
    extensions = {"persistedQuery": {"version": 1, "sha256Hash": query_hash}}

    first = GraphQLRequestData(
        query=None,
        variables=None,
        operation_name="GreetWorld",
        extensions=extensions,
    )
    view.resolve_persisted_queries(first)
    first_result = view.schema.execute_sync(
        first.query,
        variable_values=first.variables,
        operation_name=first.operation_name,
    )
    assert first_result.errors is None
    assert first_result.data == {"hello": "Hello world"}

    second = GraphQLRequestData(
        query=None,
        variables={"name": "Strawberry"},
        operation_name="GreetName",
        extensions=extensions,
    )
    view.resolve_persisted_queries(second)
    second_result = view.schema.execute_sync(
        second.query,
        variable_values=second.variables,
        operation_name=second.operation_name,
    )
    assert second_result.errors is None
    assert second_result.data == {"hello": "Hello Strawberry"}


def test_persisted_query_accepts_lowercase_hex_only() -> None:
    view = GraphQL(schema, persisted_queries=PersistedQueriesConfig())
    request = GraphQLRequestData(
        query=None,
        variables=None,
        operation_name=None,
        extensions={
            "persistedQuery": {"version": 1, "sha256Hash": "not-a-hash"}
        },
    )

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(request)

    assert exc_info.value.status_code == 400
