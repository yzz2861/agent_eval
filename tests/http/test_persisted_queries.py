import json

import pytest

from strawberry.asgi import GraphQL
from strawberry.http import GraphQLRequestData
from strawberry.http.persisted_queries import (
    PersistedQueryMode,
    PersistedQueryStore,
    PersistedQueriesConfig,
    query_sha256,
)
from tests.views.schema import schema


QUERY = "query Hello($name: String!) { hello(name: $name) }"
QUERY_HASH = query_sha256(QUERY)


def _persisted_query(query_hash: str) -> dict[str, object]:
    return {"version": 1, "sha256Hash": query_hash}


def _request(
    query: str | None = None,
    *,
    variables: dict[str, object] | None = None,
    operation_name: str | None = None,
    query_hash: str | None = None,
) -> GraphQLRequestData:
    extensions = None
    if query_hash is not None:
        extensions = {"persistedQuery": _persisted_query(query_hash)}
    return GraphQLRequestData(
        query=query,
        variables=variables,
        operation_name=operation_name,
        extensions=extensions,
    )


def test_persisted_query_registration_and_retry() -> None:
    config = PersistedQueriesConfig()
    view = GraphQL(schema, persisted_queries=config)

    missing = GraphQLRequestData(
        query=None,
        variables=None,
        operation_name=None,
        extensions={"persistedQuery": _persisted_query(QUERY_HASH)},
    )
    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(missing)
    assert exc_info.value.status_code == 400
    assert exc_info.value.reason == "PersistedQueryNotFound"

    registration = _request(QUERY, query_hash=QUERY_HASH)
    view.resolve_persisted_queries(registration)

    retry = GraphQLRequestData(
        query=None,
        variables=None,
        operation_name=None,
        extensions={"persistedQuery": _persisted_query(QUERY_HASH)},
    )
    view.resolve_persisted_queries(retry)
    assert retry.query == QUERY


def test_hash_mismatch_is_rejected_and_not_cached() -> None:
    view = GraphQL(schema, persisted_queries=PersistedQueriesConfig())
    request = _request(QUERY, query_hash=query_sha256("other"))

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(request)

    assert exc_info.value.status_code == 400
    assert exc_info.value.reason == "PersistedQueryMismatch"

    cached_request = _request(None, query_hash=query_sha256("other"))
    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(cached_request)
    assert exc_info.value.reason == "PersistedQueryNotFound"


def test_batch_mismatch_does_not_cache_other_valid_registration() -> None:
    view = GraphQL(schema, persisted_queries=PersistedQueriesConfig())
    valid = _request(QUERY, query_hash=QUERY_HASH)
    invalid = _request(QUERY, query_hash=query_sha256("other"))

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries([valid, invalid])

    assert exc_info.value.reason == "PersistedQueryMismatch"

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(_request(None, query_hash=QUERY_HASH))
    assert exc_info.value.reason == "PersistedQueryNotFound"


def test_syntax_errors_are_not_cached() -> None:
    invalid_query = "query {"
    invalid_hash = query_sha256(invalid_query)
    view = GraphQL(schema, persisted_queries=PersistedQueriesConfig())

    view.resolve_persisted_queries(_request(invalid_query, query_hash=invalid_hash))

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(_request(None, query_hash=invalid_hash))
    assert exc_info.value.reason == "PersistedQueryNotFound"


def test_schema_validation_errors_are_not_cached() -> None:
    invalid_query = "query { unknownField }"
    invalid_hash = query_sha256(invalid_query)
    view = GraphQL(schema, persisted_queries=PersistedQueriesConfig())

    view.resolve_persisted_queries(_request(invalid_query, query_hash=invalid_hash))

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(_request(None, query_hash=invalid_hash))
    assert exc_info.value.reason == "PersistedQueryNotFound"


def test_preloaded_manifest_is_validated_against_schema() -> None:
    with pytest.raises(ValueError, match="current schema"):
        GraphQL(
            schema,
            persisted_queries=PersistedQueriesConfig(
                mode=PersistedQueryMode.MANIFEST_ONLY,
                preloaded_queries=["query { unknownField }"],
            ),
        ).persisted_query_manager


def test_entries_are_bound_to_schema_version() -> None:
    store = PersistedQueryStore(schema_version="v1")
    assert store.put(QUERY_HASH, QUERY)
    assert store.get(QUERY_HASH) == QUERY

    store.schema_version = "v2"
    assert store.get(QUERY_HASH) is None


def test_learned_entries_are_evicted_without_removing_preloaded() -> None:
    preloaded_query = "query Preloaded { hello }"
    first_query = "query First { hello }"
    second_query = "query Second { hello }"
    config = PersistedQueriesConfig(
        preloaded_queries={query_sha256(preloaded_query): preloaded_query},
        max_entries=2,
    )
    view = GraphQL(schema, persisted_queries=config)

    first_hash = query_sha256(first_query)
    view.resolve_persisted_queries(_request(first_query, query_hash=first_hash))
    view.resolve_persisted_queries(
        _request(second_query, query_hash=query_sha256(second_query))
    )

    with pytest.raises(Exception):
        view.resolve_persisted_queries(
            _request(None, query_hash=query_sha256(first_query))
        )

    preloaded = _request(None, query_hash=query_sha256(preloaded_query))
    view.resolve_persisted_queries(preloaded)
    assert preloaded.query == preloaded_query


def test_full_apq_http_flow_and_per_request_values() -> None:
    pytest.importorskip("httpx2")
    from starlette.testclient import TestClient

    client = TestClient(GraphQL(schema, persisted_queries=PersistedQueriesConfig()))
    extensions = {"persistedQuery": _persisted_query(QUERY_HASH)}

    response = client.post("/graphql", json={"extensions": extensions})
    assert response.status_code == 400
    assert response.text == "PersistedQueryNotFound"

    response = client.post(
        "/graphql",
        json={"query": QUERY, "variables": {"name": "First"}, "extensions": extensions},
    )
    assert response.status_code == 200
    assert response.json()["data"]["hello"] == "Hello First"

    response = client.post(
        "/graphql",
        json={"variables": {"name": "Second"}, "extensions": extensions},
    )
    assert response.status_code == 200
    assert response.json()["data"]["hello"] == "Hello Second"


def test_manifest_only_mode_requires_preloaded_query() -> None:
    pytest.importorskip("httpx2")
    from starlette.testclient import TestClient

    config = PersistedQueriesConfig(
        mode=PersistedQueryMode.MANIFEST_ONLY,
        preloaded_queries={QUERY_HASH: QUERY},
    )
    client = TestClient(GraphQL(schema, persisted_queries=config))
    extensions = {"persistedQuery": _persisted_query(QUERY_HASH)}

    response = client.post("/graphql", json={"query": QUERY, "extensions": extensions})
    assert response.status_code == 400
    assert response.text == "PersistedQueryNotSupported"

    response = client.post("/graphql", json={"query": QUERY})
    assert response.status_code == 400
    assert response.text == "PersistedQueryNotSupported"

    response = client.post(
        "/graphql",
        json={"variables": {"name": "Manifest"}, "extensions": extensions},
    )
    assert response.status_code == 200
    assert response.json()["data"]["hello"] == "Hello Manifest"


def test_manifest_get_request_still_validates_operation_type() -> None:
    pytest.importorskip("httpx2")
    from starlette.testclient import TestClient

    mutation = "mutation Persisted { hello }"
    config = PersistedQueriesConfig(
        mode=PersistedQueryMode.MANIFEST_ONLY,
        preloaded_queries={query_sha256(mutation): mutation},
    )
    client = TestClient(GraphQL(schema, persisted_queries=config))
    extensions = json.dumps(
        {"persistedQuery": _persisted_query(query_sha256(mutation))}
    )

    response = client.get("/graphql", params={"extensions": extensions})

    assert response.status_code == 400
    assert "mutations are not allowed when using GET" in response.text


def test_oversized_query_is_rejected_and_not_cached() -> None:
    config = PersistedQueriesConfig(max_query_bytes=len(QUERY.encode()) - 1)
    view = GraphQL(schema, persisted_queries=config)

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(_request(QUERY, query_hash=QUERY_HASH))
    assert exc_info.value.reason == (
        "Persisted query exceeds the configured maximum size"
    )

    with pytest.raises(Exception) as exc_info:
        view.resolve_persisted_queries(_request(None, query_hash=QUERY_HASH))
    assert exc_info.value.reason == "PersistedQueryNotFound"
