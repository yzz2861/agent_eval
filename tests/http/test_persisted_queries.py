from __future__ import annotations

import hashlib
import json
from typing import Literal
from urllib.parse import urlencode

import pytest
from cross_web import HTTPException

import strawberry
from strawberry.http import GraphQLRequestData
from strawberry.http.persisted_queries import (
    PersistedQueriesConfig,
    PersistedQueryMode,
    PersistedQueryResolver,
)
from strawberry.schema.config import StrawberryConfig
from tests.views.schema import Mutation, Query, Subscription

from .clients.base import HttpClient

QUERY = "query PersistedHello($name: String!) { hello(name: $name) }"
MUTATION_QUERY = "mutation PersistedMutation { hello }"


def sha256(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()


def persisted_extension(query: str) -> dict[str, object]:
    return {"persistedQuery": {"version": 1, "sha256Hash": sha256(query)}}


def persisted_url(extension: dict[str, object], **params: object) -> str:
    query = {"extensions": json.dumps(extension), **params}
    return "/graphql?" + urlencode(query)


@pytest.fixture
def apq_client(http_client_class: type[HttpClient]) -> HttpClient:
    return http_client_class(
        strawberry.Schema(
            query=Query,
            mutation=Mutation,
            subscription=Subscription,
            config=StrawberryConfig(
                persisted_queries_config=PersistedQueriesConfig(
                    max_entries=10,
                    max_query_size=1024,
                )
            ),
        )
    )


@pytest.fixture
def apq_batching_client(http_client_class: type[HttpClient]) -> HttpClient:
    return http_client_class(
        strawberry.Schema(
            query=Query,
            mutation=Mutation,
            subscription=Subscription,
            config=StrawberryConfig(
                batching_config={"max_operations": 2},
                persisted_queries_config=PersistedQueriesConfig(
                    max_entries=10,
                    max_query_size=1024,
                ),
            ),
        )
    )


def manifest_client_factory(
    http_client_class: type[HttpClient],
    *,
    mode: PersistedQueryMode,
    schema_version: str = "schema-v1",
) -> HttpClient:
    config = PersistedQueriesConfig(
        mode=mode,
        manifest={sha256(QUERY): QUERY, sha256(MUTATION_QUERY): MUTATION_QUERY},
        schema_version=schema_version,
    )
    return http_client_class(
        strawberry.Schema(
            query=Query,
            mutation=Mutation,
            subscription=Subscription,
            config=StrawberryConfig(persisted_queries_config=config),
        )
    )


@pytest.fixture
def manifest_client(http_client_class: type[HttpClient]) -> HttpClient:
    return manifest_client_factory(
        http_client_class, mode=PersistedQueryMode.MANIFEST_ONLY
    )


async def test_apq_allows_registration_then_hash_only_request(apq_client: HttpClient):
    extension = persisted_extension(QUERY)

    missing = await apq_client.post(
        "/graphql",
        json={
            "variables": {"name": "missing"},
            "extensions": extension,
        },
        headers={"Content-Type": "application/json"},
    )
    assert missing.status_code == 200
    assert missing.json == {
        "data": None,
        "errors": [
            {
                "message": "PersistedQueryNotFound",
                "extensions": {"code": "PERSISTED_QUERY_NOT_FOUND"},
            }
        ],
    }

    registered = await apq_client.query(
        query=QUERY,
        variables={"name": "first"},
        extensions=extension,
    )
    assert registered.status_code == 200
    assert registered.json["data"] == {"hello": "Hello first"}

    cached = await apq_client.post(
        "/graphql",
        json={
            "variables": {"name": "second"},
            "extensions": extension,
        },
        headers={"Content-Type": "application/json"},
    )
    assert cached.status_code == 200
    assert cached.json["data"] == {"hello": "Hello second"}


async def test_apq_hash_mismatch_is_rejected_and_not_cached(apq_client: HttpClient):
    extension = persisted_extension(QUERY)

    mismatched = await apq_client.post(
        "/graphql",
        json={
            "query": "{ hello }".replace(" ", "  "),
            "variables": {"name": "ignored"},
            "extensions": extension,
        },
        headers={"Content-Type": "application/json"},
    )
    assert mismatched.status_code == 200
    assert mismatched.json == {
        "data": None,
        "errors": [
            {
                "message": "PersistedQueryMismatch",
                "extensions": {"code": "PERSISTED_QUERY_MISMATCH"},
            }
        ],
    }

    cached = await apq_client.post(
        "/graphql",
        json={"variables": {"name": "second"}, "extensions": extension},
        headers={"Content-Type": "application/json"},
    )
    assert cached.json["errors"][0]["extensions"]["code"] == (
        "PERSISTED_QUERY_NOT_FOUND"
    )


@pytest.mark.parametrize("method", ["get", "post"])
async def test_cached_query_still_uses_current_variables_and_operation_name(
    apq_client: HttpClient, method: Literal["get", "post"]
):
    query = 'query One { hello(name: "One") } query Two { hello(name: "Two") }'
    extension = persisted_extension(query)
    await apq_client.query(query=query, extensions=extension)

    if method == "get":
        response = await apq_client.get(persisted_url(extension, operationName="Two"))
    else:
        response = await apq_client.post(
            "/graphql",
            json={
                "operationName": "Two",
                "extensions": extension,
            },
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 200
    assert response.json["data"] == {"hello": "Hello Two"}


async def test_cached_query_still_validates_current_variables(apq_client: HttpClient):
    extension = persisted_extension(QUERY)
    await apq_client.query(
        query=QUERY,
        variables={"name": "valid"},
        extensions=extension,
    )

    response = await apq_client.post(
        "/graphql",
        json={"variables": {}, "extensions": extension},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert "Variable '$name' of required type" in response.json["errors"][0]["message"]


async def test_cached_mutation_cannot_execute_with_get(apq_client: HttpClient):
    extension = persisted_extension(MUTATION_QUERY)
    registered = await apq_client.post(
        "/graphql",
        json={"query": MUTATION_QUERY, "extensions": extension},
        headers={"Content-Type": "application/json"},
    )
    assert registered.status_code == 200

    response = await apq_client.get(persisted_url(extension))
    assert response.status_code == 400
    assert response.text == "mutations are not allowed when using GET"


async def test_manifest_only_rejects_plain_query_body(manifest_client: HttpClient):
    response = await manifest_client.post(
        "/graphql",
        json={"query": QUERY},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "manifest" in response.text


async def test_manifest_only_rejects_query_body_with_hash(manifest_client: HttpClient):
    response = await manifest_client.post(
        "/graphql",
        json={"query": QUERY, "extensions": persisted_extension(QUERY)},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "Query documents are not accepted" in response.text


async def test_manifest_only_executes_hash_only_request(manifest_client: HttpClient):
    response = await manifest_client.post(
        "/graphql",
        json={
            "variables": {"name": "manifest"},
            "extensions": persisted_extension(QUERY),
        },
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json["data"] == {"hello": "Hello manifest"}


async def test_manifest_hit_uses_current_operation_name(manifest_client: HttpClient):
    response = await manifest_client.post(
        "/graphql",
        json={
            "operationName": "NotInDocument",
            "variables": {"name": "manifest"},
            "extensions": persisted_extension(QUERY),
        },
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.text == 'Unknown operation named "NotInDocument".'


async def test_manifest_only_validates_current_operation_type(
    manifest_client: HttpClient,
):
    response = await manifest_client.get(
        persisted_url(persisted_extension(MUTATION_QUERY))
    )
    assert response.status_code == 400
    assert response.text == "mutations are not allowed when using GET"


async def test_manifest_hit_validates_current_variables(manifest_client: HttpClient):
    response = await manifest_client.post(
        "/graphql",
        json={
            "variables": {},
            "extensions": persisted_extension(QUERY),
        },
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert "Variable '$name' of required type" in response.json["errors"][0]["message"]


async def test_manifest_only_unknown_hash_is_rejected(manifest_client: HttpClient):
    response = await manifest_client.post(
        "/graphql",
        json={"extensions": persisted_extension("{ hello }")},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert "manifest" in response.text


async def test_apq_batch_reports_missing_and_registers_operation(
    apq_batching_client: HttpClient,
):
    extension = persisted_extension(QUERY)
    response = await apq_batching_client.post(
        "/graphql",
        json=[
            {
                "variables": {"name": "missing"},
                "extensions": extension,
            },
            {
                "query": QUERY,
                "variables": {"name": "registered"},
                "extensions": extension,
            },
        ],
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json[0]["errors"][0]["extensions"]["code"] == (
        "PERSISTED_QUERY_NOT_FOUND"
    )
    assert response.json[1]["data"] == {"hello": "Hello registered"}

    cached = await apq_batching_client.post(
        "/graphql",
        json={"variables": {"name": "cached"}, "extensions": extension},
        headers={"Content-Type": "application/json"},
    )
    assert cached.json["data"] == {"hello": "Hello cached"}


async def test_apq_invalid_syntax_is_not_cached():
    resolver = PersistedQueryResolver(PersistedQueriesConfig(max_entries=2), "v1")
    invalid_query = "{ hello"
    extension_hash = sha256(invalid_query)
    request = GraphQLRequestData(
        query=invalid_query,
        variables=None,
        operation_name=None,
        extensions={"persistedQuery": {"version": 1, "sha256Hash": extension_hash}},
    )

    resolution = resolver.resolve(request)
    assert resolution.request_data is not None

    cached = resolver.resolve(
        GraphQLRequestData(
            query=None,
            variables=None,
            operation_name=None,
            extensions={"persistedQuery": {"version": 1, "sha256Hash": extension_hash}},
        )
    )
    assert cached.error is not None
    assert cached.error.errors[0].extensions == {"code": "PERSISTED_QUERY_NOT_FOUND"}


def test_apq_cache_entries_are_bound_to_schema_version():
    resolver = PersistedQueryResolver(PersistedQueriesConfig(max_entries=2), "v1")
    request = GraphQLRequestData(
        query=QUERY,
        variables={"name": "request"},
        operation_name=None,
        extensions={"persistedQuery": {"version": 1, "sha256Hash": sha256(QUERY)}},
    )
    assert resolver.resolve(request).request_data is not None

    assert (
        resolver.resolve(
            GraphQLRequestData(
                query=None,
                variables=None,
                operation_name=None,
                extensions={
                    "persistedQuery": {"version": 1, "sha256Hash": sha256(QUERY)}
                },
            )
        ).request_data
        is not None
    )

    versioned_resolver = PersistedQueryResolver(
        PersistedQueriesConfig(max_entries=2), "v2"
    )
    missing = versioned_resolver.resolve(
        GraphQLRequestData(
            query=None,
            variables=None,
            operation_name=None,
            extensions={"persistedQuery": {"version": 1, "sha256Hash": sha256(QUERY)}},
        )
    )
    assert missing.error is not None


def test_apq_cache_respects_max_entries():
    resolver = PersistedQueryResolver(PersistedQueriesConfig(max_entries=2), "v1")
    queries = [f'{{ hello(name: "{index}") }}' for index in range(3)]

    for query in queries:
        resolver.resolve(
            GraphQLRequestData(
                query=query,
                variables=None,
                operation_name=None,
                extensions={
                    "persistedQuery": {"version": 1, "sha256Hash": sha256(query)}
                },
            )
        )

    oldest_missing = resolver.resolve(
        GraphQLRequestData(
            query=None,
            variables=None,
            operation_name=None,
            extensions={
                "persistedQuery": {"version": 1, "sha256Hash": sha256(queries[0])}
            },
        )
    )
    assert oldest_missing.error is not None


def test_apq_rejects_oversized_query_before_caching():
    resolver = PersistedQueryResolver(
        PersistedQueriesConfig(max_entries=2, max_query_size=5), "v1"
    )
    request = GraphQLRequestData(
        query="{ hello }",
        variables=None,
        operation_name=None,
        extensions={
            "persistedQuery": {
                "version": 1,
                "sha256Hash": sha256("{ hello }"),
            }
        },
    )

    with pytest.raises(HTTPException, match="maximum query size"):
        resolver.resolve(request)


def test_invalid_manifest_hash_is_rejected_at_configuration_time():
    with pytest.raises(ValueError, match="invalid hash"):
        PersistedQueriesConfig(manifest={sha256("{ hello }"): "{ __typename }"})


@pytest.mark.parametrize(
    ("kwargs", "message", "exception_type"),
    [
        (
            {"mode": "automatic"},
            "PersistedQueryMode",
            TypeError,
        ),
        (
            {"schema_version": ""},
            "schema_version",
            ValueError,
        ),
    ],
)
def test_invalid_persisted_query_configuration(
    kwargs: dict[str, object], message: str, exception_type: type[Exception]
):
    with pytest.raises(exception_type, match=message):
        PersistedQueriesConfig(**kwargs)
