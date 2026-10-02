# Persisted Queries

Strawberry supports Automatic Persisted Queries and a manifest-only mode for
production environments that only allow pre-approved operation documents.

Persisted queries use the standard
`extensions.persistedQuery.sha256Hash` field. The hash is the SHA-256 digest
of the exact GraphQL operation text sent by the client.

## Automatic Persisted Queries

Enable automatic persisted queries on the schema configuration:

```python
import strawberry
from strawberry.http.persisted_queries import PersistedQueriesConfig
from strawberry.schema.config import StrawberryConfig

schema = strawberry.Schema(
    query=Query,
    config=StrawberryConfig(
        persisted_queries_config=PersistedQueriesConfig(
            max_entries=1000,
            max_query_size=100_000,
        )
    ),
)
```

The first request can omit `query`. Strawberry responds with a GraphQL error
using the `PERSISTED_QUERY_NOT_FOUND` code. The client then retries with both
the operation text and its SHA-256 hash. If the hash matches, the operation is
stored and later requests can omit the text.

If the hash does not match the supplied operation text, Strawberry responds
with `PERSISTED_QUERY_MISMATCH` and does not store the operation. Invalid
operation syntax is also not cached.

## Manifest-Only Mode

For production, configure the SHA-256 hashes and approved operation texts up
front and set the mode to `MANIFEST_ONLY`:

```python
from strawberry.http.persisted_queries import (
    PersistedQueryMode,
    PersistedQueriesConfig,
)

config = PersistedQueriesConfig(
    mode=PersistedQueryMode.MANIFEST_ONLY,
    manifest={
        "5f2b…": "query CurrentUser { me { id } }",
    },
    schema_version="2026-10-02",
)
```

Strawberry validates every manifest entry when the configuration is created.
In manifest-only mode, requests without a persisted query extension and
requests that include operation text are rejected. A hash that is not in the
manifest cannot be executed by including its body in the same request.

## Schema Versions

Dynamically learned entries are scoped to a schema version. By default,
Strawberry derives the version from the schema's SDL, but deployments can set
`schema_version` explicitly to make rollouts deterministic.

Changing the version prevents a hash learned against one schema from being
used with another schema.

## Per-Request Validation

Persisted queries only reduce the amount of operation text transmitted. They
do not cache or reuse:

- `operationName`
- `variables`
- variable validation
- HTTP-method operation restrictions

For example, a cached mutation cannot be executed through a GET request. A
manifest query that requires variables still receives variable validation for
the variables supplied with each request.

The default in-memory cache is process-local and limited by `max_entries` and
`max_query_size`. It is suitable for a single process or sticky deployments;
multi-region deployments should populate the same release-specific manifest on
every server.
