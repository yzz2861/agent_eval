---
title: Persisted Queries
---

# Persisted Queries

Persisted queries let clients send a SHA-256 hash instead of a GraphQL
document after the server has seen the operation. Strawberry supports the
common Automatic Persisted Query (APQ) negotiation as well as a manifest-only
production mode.

Persisted query caches are in-memory and per server view. Each cache entry is
bound to the current schema version, and a changed schema makes old hashes miss.

## Automatic Persisted Queries

Pass `PersistedQueriesConfig` to an HTTP integration:

```python
import hashlib

from fastapi import FastAPI
import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.http.persisted_queries import PersistedQueriesConfig


@strawberry.type
class Query:
    @strawberry.field
    def hello(self, name: str = "world") -> str:
        return f"Hello {name}"


schema = strawberry.Schema(Query)
graphql_app = GraphQLRouter(
    schema,
    persisted_queries=PersistedQueriesConfig(),
)

app = FastAPI()
app.include_router(graphql_app, prefix="/graphql")
```

Clients first send the hash without a body:

```json
{
  "extensions": {
    "persistedQuery": {
      "version": 1,
      "sha256Hash": "..."
    }
  }
}
```

If the hash is unknown, Strawberry responds with HTTP 400 and
`PersistedQueryNotFound`. The client then retries with the same extension and
the matching `query` string. If its SHA-256 hash matches, Strawberry executes
the operation and stores its text. Later requests can omit `query`.

`operationName` and `variables` are never cached. They are taken from the
current request, so variable values and operation selection are validated on
every execution. HTTP method restrictions also still apply; a mutation stored
in the cache cannot be executed through GET.

## Manifest-Only Mode

For production, preload an allow list and use `MANIFEST_ONLY`. Requests in this
mode must use a preloaded hash and cannot include a query body. Sending a body
does not register or bypass the manifest.

```python
from strawberry.http.persisted_queries import (
    PersistedQueryMode,
    PersistedQueriesConfig,
)

query = "query Hello($name: String!) { hello(name: $name) }"
query_hash = hashlib.sha256(query.encode()).hexdigest()

persisted_queries = PersistedQueriesConfig(
    mode=PersistedQueryMode.MANIFEST_ONLY,
    preloaded_queries={query_hash: query},
)
```

You can also pass a sequence of query strings; Strawberry computes their SHA-256
hashes. Preloaded queries must have matching hashes and parse as GraphQL.

## Limits

Use `max_entries` and `max_query_bytes` to bound the cache:

```python
PersistedQueriesConfig(max_entries=500, max_query_bytes=16_384)
```

Preloaded entries count toward `max_entries`. Automatically learned entries use
an LRU policy and are evicted before preloaded entries. Oversized documents and
documents whose hash does not match their text are rejected and are not stored.
