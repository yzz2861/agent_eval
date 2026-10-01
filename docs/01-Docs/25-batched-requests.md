---
id: batched-requests
title: Batched Requests
---

# Batched Requests

Ariadne's ASGI HTTP handler can be configured to accept batched GraphQL requests: a single POST request with a JSON array of GraphQL operations, instead of a single operation object.

Batching is disabled by default. Enable it by passing the `batching_enabled` option to `GraphQLHTTPHandler`:

```python
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler

app = GraphQL(
    schema,
    http_handler=GraphQLHTTPHandler(batching_enabled=True),
)
```

## Batch request format

When batching is enabled, clients can POST a JSON array of operations:

```json
[
    {"query": "{ status }"},
    {"query": "query GetHello($name: String!) { hello(name: $name) }", "variables": {"name": "Bob"}},
    {"query": "mutation { echo(text: \"test\") }"}
]
```

The server responds with a JSON array of results, one per operation, in the same order as the operations appeared in the request:

```json
[
    {"data": {"status": true}},
    {"data": {"hello": "Hello, Bob!"}},
    {"data": {"echo": "Echo: test"}}
]
```

Single-operation requests (JSON object body) keep working unchanged when batching is enabled.

## Execution semantics

- Every operation in the batch is validated and executed independently: it gets its own context value, extensions and middleware, so no state (like DataLoader instances) is shared between operations through the shared HTTP request object.
- An operation that fails validation or raises a GraphQL error produces an individual error result without affecting other operations in the batch.
- `query` operations are executed concurrently, with the maximum concurrency controlled by the `batch_query_concurrency` option (defaults to `5`).
- `mutation` operations are executed serially, in the order they appear in the batch.
- `subscription` operations are rejected with an error result, as subscriptions require a WebSocket connection.
- If the client disconnects while the batch is being executed, unfinished operations are cancelled and their contexts are cleaned up.

## Limiting batch size

The number of operations in a single batch is limited by the `max_batch_size` option (defaults to `10`):

```python
GraphQLHTTPHandler(
    batching_enabled=True,
    max_batch_size=20,
    batch_query_concurrency=4,
)
```

Empty batches and batches exceeding the limit are rejected with a `400` response before any operation is executed.

