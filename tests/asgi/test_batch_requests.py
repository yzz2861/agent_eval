import asyncio
import json
from http import HTTPStatus

import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from ariadne import MutationType, QueryType, make_executable_schema
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler


@pytest.fixture
def batch_handler():
    return GraphQLHTTPHandler(batching_enabled=True)


@pytest.fixture
def batch_app(schema, batch_handler):
    return GraphQL(schema, http_handler=batch_handler)


@pytest.fixture
def batch_client(batch_app):
    return TestClient(batch_app)


def test_batch_request_is_rejected_when_batching_is_disabled(client):
    response = client.post(
        "/",
        json=[{"query": "{ status }"}, {"query": "{ status }"}],
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_single_operation_request_still_works_when_batching_is_enabled(batch_client):
    response = batch_client.post("/", json={"query": "{ status }"})
    assert response.status_code == HTTPStatus.OK
    assert response.json() == {"data": {"status": True}}


def test_batch_request_returns_results_matching_operations_order(batch_client):
    response = batch_client.post(
        "/",
        json=[
            {"query": "{ status }"},
            {"query": '{ hello(name: "Alice") }'},
        ],
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json() == [
        {"data": {"status": True}},
        {"data": {"hello": "Hello, Alice!"}},
    ]


def test_empty_batch_request_is_rejected(batch_client):
    response = batch_client.post("/", json=[])
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_batch_request_exceeding_max_batch_size_is_rejected(schema):
    handler = GraphQLHTTPHandler(batching_enabled=True, max_batch_size=2)
    client = TestClient(GraphQL(schema, http_handler=handler))

    response = client.post(
        "/",
        json=[
            {"query": "{ status }"},
            {"query": "{ status }"},
            {"query": "{ status }"},
        ],
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_invalid_batch_options_are_rejected():
    with pytest.raises(ValueError):
        GraphQLHTTPHandler(batching_enabled=True, max_batch_size=0)
    with pytest.raises(ValueError):
        GraphQLHTTPHandler(batching_enabled=True, batch_query_concurrency=0)


def test_invalid_operation_does_not_affect_other_operations(batch_client):
    response = batch_client.post(
        "/",
        json=[
            {"query": "{ status }"},
            {"query": 123},
            "not an operation",
            {"query": "{ invalidField }"},
            {"query": '{ hello(name: "Bob") }'},
        ],
    )
    assert response.status_code == HTTPStatus.OK

    results = response.json()
    assert len(results) == 5
    assert results[0] == {"data": {"status": True}}
    assert "errors" in results[1]
    assert "errors" in results[2]
    assert "errors" in results[3]
    assert results[4] == {"data": {"hello": "Hello, Bob!"}}


def test_operation_with_graphql_error_does_not_affect_other_operations(batch_client):
    response = batch_client.post(
        "/",
        json=[
            {"query": "{ testError }"},
            {"query": "{ status }"},
        ],
    )
    assert response.status_code == HTTPStatus.OK

    results = response.json()
    assert results[0]["data"] == {"testError": None}
    assert "errors" in results[0]
    assert results[1] == {"data": {"status": True}}


def test_operation_with_unparsable_query_does_not_affect_other_operations(
    batch_client,
):
    response = batch_client.post(
        "/",
        json=[
            {"query": "{ status }"},
            {"query": "{ not a valid graphql"},
        ],
    )
    assert response.status_code == HTTPStatus.OK

    results = response.json()
    assert results[0] == {"data": {"status": True}}
    assert "errors" in results[1]


def test_mutation_is_executed_in_batch(batch_client):
    response = batch_client.post(
        "/",
        json=[
            {"query": 'mutation { echo(text: "one") }'},
            {"query": 'mutation { echo(text: "two") }'},
        ],
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json() == [
        {"data": {"echo": "Echo: one"}},
        {"data": {"echo": "Echo: two"}},
    ]


def test_subscription_operation_in_batch_is_rejected(batch_client):
    response = batch_client.post(
        "/",
        json=[
            {"query": "subscription { ping }"},
            {"query": "{ status }"},
        ],
    )
    assert response.status_code == HTTPStatus.OK

    results = response.json()
    assert "errors" in results[0]
    assert "WebSocket" in results[0]["errors"][0]["message"]
    assert results[1] == {"data": {"status": True}}


def test_named_subscription_operation_in_batch_is_rejected(batch_client):
    response = batch_client.post(
        "/",
        json=[
            {
                "query": "subscription PingSub { ping }",
                "operationName": "PingSub",
            },
        ],
    )
    assert response.status_code == HTTPStatus.OK

    results = response.json()
    assert "errors" in results[0]
    assert "PingSub" in results[0]["errors"][0]["message"]
    assert "WebSocket" in results[0]["errors"][0]["message"]


def test_context_value_is_created_for_each_batch_operation(schema):
    contexts = []

    def context_value(request, data):
        context = {"request": request, "test": data.get("operationName")}
        contexts.append(context)
        return context

    handler = GraphQLHTTPHandler(batching_enabled=True)
    app = GraphQL(schema, context_value=context_value, http_handler=handler)
    client = TestClient(app)

    response = client.post(
        "/",
        json=[
            {"query": "query First { testContext }", "operationName": "First"},
            {"query": "query Second { testContext }", "operationName": "Second"},
        ],
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json() == [
        {"data": {"testContext": "First"}},
        {"data": {"testContext": "Second"}},
    ]
    assert len(contexts) == 2
    assert contexts[0] is not contexts[1]


def test_extensions_are_resolved_for_each_batch_operation(schema):
    extensions_calls = 0

    def extensions_factory(request, context):
        nonlocal extensions_calls
        extensions_calls += 1
        return []

    handler = GraphQLHTTPHandler(
        batching_enabled=True,
        extensions=extensions_factory,
    )
    client = TestClient(GraphQL(schema, http_handler=handler))

    response = client.post(
        "/",
        json=[{"query": "{ status }"}, {"query": "{ status }"}],
    )
    assert response.status_code == HTTPStatus.OK
    assert extensions_calls == 2


tracked_type_defs = """
    type Query {
        tracked(name: String!): String
    }

    type Mutation {
        record(name: String!): String
    }
"""


def make_tracked_schema(events):
    query = QueryType()
    mutation = MutationType()

    async def resolve_tracked(*_, name):
        events.append(("start", name))
        await asyncio.sleep(0.05)
        events.append(("end", name))
        return name

    async def resolve_record(*_, name):
        events.append(("start", name))
        await asyncio.sleep(0.05)
        events.append(("end", name))
        return name

    query.set_field("tracked", resolve_tracked)
    mutation.set_field("record", resolve_record)
    return make_executable_schema(tracked_type_defs, [query, mutation])


def get_max_concurrency(events):
    max_concurrency = 0
    current = 0
    for event, _ in events:
        current += 1 if event == "start" else -1
        max_concurrency = max(max_concurrency, current)
    return max_concurrency


def test_batch_queries_are_executed_concurrently():
    events = []
    schema = make_tracked_schema(events)
    handler = GraphQLHTTPHandler(batching_enabled=True)
    client = TestClient(GraphQL(schema, http_handler=handler))

    response = client.post(
        "/",
        json=[
            {"query": '{ tracked(name: "a") }'},
            {"query": '{ tracked(name: "b") }'},
            {"query": '{ tracked(name: "c") }'},
        ],
    )
    assert response.status_code == HTTPStatus.OK
    assert [result["data"] for result in response.json()] == [
        {"tracked": "a"},
        {"tracked": "b"},
        {"tracked": "c"},
    ]
    assert get_max_concurrency(events) == 3


def test_batch_queries_concurrency_is_limited():
    events = []
    schema = make_tracked_schema(events)
    handler = GraphQLHTTPHandler(batching_enabled=True, batch_query_concurrency=2)
    client = TestClient(GraphQL(schema, http_handler=handler))

    response = client.post(
        "/",
        json=[
            {"query": '{ tracked(name: "a") }'},
            {"query": '{ tracked(name: "b") }'},
            {"query": '{ tracked(name: "c") }'},
            {"query": '{ tracked(name: "d") }'},
        ],
    )
    assert response.status_code == HTTPStatus.OK
    assert get_max_concurrency(events) == 2


def test_batch_mutations_are_executed_serially_in_order():
    events = []
    schema = make_tracked_schema(events)
    handler = GraphQLHTTPHandler(batching_enabled=True)
    client = TestClient(GraphQL(schema, http_handler=handler))

    response = client.post(
        "/",
        json=[
            {"query": 'mutation { record(name: "a") }'},
            {"query": '{ tracked(name: "q") }'},
            {"query": 'mutation { record(name: "b") }'},
        ],
    )
    assert response.status_code == HTTPStatus.OK
    assert [result["data"] for result in response.json()] == [
        {"record": "a"},
        {"tracked": "q"},
        {"record": "b"},
    ]

    mutation_events = [(event, name) for event, name in events if name in ("a", "b")]
    assert mutation_events == [
        ("start", "a"),
        ("end", "a"),
        ("start", "b"),
        ("end", "b"),
    ]


@pytest.mark.asyncio
async def test_batch_execution_is_cancelled_when_client_disconnects():
    started = []
    cancelled = []

    query = QueryType()

    async def resolve_slow(*_):
        started.append(True)
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        return "done"

    query.set_field("slow", resolve_slow)
    schema = make_executable_schema("type Query { slow: String }", query)

    handler = GraphQLHTTPHandler(batching_enabled=True)
    handler.configure(schema)

    body = json.dumps([{"query": "{ slow }"}, {"query": "{ slow }"}]).encode()
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        if messages:
            return messages.pop(0)
        if len(started) < 2:
            # Report disconnect only after both operations started executing
            await asyncio.sleep(0.05)
            return {}
        return {"type": "http.disconnect"}

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-type", b"application/json")],
    }
    request = Request(scope, receive)

    with pytest.raises(asyncio.CancelledError):
        await handler.handle_request(request)

    assert cancelled


@pytest.mark.asyncio
async def test_batch_results_are_returned_when_client_stays_connected():
    query = QueryType()
    query.set_field("status", lambda *_: True)
    schema = make_executable_schema("type Query { status: Boolean }", query)

    handler = GraphQLHTTPHandler(batching_enabled=True)
    handler.configure(schema)

    body = json.dumps([{"query": "{ status }"}, {"query": "{ status }"}]).encode()
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        if messages:
            return messages.pop(0)
        await asyncio.sleep(30)
        return {"type": "http.disconnect"}

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-type", b"application/json")],
    }
    request = Request(scope, receive)

    response = await handler.handle_request(request)
    assert response.status_code == HTTPStatus.OK
    assert json.loads(response.body) == [
        {"data": {"status": True}},
        {"data": {"status": True}},
    ]
