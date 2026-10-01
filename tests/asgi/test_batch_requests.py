from __future__ import annotations

import asyncio
from http import HTTPStatus

import httpx
import pytest
from graphql import GraphQLResolveInfo
from starlette.testclient import TestClient

from ariadne import MutationType, QueryType, make_executable_schema
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler
from ariadne.types import Extension


class TrackingExtension(Extension):
    instances: list[TrackingExtension] = []
    finished_contexts: list[dict] = []

    def __init__(self):
        self.context = None
        TrackingExtension.instances.append(self)

    def request_started(self, context):
        self.context = context
        context["extension_id"] = id(self)

    def request_finished(self, context):
        TrackingExtension.finished_contexts.append(context)


@pytest.fixture
def batch_schema():
    order = []
    active_queries = 0
    max_active_queries = 0
    query_lock = asyncio.Lock()
    query_started = asyncio.Event()
    query_can_complete = asyncio.Event()

    query = QueryType()
    mutation = MutationType()

    @query.field("hello")
    def resolve_hello(*_, name=None):
        return f"Hello, {name or 'world'}!"

    @query.field("extensionId")
    def resolve_extension_id(_, info: GraphQLResolveInfo):
        return str(info.context["number"])

    @query.field("blocked")
    async def resolve_blocked(*_):
        nonlocal active_queries, max_active_queries
        async with query_lock:
            active_queries += 1
            max_active_queries = max(max_active_queries, active_queries)
            if active_queries == 2:
                query_started.set()
        await query_can_complete.wait()
        async with query_lock:
            active_queries -= 1
        return True

    @mutation.field("record")
    async def resolve_record(*_, value):
        order.append(value)
        await asyncio.sleep(0)
        return value

    type_defs = """
        type Query {
          hello(name: String): String
          extensionId: String
          blocked: Boolean
        }

        type Mutation {
          record(value: String!): String!
        }
      """

    schema = make_executable_schema(type_defs, query, mutation)
    return {
        "schema": schema,
        "order": order,
        "query_lock": query_lock,
        "query_started": query_started,
        "query_can_complete": query_can_complete,
        "max_active_queries": lambda: max_active_queries,
    }


@pytest.fixture(autouse=True)
def clear_tracking_extensions():
    TrackingExtension.instances.clear()
    TrackingExtension.finished_contexts.clear()


def test_batch_returns_results_in_input_order(batch_schema):
    app = GraphQL(batch_schema["schema"])
    client = TestClient(app)

    response = client.post(
        "/",
        json=[
            {"query": '{ hello(name: "Ada") }'},
            {"query": '{ hello(name: "Grace") }'},
        ],
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json() == [
        {"data": {"hello": "Hello, Ada!"}},
        {"data": {"hello": "Hello, Grace!"}},
    ]


def test_invalid_batch_item_does_not_erase_other_results(batch_schema):
    app = GraphQL(batch_schema["schema"])
    client = TestClient(app)

    response = client.post(
        "/",
        json=[
            {"query": "{ hello }"},
            {"variables": None},
            {"query": "subscription Test { blocked }"},
        ],
    )

    assert response.status_code == HTTPStatus.OK
    results = response.json()
    assert results[0] == {"data": {"hello": "Hello, world!"}}
    assert results[1]["errors"][0]["message"] == ("The query must be a string.")
    assert "Subscription operations" in results[2]["errors"][0]["message"]


def test_empty_batch_is_rejected_before_execution(batch_schema):
    context_calls = 0

    def get_context(*_):
        nonlocal context_calls
        context_calls += 1
        return {}

    app = GraphQL(batch_schema["schema"], context_value=get_context)
    client = TestClient(app)

    response = client.post("/", json=[])

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "at least one operation" in response.text
    assert context_calls == 0


def test_batch_larger_than_limit_is_rejected_before_execution(batch_schema):
    context_calls = 0

    def get_context(*_):
        nonlocal context_calls
        context_calls += 1
        return {}

    app = GraphQL(
        batch_schema["schema"],
        max_batch_size=2,
        context_value=get_context,
    )
    client = TestClient(app)

    response = client.post(
        "/",
        json=[
            {"query": "{ hello }"},
            {"query": "{ hello }"},
            {"query": "{ hello }"},
        ],
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "maximum of 2 operations" in response.text
    assert context_calls == 0


def test_batch_requests_can_be_disabled(batch_schema):
    app = GraphQL(batch_schema["schema"], batch_requests=False)
    client = TestClient(app)

    response = client.post("/", json=[{"query": "{ hello }"}])

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "Batch requests are disabled" in response.text


def test_batch_requests_reject_multipart_operations(batch_schema):
    app = GraphQL(batch_schema["schema"])
    client = TestClient(app)

    response = client.post(
        "/",
        data={
            "operations": '[{"query":"{ hello }"}]',
            "map": "{}",
        },
        files={},
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "application/json" in response.text


def test_batch_creates_separate_contexts_and_extension_instances(batch_schema):
    context_ids = []

    def get_context(request, data):
        number = len(context_ids)
        context = {"request": request, "data": data, "number": number}
        context_ids.append(number)
        return context

    handler = GraphQLHTTPHandler(extensions=[TrackingExtension])
    app = GraphQL(
        batch_schema["schema"],
        http_handler=handler,
        context_value=get_context,
    )
    client = TestClient(app)

    response = client.post(
        "/",
        json=[
            {"query": "{ extensionId }"},
            {"query": "{ extensionId }"},
        ],
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json()[0]["data"]["extensionId"] == str(context_ids[0])
    assert response.json()[1]["data"]["extensionId"] == str(context_ids[1])
    assert len(TrackingExtension.instances) == 2
    assert TrackingExtension.instances[0].context is not (
        TrackingExtension.instances[1].context
    )


def test_mutations_execute_in_input_order(batch_schema):
    app = GraphQL(batch_schema["schema"], batch_query_concurrency=10)
    client = TestClient(app)

    response = client.post(
        "/",
        json=[
            {"query": 'mutation { record(value: "first") }'},
            {"query": 'mutation { record(value: "second") }'},
            {"query": 'mutation { record(value: "third") }'},
        ],
    )

    assert response.status_code == HTTPStatus.OK
    assert batch_schema["order"] == ["first", "second", "third"]


@pytest.mark.asyncio
async def test_query_concurrency_is_limited(batch_schema):
    app = GraphQL(
        batch_schema["schema"],
        http_handler=GraphQLHTTPHandler(batch_query_concurrency=2),
    )

    async def send_batch():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.post(
                "/",
                json=[
                    {"query": "{ blocked }"},
                    {"query": "{ blocked }"},
                    {"query": "{ blocked }"},
                ],
            )

    request_task = asyncio.create_task(send_batch())
    await asyncio.wait_for(batch_schema["query_started"].wait(), timeout=1)
    assert batch_schema["max_active_queries"]() == 2
    batch_schema["query_can_complete"].set()
    response = await asyncio.wait_for(request_task, timeout=1)

    assert response.status_code == HTTPStatus.OK
    assert all(result["data"] == {"blocked": True} for result in response.json())


@pytest.mark.asyncio
async def test_disconnect_cancels_unfinished_batch_operations(batch_schema):
    cancelled = asyncio.Event()
    finished = asyncio.Event()
    query = QueryType()

    class CleanupExtension(Extension):
        def request_finished(self, context):
            finished.set()

    @query.field("cancellable")
    async def resolve_cancellable(*_):
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    type_defs = """
        type Query { cancellable: Boolean }
    """
    schema = make_executable_schema(type_defs, query)
    app = GraphQL(
        schema,
        http_handler=GraphQLHTTPHandler(extensions=[CleanupExtension]),
    )
    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-type", b"application/json")],
    }
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b'[{"query":"{cancellable}"}]'}
        return {"type": "http.disconnect"}

    messages = []

    async def send(message):
        messages.append(message)

    with pytest.raises(asyncio.CancelledError):
        await app(scope, receive, send)

    await asyncio.wait_for(cancelled.wait(), timeout=1)
    await asyncio.wait_for(finished.wait(), timeout=1)
    assert messages == []


def test_invalid_batch_settings_raise_value_error():
    with pytest.raises(ValueError):
        GraphQLHTTPHandler(max_batch_size=0)

    with pytest.raises(ValueError):
        GraphQLHTTPHandler(batch_query_concurrency=0)
