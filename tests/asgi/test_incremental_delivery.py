import json
from http import HTTPStatus

import pytest
from graphql import ExecutionResult, GraphQLError
from starlette.testclient import TestClient

from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler
from ariadne.asgi.incremental import IncrementalMultipartResponse
from ariadne.types import IncrementalExecutionResults, IncrementalPatch


class PatchStream:
    """Async iterator of patches that tracks its consumption and closing."""

    def __init__(self, patches):
        self._patches = list(patches)
        self.consumed = 0
        self.closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._patches:
            raise StopAsyncIteration
        self.consumed += 1
        return self._patches.pop(0)

    async def aclose(self):
        self.closed = True


@pytest.fixture
def executor():
    return lambda **_: ExecutionResult(data={"hello": "Hello, world!"})


@pytest.fixture
def app(schema, executor):
    http_handler = GraphQLHTTPHandler(executor=executor)
    return GraphQL(schema, http_handler=http_handler)


@pytest.fixture
def client(app):
    return TestClient(app)


def parse_multipart_payloads(text):
    payloads = []
    for segment in text.split("---\r\n"):
        segment = segment.strip()
        if not segment or segment == "--":
            continue
        _, _, payload = segment.partition("\r\n\r\n")
        payload = payload.strip()
        if payload.endswith("--"):
            payload = payload[:-2]
        payloads.append(json.loads(payload))
    return payloads


def test_executor_returning_execution_result_gets_json_response(client):
    response = client.post("/", json={"query": "{ hello(name: \"world\") }"})
    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"data": {"hello": "Hello, world!"}}


def test_executor_receives_schema_data_context_and_root_value(schema):
    received_kwargs = {}

    def executor(**kwargs):
        received_kwargs.update(kwargs)
        return ExecutionResult(data={"status": True})

    http_handler = GraphQLHTTPHandler(executor=executor)
    client = TestClient(GraphQL(schema, http_handler=http_handler))
    response = client.post("/", json={"query": "{ status }"})

    assert response.status_code == HTTPStatus.OK
    assert received_kwargs["schema"] is schema
    assert received_kwargs["data"] == {"query": "{ status }"}
    assert "request" in received_kwargs["context_value"]
    assert received_kwargs["root_value"] is None


def test_executor_can_be_async(schema):
    async def executor(**_):
        return ExecutionResult(data={"status": True})

    http_handler = GraphQLHTTPHandler(executor=executor)
    client = TestClient(GraphQL(schema, http_handler=http_handler))
    response = client.post("/", json={"query": "{ status }"})
    assert response.status_code == HTTPStatus.OK
    assert response.json() == {"data": {"status": True}}


def test_executor_errors_are_formatted_in_json_response(schema):
    def executor(**_):
        return ExecutionResult(data=None, errors=[GraphQLError("Test error")])

    http_handler = GraphQLHTTPHandler(executor=executor)
    client = TestClient(GraphQL(schema, http_handler=http_handler))
    response = client.post("/", json={"query": "{ status }"})
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json() == {
        "data": None,
        "errors": [{"message": "Test error"}],
    }


def test_executor_returning_invalid_result_raises_type_error(schema):
    def executor(**_):
        return {"data": {"status": True}}

    http_handler = GraphQLHTTPHandler(executor=executor)
    client = TestClient(GraphQL(schema, http_handler=http_handler))
    with pytest.raises(TypeError):
        client.post("/", json={"query": "{ status }"})


@pytest.fixture
def incremental_patches():
    return PatchStream(
        [
            IncrementalPatch(
                data={"name": "Alice"},
                path=["user", "friends", 0],
                label="friendsDefer",
                has_next=True,
            ),
            IncrementalPatch(
                data={"name": "Bob"},
                path=["user", "friends", 1],
                label="friendsDefer",
                has_next=False,
            ),
        ]
    )


@pytest.fixture
def incremental_results(incremental_patches):
    return IncrementalExecutionResults(
        initial_result=ExecutionResult(
            data={"user": {"name": "Ann"}},
            errors=[GraphQLError("Initial error")],
        ),
        subsequent_results=incremental_patches,
    )


@pytest.fixture
def incremental_client(schema, incremental_results):
    http_handler = GraphQLHTTPHandler(executor=lambda **_: incremental_results)
    return TestClient(GraphQL(schema, http_handler=http_handler))


def test_incremental_results_are_streamed_as_multipart_response(
    incremental_client, incremental_patches
):
    response = incremental_client.post(
        "/",
        json={"query": "{ user { name } }"},
        headers={"Accept": "multipart/mixed"},
    )
    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"] == 'multipart/mixed; boundary="-"'
    assert "content-length" not in response.headers

    body = response.text
    assert body.endswith("-----\r\n")

    initial, first_patch, second_patch = parse_multipart_payloads(body)
    assert initial == {
        "data": {"user": {"name": "Ann"}},
        "errors": [{"message": "Initial error"}],
        "hasNext": True,
    }
    assert first_patch == {
        "data": {"name": "Alice"},
        "path": ["user", "friends", 0],
        "label": "friendsDefer",
        "hasNext": True,
    }
    assert second_patch == {
        "data": {"name": "Bob"},
        "path": ["user", "friends", 1],
        "label": "friendsDefer",
        "hasNext": False,
    }
    assert incremental_patches.closed


def test_incremental_results_are_rejected_if_client_does_not_accept_multipart(
    incremental_client, incremental_patches
):
    response = incremental_client.post("/", json={"query": "{ user { name } }"})
    assert response.status_code == HTTPStatus.NOT_ACCEPTABLE
    assert incremental_patches.consumed == 0
    assert incremental_patches.closed


def test_has_next_false_is_sent_when_patch_stream_ends_without_final_marker(schema):
    patches = PatchStream([IncrementalPatch(data={"name": "Alice"}, has_next=True)])
    results = IncrementalExecutionResults(
        initial_result=ExecutionResult(data={"user": None}),
        subsequent_results=patches,
    )
    http_handler = GraphQLHTTPHandler(executor=lambda **_: results)
    client = TestClient(GraphQL(schema, http_handler=http_handler))

    response = client.post(
        "/",
        json={"query": "{ user { name } }"},
        headers={"Accept": "multipart/mixed"},
    )
    assert response.status_code == HTTPStatus.OK
    payloads = parse_multipart_payloads(response.text)
    assert payloads[-1] == {"hasNext": False}
    assert patches.closed


@pytest.mark.asyncio
async def test_patch_stream_is_closed_when_response_sending_fails():
    patches = PatchStream(
        [
            IncrementalPatch(data={"name": "Alice"}, has_next=True),
            IncrementalPatch(data={"name": "Bob"}, has_next=True),
        ]
    )
    results = IncrementalExecutionResults(
        initial_result=ExecutionResult(data={"user": None}),
        subsequent_results=patches,
    )
    response = IncrementalMultipartResponse(results)

    sent_messages = []

    async def send(message):
        sent_messages.append(message)
        if len(sent_messages) == 3:
            raise RuntimeError("Client disconnected")

    async def receive():
        return {"type": "http.request"}

    with pytest.raises(RuntimeError):
        await response({"type": "http"}, receive, send)

    assert patches.closed


@pytest.mark.asyncio
async def test_patch_stream_is_closed_when_response_is_not_consumed():
    patches = PatchStream([IncrementalPatch(data={"name": "Alice"})])
    results = IncrementalExecutionResults(
        initial_result=ExecutionResult(data={"user": None}),
        subsequent_results=patches,
    )
    response = IncrementalMultipartResponse(results)

    async def send(message):
        raise RuntimeError("Client disconnected")

    async def receive():
        return {"type": "http.request"}

    with pytest.raises(RuntimeError):
        await response({"type": "http"}, receive, send)

    assert patches.closed
    assert patches.consumed == 0
