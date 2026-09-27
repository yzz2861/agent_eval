import asyncio
import json
from http import HTTPStatus

import pytest
from graphql import ExecutionResult, GraphQLError
from starlette.testclient import TestClient

from ariadne import IncrementalExecutionResult, IncrementalPatch
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler
from ariadne.asgi.incremental import IncrementalDeliveryResponse

MULTIPART_HEADER = {"Accept": "multipart/mixed"}


class StubExecutor:
    """Test executor returning preset results and tracking patch stream."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, schema, document, **kwargs):
        self.calls.append((schema, document, kwargs))
        return self.result


class StubPatchStream:
    """Test patch stream tracking iteration and aclose calls."""

    def __init__(self, patches, state):
        self.patches = patches
        self.state = state

    def __aiter__(self):
        return self._iterate()

    async def _iterate(self):
        for patch in self.patches:
            self.state["yielded"] += 1
            yield patch

    async def aclose(self):
        self.state["closed"] = True


def make_patch_stream(patches, state):
    return StubPatchStream(patches, state)


@pytest.fixture
def stream_state():
    return {"closed": False, "yielded": 0}


@pytest.fixture
def incremental_result(stream_state):
    return IncrementalExecutionResult(
        initial_result=ExecutionResult(data={"hello": "Hello, world!"}),
        subsequent_results=make_patch_stream(
            [
                IncrementalPatch(
                    data={"name": "Bob"},
                    path=["user", "name"],
                    label="userDefer",
                    has_next=True,
                ),
                IncrementalPatch(
                    errors=[GraphQLError("Patch failure")],
                    path=["user", "name"],
                    label="userDefer",
                    has_next=False,
                ),
            ],
            stream_state,
        ),
    )


@pytest.fixture
def incremental_app(schema, incremental_result):
    executor = StubExecutor(incremental_result)
    app = GraphQL(schema, http_handler=GraphQLHTTPHandler(executor=executor))
    app.test_executor = executor
    return app


@pytest.fixture
def incremental_client(incremental_app):
    return TestClient(incremental_app)


def parse_multipart_body(text, boundary="graphql"):
    parts = []
    for chunk in text.split(f"--{boundary}"):
        chunk = chunk.strip()
        if not chunk or chunk == "--":
            continue
        _, _, payload = chunk.partition("\r\n\r\n")
        parts.append(json.loads(payload))
    return parts


def test_executor_returning_normal_result_gets_json_response(schema):
    executor = StubExecutor(ExecutionResult(data={"hello": "Hello, world!"}))
    app = GraphQL(schema, http_handler=GraphQLHTTPHandler(executor=executor))
    client = TestClient(app)

    response = client.post("/", json={"query": "{ hello }"})

    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"data": {"hello": "Hello, world!"}}


def test_executor_returning_normal_result_with_multipart_accept_gets_json(
    schema,
):
    executor = StubExecutor(ExecutionResult(data={"hello": "Hello, world!"}))
    app = GraphQL(schema, http_handler=GraphQLHTTPHandler(executor=executor))
    client = TestClient(app)

    response = client.post("/", json={"query": "{ hello }"}, headers=MULTIPART_HEADER)

    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"data": {"hello": "Hello, world!"}}


def test_incremental_result_is_streamed_as_multipart_mixed(incremental_client):
    response = incremental_client.post(
        "/", json={"query": "{ hello }"}, headers=MULTIPART_HEADER
    )

    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"].startswith("multipart/mixed")
    assert 'boundary="graphql"' in response.headers["content-type"]

    parts = parse_multipart_body(response.text)
    assert len(parts) == 3

    assert parts[0] == {"data": {"hello": "Hello, world!"}, "hasNext": True}
    assert parts[1] == {
        "data": {"name": "Bob"},
        "path": ["user", "name"],
        "label": "userDefer",
        "hasNext": True,
    }
    assert parts[2]["errors"] == [{"message": "Patch failure"}]
    assert parts[2]["path"] == ["user", "name"]
    assert parts[2]["label"] == "userDefer"
    assert parts[2]["hasNext"] is False

    assert response.text.rstrip().endswith("--graphql--")


def test_incremental_result_stream_is_closed_after_response(
    incremental_client,
    stream_state,
):
    response = incremental_client.post(
        "/", json={"query": "{ hello }"}, headers=MULTIPART_HEADER
    )

    assert response.status_code == HTTPStatus.OK
    assert stream_state["yielded"] == 2
    assert stream_state["closed"] is True


def test_incremental_result_without_multipart_accept_is_rejected(
    incremental_client,
    stream_state,
):
    response = incremental_client.post("/", json={"query": "{ hello }"})

    assert response.status_code == HTTPStatus.NOT_ACCEPTABLE
    assert stream_state["yielded"] == 0
    assert stream_state["closed"] is True


def test_incremental_result_with_json_accept_is_rejected(incremental_client):
    response = incremental_client.post(
        "/", json={"query": "{ hello }"}, headers={"Accept": "application/json"}
    )

    assert response.status_code == HTTPStatus.NOT_ACCEPTABLE


def test_incremental_initial_result_errors_are_preserved(schema, stream_state):
    result = IncrementalExecutionResult(
        initial_result=ExecutionResult(
            data=None,
            errors=[GraphQLError("Initial failure")],
        ),
        subsequent_results=make_patch_stream(
            [IncrementalPatch(has_next=False)],
            stream_state,
        ),
    )
    app = GraphQL(
        schema, http_handler=GraphQLHTTPHandler(executor=StubExecutor(result))
    )
    client = TestClient(app)

    response = client.post("/", json={"query": "{ hello }"}, headers=MULTIPART_HEADER)

    assert response.status_code == HTTPStatus.OK
    parts = parse_multipart_body(response.text)
    assert parts[0]["errors"] == [{"message": "Initial failure"}]
    assert parts[0]["hasNext"] is True
    assert parts[1] == {"hasNext": False}


def test_executor_is_called_with_query_execution_arguments(
    incremental_app,
    incremental_client,
    schema,
):
    incremental_client.post("/", json={"query": "{ hello }"}, headers=MULTIPART_HEADER)

    assert len(incremental_app.test_executor.calls) == 1
    call_schema, call_document, call_kwargs = incremental_app.test_executor.calls[0]
    assert call_schema is schema
    assert call_document is not None
    assert "context_value" in call_kwargs
    assert "variable_values" in call_kwargs
    assert "operation_name" in call_kwargs


def test_incremental_result_with_awaitable_executor(schema):
    async def async_executor(schema, document, **kwargs):
        return ExecutionResult(data={"hello": "Hello, world!"})

    app = GraphQL(schema, http_handler=GraphQLHTTPHandler(executor=async_executor))
    client = TestClient(app)

    response = client.post("/", json={"query": "{ hello }"})

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {"data": {"hello": "Hello, world!"}}


def test_incremental_response_uses_custom_headers(stream_state):
    response = IncrementalDeliveryResponse(
        initial_result={"data": {}},
        subsequent_results=make_patch_stream([], stream_state),
        headers={"X-Test-Header": "test-value"},
    )

    headers = {key.decode(): value.decode() for key, value in response.raw_headers}
    assert headers["x-test-header"] == "test-value"
    assert headers["content-type"].startswith("multipart/mixed")


@pytest.mark.asyncio
async def test_disconnect_closes_incremental_patch_stream(stream_state):
    response = IncrementalDeliveryResponse(
        initial_result={"data": {"hello": "Hello, world!"}, "hasNext": True},
        subsequent_results=make_patch_stream([{"hasNext": False}], stream_state),
    )

    sent_messages = []

    async def send(message):
        sent_messages.append(message)

    async def receive():
        return {"type": "http.disconnect"}

    await response({}, receive, send)

    assert stream_state["closed"] is True


@pytest.mark.asyncio
async def test_cancelled_patch_stream_closes_response_gracefully(stream_state):
    class CancelledStream:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise asyncio.CancelledError

        async def aclose(self):
            stream_state["closed"] = True

    response = IncrementalDeliveryResponse(
        initial_result={"data": {}, "hasNext": True},
        subsequent_results=CancelledStream(),
    )

    sent_messages = []

    async def send(message):
        sent_messages.append(message)

    disconnect = asyncio.Event()

    async def receive():
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def disconnect_after_send():
        while not any(m["type"] == "http.response.body" for m in sent_messages):
            await asyncio.sleep(0)
        disconnect.set()

    await asyncio.gather(response({}, receive, send), disconnect_after_send())

    assert stream_state["closed"] is True
    assert sent_messages[-1] == {
        "type": "http.response.body",
        "body": b"",
        "more_body": False,
    }
