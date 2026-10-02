from __future__ import annotations

import gzip
import json
from typing import TYPE_CHECKING, Any

import pytest

from litestar import Request, post
from litestar.enums import RequestEncodingType
from litestar.middleware.request_decompression import (
    RequestDecompressionMiddleware,
    RequestDecompressionState,
)
from litestar.status_codes import (
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    HTTP_415_UNSUPPORTED_MEDIA_TYPE,
)
from litestar.testing import create_test_client

if TYPE_CHECKING:
    from litestar.types import Receive, Scope, Send
    from litestar.types.asgi_types import Message, ReceiveMessage


def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)


@post("/body")
async def read_body(request: Request) -> dict[str, Any]:
    state = request.decompression_state
    return {
        "body": (await request.body()).decode(),
        "content_encoding": request.headers.get("content-encoding"),
        "content_length_header": request.headers.get("content-length"),
        "content_length": request.content_length,
        "state": None
        if state is None
        else {
            "content_encoding": state.content_encoding,
            "compressed_content_length": state.compressed_content_length,
            "compressed_bytes_received": state.compressed_bytes_received,
            "decompressed_bytes_emitted": state.decompressed_bytes_emitted,
        },
    }


@post("/json")
async def read_json(data: dict[str, str]) -> dict[str, str]:
    return data


@post("/form")
async def read_form(request: Request) -> dict[str, str]:
    form = await request.form()
    return dict(form)


@post("/stream")
async def read_stream(request: Request) -> dict[str, Any]:
    chunks = [chunk async for chunk in request.stream()]
    return {"chunks": len(chunks), "body": b"".join(chunks).decode()}


def test_gzip_body_is_decompressed() -> None:
    payload = json.dumps({"hello": "world"}).encode()
    compressed = gzip_compress(payload)

    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=compressed, headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_201_CREATED
    assert response.json()["body"] == payload.decode()


def test_gzip_json_body_is_decompressed() -> None:
    payload = json.dumps({"hello": "world"}).encode()

    with create_test_client([read_json], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post(
            "/json",
            content=gzip_compress(payload),
            headers={"content-encoding": "gzip", "content-type": "application/json"},
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {"hello": "world"}


def test_gzip_form_body_is_decompressed() -> None:
    with create_test_client([read_form], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post(
            "/form",
            content=gzip_compress(b"foo=bar&baz=qux"),
            headers={
                "content-encoding": "gzip",
                "content-type": RequestEncodingType.URL_ENCODED.value,
            },
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {"foo": "bar", "baz": "qux"}


def test_gzip_stream_is_decompressed() -> None:
    payload = b"streamed-payload" * 100

    with create_test_client([read_stream], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/stream", content=gzip_compress(payload), headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_201_CREATED
    assert response.json()["body"] == payload.decode()


@pytest.mark.parametrize("content_encoding", [None, "identity"])
def test_passthrough_encodings(content_encoding: str | None) -> None:
    headers = {} if content_encoding is None else {"content-encoding": content_encoding}

    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=b"plain body", headers=headers)

    assert response.status_code == HTTP_201_CREATED
    data = response.json()
    assert data["body"] == "plain body"
    assert data["state"] is None


def test_unsupported_content_encoding() -> None:
    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=b"whatever", headers={"content-encoding": "br"})

    assert response.status_code == HTTP_415_UNSUPPORTED_MEDIA_TYPE
    assert "br" in response.json()["detail"]


def test_original_headers_are_not_visible_downstream() -> None:
    payload = b"hello"
    compressed = gzip_compress(payload)

    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=compressed, headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_201_CREATED
    data = response.json()
    assert data["content_encoding"] is None
    assert data["content_length_header"] is None
    assert data["content_length"] is None


def test_decompression_state_exposes_compressed_and_decompressed_sizes() -> None:
    payload = b"hello" * 100
    compressed = gzip_compress(payload)

    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=compressed, headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_201_CREATED
    state = response.json()["state"]
    assert state["content_encoding"] == "gzip"
    assert state["compressed_content_length"] == len(compressed)
    assert state["compressed_bytes_received"] == len(compressed)
    assert state["decompressed_bytes_emitted"] == len(payload)


def test_truncated_gzip_stream() -> None:
    compressed = gzip_compress(b"hello world")

    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=compressed[:10], headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert "Truncated" in response.json()["detail"]


def test_empty_gzip_body_is_rejected() -> None:
    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=b"", headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert "Truncated" in response.json()["detail"]


def test_bad_checksum() -> None:
    compressed = bytearray(gzip_compress(b"hello world"))
    # corrupt the CRC32 checksum stored in the gzip trailer
    compressed[-8] ^= 0xFF

    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=bytes(compressed), headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert "Malformed" in response.json()["detail"]


def test_not_gzip_data() -> None:
    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=b"this is not gzip", headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert "Malformed" in response.json()["detail"]


def test_trailing_garbage() -> None:
    compressed = gzip_compress(b"hello world") + b"trailing garbage"

    with create_test_client([read_body], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/body", content=compressed, headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert "Trailing" in response.json()["detail"]


def test_handler_request_max_body_size_applies_to_decompressed_size() -> None:
    @post("/limited", request_max_body_size=100)
    async def limited_handler(request: Request) -> str:
        return (await request.body()).decode()

    payload = b"a" * 1000
    compressed = gzip_compress(payload)
    assert len(compressed) < 100  # the compressed payload is well below the limit

    with create_test_client([limited_handler], middleware=[RequestDecompressionMiddleware()]) as client:
        response = client.post("/limited", content=compressed, headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_413_REQUEST_ENTITY_TOO_LARGE


def test_middleware_max_decompressed_size() -> None:
    payload = b"a" * 1000
    compressed = gzip_compress(payload)

    with create_test_client(
        [read_body],
        middleware=[RequestDecompressionMiddleware(max_decompressed_size=100)],
    ) as client:
        response = client.post("/body", content=compressed, headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_413_REQUEST_ENTITY_TOO_LARGE
    assert "100" in response.json()["detail"]


def test_decompressed_size_within_limit_is_accepted() -> None:
    payload = b"a" * 1000
    compressed = gzip_compress(payload)

    with create_test_client(
        [read_body],
        middleware=[RequestDecompressionMiddleware(max_decompressed_size=1000)],
    ) as client:
        response = client.post("/body", content=compressed, headers={"content-encoding": "gzip"})

    assert response.status_code == HTTP_201_CREATED


def make_scope(headers: list[tuple[bytes, bytes]]) -> Scope:
    return {  # type: ignore[return-value]
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": headers,
        "state": {},
    }


def make_receive(messages: list[ReceiveMessage], calls: list[None]) -> Receive:
    queue = list(messages)

    async def receive() -> ReceiveMessage:
        calls.append(None)
        return queue.pop(0)

    return receive


async def noop_send(message: Message) -> None:
    pass


async def test_chunked_gzip_input() -> None:
    payload = b"chunked-payload" * 50
    compressed = gzip_compress(payload)
    # split the compressed payload into uneven chunks
    chunks = [compressed[:5], compressed[5:20], compressed[20:]]
    messages: list[ReceiveMessage] = [
        {"type": "http.request", "body": chunk, "more_body": True} for chunk in chunks[:-1]
    ]
    messages.append({"type": "http.request", "body": chunks[-1], "more_body": False})

    received_chunks = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            assert message["type"] == "http.request"
            received_chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break

    receive_calls: list[None] = []
    middleware = RequestDecompressionMiddleware()
    app = middleware(downstream)
    scope = make_scope([(b"content-encoding", b"gzip"), (b"content-length", str(len(compressed)).encode())])

    await app(scope, make_receive(messages, receive_calls), noop_send)

    assert b"".join(received_chunks) == payload
    # one upstream receive call per downstream receive call: no eager consumption
    assert len(receive_calls) == len(received_chunks)


async def test_receive_is_lazy() -> None:
    compressed = gzip_compress(b"hello")
    messages: list[ReceiveMessage] = [
        {"type": "http.request", "body": compressed, "more_body": False},
    ]
    receive_calls: list[None] = []

    downstream_called = False

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal downstream_called
        downstream_called = True
        # the application chooses to not read the request body at all

    middleware = RequestDecompressionMiddleware()
    app = middleware(downstream)
    scope = make_scope([(b"content-encoding", b"gzip")])

    await app(scope, make_receive(messages, receive_calls), noop_send)

    assert downstream_called
    assert receive_calls == []


async def test_disconnect_is_passed_through() -> None:
    messages: list[ReceiveMessage] = [{"type": "http.disconnect"}]
    received: list[ReceiveMessage] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        received.append(await receive())

    middleware = RequestDecompressionMiddleware()
    app = middleware(downstream)
    scope = make_scope([(b"content-encoding", b"gzip")])

    await app(scope, make_receive(messages, []), noop_send)

    assert received == [{"type": "http.disconnect"}]


async def test_application_may_stop_reading_early() -> None:
    payload = b"a" * 10000
    compressed = gzip_compress(payload)
    halfway = len(compressed) // 2
    messages: list[ReceiveMessage] = [
        {"type": "http.request", "body": compressed[:halfway], "more_body": True},
        {"type": "http.request", "body": compressed[halfway:], "more_body": False},
    ]
    receive_calls: list[None] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        message = await receive()
        assert message["type"] == "http.request"
        # read a single chunk and stop; the middleware must not pull the rest of the body

    middleware = RequestDecompressionMiddleware()
    app = middleware(downstream)
    scope = make_scope([(b"content-encoding", b"gzip")])

    await app(scope, make_receive(messages, receive_calls), noop_send)

    assert len(receive_calls) == 1


async def test_state_is_tracked_on_scope() -> None:
    payload = b"tracked" * 10
    compressed = gzip_compress(payload)
    messages: list[ReceiveMessage] = [{"type": "http.request", "body": compressed, "more_body": False}]

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break

    middleware = RequestDecompressionMiddleware()
    app = middleware(downstream)
    scope = make_scope([(b"content-encoding", b"gzip"), (b"content-length", str(len(compressed)).encode())])

    await app(scope, make_receive(messages, []), noop_send)

    from litestar.utils.scope.state import ScopeState

    state = ScopeState.from_scope(scope).request_decompression
    assert isinstance(state, RequestDecompressionState)
    assert state.compressed_content_length == len(compressed)
    assert state.compressed_bytes_received == len(compressed)
    assert state.decompressed_bytes_emitted == len(payload)
