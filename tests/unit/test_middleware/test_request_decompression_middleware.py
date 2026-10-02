import asyncio
import gzip
import zlib
from types import SimpleNamespace

import pytest

from litestar import MediaType, Request, post
from litestar.middleware.request_decompression import (
    REQUEST_DECOMPRESSION_SCOPE_KEY,
    RequestDecompressionMiddleware,
)
from litestar.status_codes import (
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    HTTP_415_UNSUPPORTED_MEDIA_TYPE,
)
from litestar.testing import create_test_client


@post("/", request_max_body_size=100)
async def handler(request: Request) -> dict[str, object]:
    info = request.scope["state"][REQUEST_DECOMPRESSION_SCOPE_KEY]
    body = await request.body()
    return {
        "body": body.decode(),
        "headers_content_encoding": request.headers.get("content-encoding"),
        "headers_content_length": request.headers.get("content-length"),
        "content_length": request.content_length,
        "content_encoding": request.content_encoding,
        "compressed_content_length": request.compressed_content_length,
        "compressed_bytes_received": request.compressed_bytes_received,
        "decompressed_content_length": request.decompressed_content_length,
    }


def test_gzip_request_is_decompressed() -> None:
    body = b"hello world"
    compressed = gzip.compress(body)
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/",
            content=compressed,
            headers={
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            },
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {
        "body": body.decode(),
        "headers_content_encoding": None,
        "headers_content_length": None,
        "content_length": None,
        "content_encoding": "gzip",
        "compressed_content_length": len(compressed),
        "decompressed_content_length": len(body),
        "compressed_bytes_received": len(compressed),
    }


def test_identity_request_is_counted() -> None:
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/",
            content=b"hello",
            headers={"content-encoding": "identity"},
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {
        "body": "hello",
        "headers_content_encoding": None,
        "headers_content_length": "5",
        "content_length": 5,
        "content_encoding": "identity",
        "compressed_content_length": 5,
        "decompressed_content_length": 5,
        "compressed_bytes_received": 5,
    }


def test_limit_uses_decompressed_size() -> None:
    body = b"x" * 101
    compressed = gzip.compress(body)
    assert len(compressed) < 100
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/", content=compressed, headers={"content-encoding": "gzip"}
        )

    assert response.status_code == HTTP_413_REQUEST_ENTITY_TOO_LARGE


def test_limit_allows_gzip_body_at_exact_limit() -> None:
    body = b"x" * 100
    compressed = gzip.compress(body)
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/", content=compressed, headers={"content-encoding": "gzip"}
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json()["body"] == body.decode()


@pytest.mark.parametrize(
    ("mutation", "detail"),
    (
        ("truncate", "ended prematurely"),
        ("crc", "checksum"),
        ("length", "checksum"),
        ("garbage", "Trailing data"),
    ),
)
def test_invalid_gzip_returns_400(mutation: str, detail: str) -> None:
    compressed = bytearray(gzip.compress(b"hello world"))
    if mutation == "truncate":
        compressed = compressed[:-8]
    elif mutation == "crc":
        compressed[-8] ^= 0xFF
    elif mutation == "length":
        compressed[-1] ^= 0xFF
    else:
        compressed.extend(b"garbage")

    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/",
            content=bytes(compressed),
            headers={"content-encoding": "gzip"},
        )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert detail in response.json()["detail"]


def test_concatenated_gzip_members_are_supported() -> None:
    compressed = gzip.compress(b"hello ") + gzip.compress(b"world")
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/", content=compressed, headers={"content-encoding": "gzip"}
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json()["body"] == "hello world"


def test_concatenated_gzip_members_split_across_events_are_supported() -> None:
    compressed = gzip.compress(b"one") + gzip.compress(b"two")
    first_compressed = compressed[: len(gzip.compress(b"one")) + 1]
    events = [
        {
            "type": "http.request",
            "body": first_compressed,
            "more_body": True,
        },
        {
            "type": "http.request",
            "body": compressed[len(first_compressed) :],
            "more_body": False,
        },
    ]
    seen_bodies = []
    receive_calls = 0

    async def receive():
        nonlocal receive_calls
        event = events[receive_calls]
        receive_calls += 1
        return event

    async def app(scope, receive, send):  # noqa: ANN001, ANN202
        while True:
            event = await receive()
            seen_bodies.append(event["body"])
            if not event.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    scope = {
        "type": "http",
        "headers": [(b"content-encoding", b"gzip")],
        "route_handler": SimpleNamespace(request_max_body_size=None),
        "state": {},
    }

    async def send(event):  # noqa: ANN001, ANN202
        return None

    asyncio.run(RequestDecompressionMiddleware(app)(scope, receive, send))

    assert receive_calls == 2
    assert b"".join(seen_bodies) == b"onetwo"


@post("/form", request_max_body_size=100)
async def form_handler(request: Request) -> dict[str, str]:
    form = await request.form()
    return {"a": form["a"], "b": form["b"]}


def test_gzipped_form_is_decoded() -> None:
    compressed = gzip.compress(b"a=1&b=two")
    with create_test_client(
        [form_handler],
        middleware=[RequestDecompressionMiddleware],
    ) as client:
        response = client.post(
            "/form",
            content=compressed,
            headers={
                "content-encoding": "gzip",
                "content-type": "application/x-www-form-urlencoded",
            },
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {"a": "1", "b": "two"}


@post("/json", media_type=MediaType.JSON, request_max_body_size=100)
async def json_handler(data: dict[str, str]) -> dict[str, str]:
    return data


def test_gzipped_json_is_decoded() -> None:
    compressed = gzip.compress(b'{"message":"hello"}')
    with create_test_client(
        [json_handler],
        middleware=[RequestDecompressionMiddleware],
    ) as client:
        response = client.post(
            "/json",
            content=compressed,
            headers={"content-encoding": "gzip", "content-type": MediaType.JSON},
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {"message": "hello"}


@post("/request-stream", request_max_body_size=100_000)
async def request_stream_handler(request: Request) -> dict[str, object]:
    chunks = [chunk async for chunk in request.stream() if chunk]
    return {"body": b"".join(chunks).decode(), "chunk_count": len(chunks)}


def test_gzipped_request_stream_is_decoded() -> None:
    compressed = gzip.compress(b"streamed body")
    with create_test_client(
        [request_stream_handler],
        middleware=[RequestDecompressionMiddleware],
    ) as client:
        response = client.post(
            "/request-stream",
            content=compressed,
            headers={"content-encoding": "gzip"},
        )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {"body": "streamed body", "chunk_count": 1}


def test_gzip_stream_does_not_eagerly_consume_request() -> None:
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    first_compressed = compressor.compress(b"a" * 10_000) + compressor.flush(
        zlib.Z_SYNC_FLUSH
    )
    second_compressed = compressor.compress(b"b" * 10_000) + compressor.flush(
        zlib.Z_FINISH
    )
    events = [
        {"type": "http.request", "body": first_compressed, "more_body": True},
        {"type": "http.request", "body": second_compressed, "more_body": False},
    ]
    receive_calls = 0

    async def receive():
        nonlocal receive_calls
        receive_calls += 1
        return events[receive_calls - 1]

    seen_events = []

    async def app(scope, receive, send):  # noqa: ANN001, ANN202
        event = await receive()
        seen_events.append(event)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent = []
    scope = {
        "type": "http",
        "headers": [(b"content-encoding", b"gzip"), (b"content-length", b"999")],
        "route_handler": SimpleNamespace(request_max_body_size=None),
        "state": {},
    }
    middleware = RequestDecompressionMiddleware(app)

    async def send(event):  # noqa: ANN001, ANN202
        sent.append(event)

    asyncio.run(middleware(scope, receive, send))

    assert receive_calls == 1
    assert seen_events[0]["body"] == b"a" * 10_000
    assert seen_events[0]["more_body"] is True
    assert scope["headers"] == []


def test_chunked_gzip_is_fully_reassembled() -> None:
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    compressed = (
        compressor.compress(b"first")
        + compressor.compress(b" second")
        + compressor.flush(zlib.Z_FINISH)
    )
    first_compressed = compressed[: len(compressed) // 2]
    second_compressed = compressed[len(first_compressed) :]
    events = [
        {"type": "http.request", "body": first_compressed, "more_body": True},
        {"type": "http.request", "body": second_compressed, "more_body": False},
    ]
    receive_calls = 0
    seen_bodies = []

    async def receive():
        nonlocal receive_calls
        receive_calls += 1
        return events[receive_calls - 1]

    async def app(scope, receive, send):  # noqa: ANN001, ANN202
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            seen_bodies.append(event["body"])
            if not event.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    scope = {
        "type": "http",
        "headers": [(b"content-encoding", b"gzip")],
        "route_handler": SimpleNamespace(request_max_body_size=None),
        "state": {},
    }

    async def send(event):  # noqa: ANN001, ANN202
        return None

    asyncio.run(RequestDecompressionMiddleware(app)(scope, receive, send))

    assert receive_calls == 2
    assert b"".join(seen_bodies) == b"first second"


def test_disconnect_is_passed_through_without_reading_further() -> None:
    calls = 0

    async def receive():
        nonlocal calls
        calls += 1
        return {"type": "http.disconnect"}

    seen_events = []

    async def app(scope, receive, send):  # noqa: ANN001, ANN202
        seen_events.append(await receive())

    scope = {
        "type": "http",
        "headers": [(b"content-encoding", b"gzip")],
        "route_handler": SimpleNamespace(request_max_body_size=None),
        "state": {},
    }

    async def send(event):  # noqa: ANN001, ANN202
        return None

    asyncio.run(RequestDecompressionMiddleware(app)(scope, receive, send))

    assert calls == 1
    assert seen_events == [{"type": "http.disconnect"}]


def test_unsupported_encoding_returns_415() -> None:
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/", content=b"hello", headers={"content-encoding": "br"}
        )

    assert response.status_code == HTTP_415_UNSUPPORTED_MEDIA_TYPE


def test_invalid_content_length_returns_400() -> None:
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/",
            content=b"hello",
            headers={"content-encoding": "gzip", "content-length": "invalid"},
        )

    assert response.status_code == HTTP_400_BAD_REQUEST


def test_empty_gzip_stream_returns_400() -> None:
    with create_test_client(
        [handler], middleware=[RequestDecompressionMiddleware]
    ) as client:
        response = client.post(
            "/",
            content=b"",
            headers={"content-encoding": "gzip"},
        )

    assert response.status_code == HTTP_400_BAD_REQUEST
