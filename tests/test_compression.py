import asyncio
import gzip
import io

import pytest

from sanic import Compression, Request, Sanic
from sanic.compression import _GzipStream
from sanic.response import HTTPResponse, empty, raw, text


async def asgi_request(
    app: Sanic,
    headers: list[tuple[bytes, bytes]],
    path: str = "/",
):
    messages = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1234),
        "server": ("mockserver", 80),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    app.asgi = True
    await app._startup()
    await app(scope, receive, send)
    return messages


def headers_for(messages):
    return dict(messages[0]["headers"])


@pytest.mark.asyncio
async def test_normal_response_uses_gzip_and_updates_headers(app: Sanic):
    Compression(app, minimum_size=4)
    payload = b"compressible response"

    @app.get("/")
    async def handler(request: Request):
        return raw(
            payload,
            content_type="text/plain",
            headers={
                "Content-Length": str(len(payload)),
                "ETag": '"abc"',
                "Vary": "Cookie",
            },
        )

    messages = await asgi_request(
        app,
        [(b"accept-encoding", b"gzip")],
    )

    headers = headers_for(messages)
    assert messages[0]["status"] == 200
    assert headers[b"content-encoding"] == b"gzip"
    assert headers[b"vary"] == b"Cookie, Accept-Encoding"
    assert headers[b"etag"] == b'W/"abc"'
    assert gzip.decompress(messages[-1]["body"]) == payload
    assert int(headers[b"content-length"]) == len(messages[-1]["body"])


@pytest.mark.asyncio
async def test_small_response_keeps_identity_bytes(app: Sanic):
    Compression(app, minimum_size=100)
    payload = b"small"

    @app.get("/")
    async def handler(request: Request):
        return raw(payload)

    _, response = await app.asgi_client.get(
        "/", headers={"Accept-Encoding": "gzip"}
    )

    assert response.content == payload
    assert "Content-Encoding" not in response.headers
    assert response.headers["Vary"] == "Accept-Encoding"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "headers", "should_vary"),
    (
        ("/empty", [], True),
        ("/encoded", [(b"accept-encoding", b"gzip")], False),
        ("/range", [(b"accept-encoding", b"gzip")], False),
        ("/head", [(b"accept-encoding", b"gzip")], True),
        ("/status", [(b"accept-encoding", b"gzip")], False),
    ),
)
async def test_special_responses_are_not_compressed(
    app: Sanic,
    path: str,
    headers: list[tuple[bytes, bytes]],
    should_vary: bool,
):
    Compression(app)

    @app.get("/empty")
    async def empty_response(request: Request):
        response = empty(status=200)
        response.content_type = "text/plain"
        return response

    @app.get("/encoded")
    async def encoded(request: Request):
        return raw(
            b"already",
            headers={"Content-Encoding": "identity"},
        )

    @app.get("/range")
    async def range_response(request: Request):
        return raw(
            b"range",
            status=206,
            headers={"Content-Range": "bytes 0-4/10"},
        )

    @app.head("/head")
    async def head_response(request: Request):
        return raw(b"head", content_type="text/plain")

    @app.get("/status")
    async def no_body_status(request: Request):
        return empty(status=204)

    messages = await asgi_request(app, headers, path)
    response_headers = headers_for(messages)

    assert b"content-encoding" not in response_headers
    assert (b"vary" in response_headers) is should_vary


@pytest.mark.asyncio
async def test_default_request_uses_identity_bytes(app: Sanic):
    payload = b"compressible response"

    @app.get("/")
    async def handler(request: Request):
        return raw(payload, content_type="text/plain")

    messages = await asgi_request(app, [])

    assert messages[-1]["body"] == payload
    assert b"content-encoding" not in headers_for(messages)


@pytest.mark.asyncio
async def test_media_types_are_configurable(app: Sanic):
    Compression(app, minimum_size=1, media_types=("application/json",))

    @app.get("/json")
    async def json_response(request: Request):
        return raw(b'{"ok":true}', content_type="application/json")

    @app.get("/text")
    async def text_response(request: Request):
        return raw(b"text", content_type="text/plain")

    json_messages = await asgi_request(
        app,
        [(b"accept-encoding", b"gzip")],
        "/json",
    )
    text_messages = await asgi_request(
        app,
        [(b"accept-encoding", b"gzip")],
        "/text",
    )

    assert headers_for(json_messages)[b"content-encoding"] == b"gzip"
    assert b"content-encoding" not in headers_for(text_messages)


@pytest.mark.parametrize(
    "accept_encoding,status_code,content_encoding",
    (
        ("gzip;q=0, identity;q=0", 406, None),
        ("gzip, identity;q=0", 200, "gzip"),
        ("identity;q=0", 406, None),
        ("gzip;q=0.9, identity;q=0.5", 200, "gzip"),
        ("gzip;q=0.5, identity;q=0.9", 200, None),
    ),
)
@pytest.mark.asyncio
async def test_accept_encoding_negotiation(
    app: Sanic,
    accept_encoding: str,
    status_code: int,
    content_encoding: str | None,
):
    Compression(app, minimum_size=100)

    @app.get("/")
    async def handler(request: Request):
        return text("negotiation")

    _, response = await app.asgi_client.get(
        "/",
        headers={"Accept-Encoding": accept_encoding},
    )

    assert response.status_code == status_code
    assert response.headers.get("Content-Encoding") == content_encoding


@pytest.mark.asyncio
async def test_existing_encoding_and_range_are_not_modified(app: Sanic):
    Compression(app)

    @app.get("/encoded")
    async def encoded(request: Request):
        return raw(b"already", headers={"Content-Encoding": "identity"})

    @app.get("/range")
    async def range_response(request: Request):
        return raw(
            b"range",
            status=206,
            headers={"Content-Range": "bytes 0-4/10"},
        )

    for path in ("/encoded", "/range"):
        _, response = await app.asgi_client.get(
            path,
            headers={"Accept-Encoding": "gzip"},
        )
        assert "Vary" not in response.headers or (
            "Accept-Encoding" not in response.headers["Vary"]
        )


@pytest.mark.asyncio
async def test_streaming_response_compresses_without_buffering_all(app: Sanic):
    Compression(app, minimum_size=8)
    app.asgi = True
    first_compressed_chunk = asyncio.Event()
    chunks_received = []

    @app.get("/")
    async def handler(request: Request):
        response = await request.respond(content_type="text/plain")
        await response.send(b"01234567")
        await first_compressed_chunk.wait()
        await response.send(b"89abcdef")
        await response.eof()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"accept-encoding", b"gzip")],
        "client": ("127.0.0.1", 1234),
        "server": ("mockserver", 80),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.body":
            chunks_received.append(message.get("body", b""))
            if len([chunk for chunk in chunks_received if chunk]) == 1:
                first_compressed_chunk.set()

    await app._startup()
    await app(scope, receive, send)

    assert first_compressed_chunk.is_set()
    assert len(chunks_received) == 3
    decompressor = gzip.GzipFile(fileobj=io.BytesIO(b"".join(chunks_received)))
    assert decompressor.read() == b"0123456789abcdef"


@pytest.mark.asyncio
async def test_streaming_client_departure_does_not_leave_task(app: Sanic):
    Compression(app, minimum_size=1)
    tasks_before = set(asyncio.all_tasks())

    @app.get("/")
    async def handler(request: Request):
        response = await request.respond(content_type="text/plain")
        for number in range(100):
            await response.send(f"{number:0100d}".encode())
            await asyncio.sleep(0)

    request_task = asyncio.create_task(
        app.asgi_client.get(
            "/",
            headers={"Accept-Encoding": "gzip"},
        )
    )
    await asyncio.sleep(0)
    request_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await request_task

    assert not (set(asyncio.all_tasks()) - tasks_before)


@pytest.mark.asyncio
async def test_gzip_stream_preserves_backpressure():
    response = HTTPResponse(content_type="text/plain")
    can_send = asyncio.Event()
    can_send.set()
    calls = []

    class SlowStream:
        async def send(self, data, end_stream):
            calls.append((len(data), end_stream))
            await can_send.wait()

    stream = _GzipStream(
        response,
        SlowStream(),
        minimum_size=1,
        compresslevel=1,
        force=False,
    )

    first = asyncio.create_task(stream.send(b"a"))
    await asyncio.sleep(0)
    assert first.done()
    can_send.clear()

    second = asyncio.create_task(stream.send(b"b"))
    await asyncio.sleep(0)
    assert not second.done()

    can_send.set()
    await second
    await stream.send(end_stream=True)

    assert len(calls) == 3
