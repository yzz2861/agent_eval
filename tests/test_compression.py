import asyncio
import gzip

import pytest

from sanic import Sanic
from sanic.compat import Header
from sanic.compression import CompressedStream
from sanic.response import HTTPResponse, text


APP_ID = 0


class RecordingInner:
    def __init__(self):
        self.calls = []
        self.gate = asyncio.Event()

    async def send(self, data, end_stream):
        self.calls.append((data, end_stream))
        await self.gate.wait()


def make_app(name):
    global APP_ID
    APP_ID += 1
    app = Sanic(f"{name}-{APP_ID}")
    app.ctx.first_chunk = asyncio.Event()
    app.ctx.headers_sent = asyncio.Event()
    app.ctx.proceed = asyncio.Event()
    app.ctx.send_final = asyncio.Event()
    return app


def scope(accept_encoding=None, method="GET"):
    headers = []
    if accept_encoding is not None:
        headers.append((b"accept-encoding", accept_encoding.encode()))

    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1234),
        "server": ("localhost", 80),
    }


async def request(app, accept_encoding=None, method="GET"):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.start":
            app.ctx.headers_sent.set()

    app.asgi = True
    await app._startup()
    await app(scope(accept_encoding, method), receive, send)

    start = messages[0]
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    headers = Header(
        (name.decode(), value.decode()) for name, value in start["headers"]
    )
    return start["status"], headers, body, messages


@pytest.mark.asyncio
async def test_disabled_compression_returns_original_bytes():
    app = make_app("disabled-compression")
    payload = b"x" * 1024

    @app.get("/")
    async def handler(request):
        return text(payload.decode())

    status, headers, body, _ = await request(app, "gzip")

    assert status == 200
    assert body == payload
    assert "content-encoding" not in headers
    assert "vary" not in headers


@pytest.mark.asyncio
async def test_normal_response_is_gzip_compressed():
    app = make_app("normal-gzip-compression")
    app.config.COMPRESS = True
    payload = b"compressible " * 96

    @app.get("/")
    async def handler(request):
        return text(
            payload.decode(),
            headers={
                "ETag": '"abc123"',
                "Content-MD5": "ignored",
                "Vary": "Cookie, Accept-Encoding, X-Test",
            },
        )

    status, headers, body, _ = await request(app, "gzip")

    assert status == 200
    assert headers["content-encoding"] == "gzip"
    assert headers["etag"] == 'W/"abc123"'
    assert "content-md5" not in headers
    assert "Cookie" in headers["vary"]
    assert "X-Test" in headers["vary"]
    vary_values = [part.strip().lower() for part in headers["vary"].split(",")]
    assert vary_values.count("accept-encoding") == 1
    assert int(headers["content-length"]) == len(body)
    assert gzip.decompress(body) == payload
    assert body != payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("accept_encoding", "compressed"),
    [
        ("gzip;q=1, identity;q=0.5", True),
        ("gzip;q=0, identity;q=1", False),
        ("gzip, identity;q=0", True),
    ],
)
async def test_encoding_negotiation(accept_encoding, compressed):
    app = make_app("negotiation")
    app.config.COMPRESS = True
    app.config.COMPRESS_MIN_SIZE = 0

    @app.route("/", methods=["GET", "HEAD"])
    async def handler(request):
        return text("hello")

    status, headers, body, _ = await request(app, accept_encoding)

    assert status == 200
    assert ("content-encoding" in headers) is compressed
    if compressed:
        assert gzip.decompress(body) == b"hello"
    else:
        assert body == b"hello"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("accept_encoding", "expected_status", "mimetype"),
    [
        ("identity;q=0, gzip;q=0", 406, "text/plain"),
        ("identity;q=0", 406, "text/html"),
        ("*;q=0", 406, "text/plain"),
        ("gzip;q=1.2", 400, "text/plain"),
    ],
)
async def test_unacceptable_or_invalid_encoding(
    accept_encoding, expected_status, mimetype
):
    app = make_app("unacceptable")
    app.config.COMPRESS = True
    app.config.COMPRESS_MIMETYPES = (mimetype,)

    @app.get("/")
    async def handler(request):
        return text("hello")

    status, headers, _, _ = await request(app, accept_encoding)

    assert status == expected_status
    assert "content-encoding" not in headers


@pytest.mark.asyncio
async def test_threshold_and_allowed_media_type():
    small_app = make_app("below-threshold")
    small_app.config.COMPRESS = True
    small_app.config.COMPRESS_MIN_SIZE = 16

    @small_app.get("/")
    async def small_handler(request):
        return text("small")

    binary_app = make_app("disallowed-mimetype")
    binary_app.config.COMPRESS = True
    binary_app.config.COMPRESS_MIN_SIZE = 16

    @binary_app.get("/")
    async def binary_handler(request):
        return HTTPResponse(
            b"x" * 32,
            content_type="application/octet-stream",
        )

    _, small_headers, small_body, _ = await request(small_app, "gzip")
    _, binary_headers, binary_body, _ = await request(binary_app, "gzip")

    assert small_body == b"small"
    assert "content-encoding" not in small_headers
    assert binary_body == b"x" * 32
    assert "content-encoding" not in binary_headers


@pytest.mark.asyncio
async def test_head_is_negotiated_before_transport_layer():
    app = make_app("head-compression")
    app.config.COMPRESS = True

    @app.route("/", methods=["GET", "HEAD"])
    async def handler(request):
        return text("x" * 1024)

    status, headers, _, _ = await request(
        app, "gzip, identity;q=0", method="HEAD"
    )

    assert status == 200
    assert headers["content-encoding"] == "gzip"


@pytest.mark.asyncio
async def test_existing_encoding_is_not_modified():
    app = make_app("existing-encoding")
    app.config.COMPRESS = True

    @app.get("/")
    async def handler(request):
        return HTTPResponse(
            b"already encoded",
            headers={"Content-Encoding": "br", "Vary": "Cookie"},
        )

    status, headers, body, _ = await request(app, "identity;q=0")

    assert status == 200
    assert headers["content-encoding"] == "br"
    assert headers["vary"] == "Cookie"
    assert body == b"already encoded"


@pytest.mark.asyncio
async def test_range_response_is_sent_as_identity():
    app = make_app("range-response")
    app.config.COMPRESS = True

    @app.get("/")
    async def handler(request):
        return HTTPResponse(
            b"0123456789",
            status=206,
            headers={"Content-Range": "bytes 0-9/20"},
            content_type="text/plain",
        )

    status, headers, body, _ = await request(app, "gzip")

    assert status == 206
    assert "content-encoding" not in headers
    assert headers["vary"] == "Accept-Encoding"
    assert body == b"0123456789"


@pytest.mark.asyncio
async def test_range_response_identity_rejected():
    app = make_app("range-response-rejected")
    app.config.COMPRESS = True

    @app.get("/")
    async def handler(request):
        return HTTPResponse(
            b"0123456789",
            status=206,
            headers={"Content-Range": "bytes 0-9/20"},
            content_type="text/plain",
        )

    status, _, _, _ = await request(app, "identity;q=0")

    assert status == 406


@pytest.mark.asyncio
async def test_no_body_status_is_not_negotiated():
    app = make_app("no-body-status")
    app.config.COMPRESS = True

    @app.get("/")
    async def handler(request):
        return HTTPResponse(status=204)

    status, headers, _, _ = await request(app, "identity;q=0")

    assert status == 204
    assert "content-encoding" not in headers
    assert "vary" not in headers


@pytest.mark.asyncio
@pytest.mark.parametrize("status", (100, 204, 304))
async def test_statuses_without_bodies_skip_compression(status):
    app = make_app(f"no-body-{status}")
    app.config.COMPRESS = True

    @app.get("/")
    async def handler(request):
        return HTTPResponse(status=status)

    response_status, headers, _, _ = await request(app, "gzip, identity;q=0")

    assert response_status == status
    assert "content-encoding" not in headers
    assert "vary" not in headers


@pytest.mark.asyncio
async def test_streaming_compression_starts_before_response_ends():
    app = make_app("streaming-threshold")
    app.config.COMPRESS = True
    app.config.COMPRESS_MIN_SIZE = 128

    @app.get("/")
    async def slow(request):
        response = await request.respond(
            content_type="text/plain; charset=utf-8"
        )
        await response.send(b"a" * 64, end_stream=False)
        app.ctx.first_chunk.set()
        await app.ctx.proceed.wait()
        await response.send(b"b" * 64, end_stream=False)
        await app.ctx.headers_sent.wait()
        await app.ctx.send_final.wait()
        await response.send(b"c" * 64, end_stream=True)

    task = asyncio.create_task(request(app, "gzip"))
    await app.ctx.first_chunk.wait()
    assert not task.done()

    app.ctx.proceed.set()
    await app.ctx.headers_sent.wait()
    assert not task.done()

    app.ctx.send_final.set()
    status, headers, body, messages = await task

    assert status == 200
    assert headers["content-encoding"] == "gzip"
    assert gzip.decompress(body) == b"a" * 64 + b"b" * 64 + b"c" * 64
    assert messages[0]["type"] == "http.response.start"


@pytest.mark.asyncio
async def test_streaming_compression_preserves_backpressure():
    response = HTTPResponse(content_type="text/plain")
    inner = RecordingInner()
    stream = CompressedStream(
        response,
        inner,
        level=6,
        minimum_size=1,
        force=False,
    )

    task = asyncio.create_task(stream.send(b"x" * 64, False))
    await asyncio.sleep(0)
    assert not task.done()

    inner.gate.set()
    await task
    assert inner.calls


@pytest.mark.asyncio
async def test_streaming_headers_before_body_use_negotiated_gzip():
    response = HTTPResponse(content_type="text/plain")
    inner = RecordingInner()
    inner.gate.set()
    stream = CompressedStream(
        response,
        inner,
        level=6,
        minimum_size=512,
        force=False,
    )

    await stream.send(b"", False)

    assert response.headers["content-encoding"] == "gzip"
    assert inner.calls == [(b"", False)]


@pytest.mark.asyncio
async def test_streaming_force_gzip_does_not_wait_for_threshold():
    response = HTTPResponse(content_type="text/plain")
    inner = RecordingInner()
    inner.gate.set()
    stream = CompressedStream(
        response,
        inner,
        level=6,
        minimum_size=512,
        force=True,
    )

    await stream.send(b"hello", True)

    assert response.headers["content-encoding"] == "gzip"
    assert (
        gzip.decompress(b"".join(call[0] for call in inner.calls)) == b"hello"
    )


@pytest.mark.asyncio
async def test_client_disconnect_leaves_no_compression_task():
    response = HTTPResponse(content_type="text/plain")
    inner = RecordingInner()
    stream = CompressedStream(
        response,
        inner,
        level=6,
        minimum_size=1,
        force=False,
    )

    task = asyncio.create_task(stream.send(b"x" * 64, False))
    await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    pending = [
        current_task
        for current_task in asyncio.all_tasks()
        if not current_task.done()
        and current_task is not asyncio.current_task()
    ]
    assert pending == []
