from __future__ import annotations

import os
from pathlib import Path

import pytest

from starlette.applications import Starlette
from starlette.middleware.bodyreplay import BodyReplayMiddleware
from starlette.requests import BODY_REPLAY_CACHE_SCOPE_KEY, ClientDisconnect, Request, RequestBodyCache
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from tests.types import TestClientFactory


class SignatureMiddleware:
    """Stands in for a signature verification middleware that reads the body first."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            request = Request(scope, receive)
            await request.body()
        await self.app(scope, receive, send)


async def echo_stream(request: Request) -> Response:
    chunks: list[bytes] = []
    async for chunk in request.stream():
        chunks.append(chunk)
    return Response(b"".join(chunks))


def test_middleware_body_then_endpoint_stream(test_client_factory: TestClientFactory) -> None:
    app = BodyReplayMiddleware(
        SignatureMiddleware(Starlette(routes=[Route("/", echo_stream, methods=["POST"])])),
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"hello world")
    assert response.status_code == 200
    assert response.content == b"hello world"


def test_small_body_stays_in_memory(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> PlainTextResponse:
        cache = request.scope[BODY_REPLAY_CACHE_SCOPE_KEY]
        await request.body()
        assert isinstance(cache, RequestBodyCache)
        return PlainTextResponse(str(cache.rolled_to_disk))

    app = BodyReplayMiddleware(Starlette(routes=[Route("/", endpoint, methods=["POST"])]))
    client = test_client_factory(app)

    response = client.post("/", content=b"small")
    assert response.text == "False"


def test_large_body_spooled_to_disk_and_replayed_in_chunks(test_client_factory: TestClientFactory) -> None:
    body = os.urandom(200 * 1024)
    chunk_sizes: list[int] = []

    async def endpoint(request: Request) -> Response:
        cache = request.scope[BODY_REPLAY_CACHE_SCOPE_KEY]
        assert isinstance(cache, RequestBodyCache)
        assert cache.rolled_to_disk
        # A fresh Request replays the cached body from disk in chunks.
        replay = Request(request.scope, request.receive)
        chunks: list[bytes] = []
        async for chunk in replay.stream():
            chunks.append(chunk)
        chunk_sizes.extend(len(chunk) for chunk in chunks if chunk)
        return Response(b"".join(chunks))

    app = BodyReplayMiddleware(
        SignatureMiddleware(Starlette(routes=[Route("/", endpoint, methods=["POST"])])),
        spool_threshold=1024,
        replay_chunk_size=4096,
    )
    client = test_client_factory(app)

    response = client.post("/", content=body)
    assert response.status_code == 200
    assert response.content == body
    # The file-backed body is replayed in bounded chunks, not loaded whole.
    assert len(chunk_sizes) > 1
    assert max(chunk_sizes) <= 4096


def test_middleware_body_then_endpoint_multipart_form(test_client_factory: TestClientFactory) -> None:
    file_content = os.urandom(150 * 1024)

    async def endpoint(request: Request) -> Response:
        async with request.form() as form:
            upload = form["file"]
            assert hasattr(upload, "read")
            return Response(await upload.read())  # type: ignore[attr-defined]

    app = BodyReplayMiddleware(
        SignatureMiddleware(Starlette(routes=[Route("/", endpoint, methods=["POST"])])),
        spool_threshold=1024,
    )
    client = test_client_factory(app)

    response = client.post("/", files={"file": ("upload.bin", file_content)})
    assert response.status_code == 200
    assert response.content == file_content


def test_max_cache_size_returns_413(test_client_factory: TestClientFactory) -> None:
    app = BodyReplayMiddleware(
        Starlette(routes=[Route("/", echo_stream, methods=["POST"])]),
        max_cache_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"12345")
    assert response.status_code == 200
    assert response.content == b"12345"

    response = client.post("/", content=b"123456")
    assert response.status_code == 413
    assert response.text == "Content Too Large"


@pytest.mark.anyio
async def test_max_cache_size_stops_receiving() -> None:
    messages = iter(
        [
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.request", "body": b"5678", "more_body": True},
            {"type": "http.request", "body": b"90ab", "more_body": False},
        ]
    )
    receive_calls = 0

    async def receive() -> Message:
        nonlocal receive_calls
        receive_calls += 1
        return next(messages)

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        await request.body()

    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    middleware = BodyReplayMiddleware(downstream, max_cache_size=5)

    await middleware(scope, receive, send)

    # The third message is never received once the limit is exceeded.
    assert receive_calls == 2
    assert sent[0]["status"] == 413


@pytest.mark.anyio
async def test_network_is_read_exactly_once() -> None:
    messages = iter(
        [
            {"type": "http.request", "body": b"aaa", "more_body": True},
            {"type": "http.request", "body": b"bbb", "more_body": True},
            {"type": "http.request", "body": b"ccc", "more_body": False},
        ]
    )
    receive_calls = 0

    async def receive() -> Message:
        nonlocal receive_calls
        receive_calls += 1
        return next(messages)

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        first = Request(scope, receive)
        await first.body()
        second = Request(scope, receive)
        body = await second.body()
        response = Response(body)
        await response(scope, receive, send)

    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    middleware = BodyReplayMiddleware(downstream)

    await middleware(scope, receive, send)

    assert receive_calls == 3
    assert sent[-1]["body"] == b"aaabbbccc"


@pytest.mark.anyio
async def test_scope_key_removed_and_cache_closed_after_request(tmp_path: Path) -> None:
    captured_scope: Scope = {}

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal captured_scope
        captured_scope = scope
        request = Request(scope, receive)
        await request.body()

    async def receive() -> Message:
        return {"type": "http.request", "body": b"x" * 2048, "more_body": False}

    async def send(message: Message) -> None:
        pass

    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    middleware = BodyReplayMiddleware(downstream, spool_threshold=1024, temp_dir=str(tmp_path))

    await middleware(scope, receive, send)

    assert BODY_REPLAY_CACHE_SCOPE_KEY not in captured_scope
    assert list(tmp_path.iterdir()) == []


def test_cache_file_released_on_exception(test_client_factory: TestClientFactory, tmp_path: Path) -> None:
    async def endpoint(request: Request) -> Response:
        await request.body()
        raise RuntimeError("signature verification failed")

    app = BodyReplayMiddleware(
        Starlette(routes=[Route("/", endpoint, methods=["POST"])]),
        spool_threshold=1024,
        temp_dir=str(tmp_path),
    )
    client = test_client_factory(app, raise_server_exceptions=False)

    response = client.post("/", content=os.urandom(2048))
    assert response.status_code == 500
    assert list(tmp_path.iterdir()) == []


@pytest.mark.anyio
async def test_cache_file_released_on_client_disconnect(tmp_path: Path) -> None:
    messages = iter(
        [
            {"type": "http.request", "body": b"x" * 2048, "more_body": True},
            {"type": "http.disconnect"},
        ]
    )

    async def receive() -> Message:
        return next(messages)

    async def send(message: Message) -> None:
        pass

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        async for _ in request.stream():
            pass  # pragma: no cover

    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    middleware = BodyReplayMiddleware(downstream, spool_threshold=1024, temp_dir=str(tmp_path))

    with pytest.raises(ClientDisconnect):
        await middleware(scope, receive, send)

    assert list(tmp_path.iterdir()) == []


@pytest.mark.anyio
async def test_non_http_scope_passes_through() -> None:
    called = False

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal called
        called = True

    scope: Scope = {"type": "lifespan"}
    middleware = BodyReplayMiddleware(downstream)

    await middleware(scope, None, None)  # type: ignore[arg-type]

    assert called
    assert BODY_REPLAY_CACHE_SCOPE_KEY not in scope


@pytest.mark.anyio
async def test_stream_after_close_raises() -> None:
    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    cache = RequestBodyCache(receive)
    await cache.close()

    with pytest.raises(RuntimeError, match="Request body cache is closed"):
        async for _ in cache.stream():
            pass  # pragma: no cover


def test_replay_is_private_to_the_request(test_client_factory: TestClientFactory) -> None:
    scopes: list[Scope] = []

    async def endpoint(request: Request) -> Response:
        scopes.append(request.scope)
        return Response(await request.body())

    app = BodyReplayMiddleware(Starlette(routes=[Route("/", endpoint, methods=["POST"])]))
    client = test_client_factory(app)

    assert client.post("/", content=b"first").content == b"first"
    assert client.post("/", content=b"second").content == b"second"
    assert len(scopes) == 2
    # Each request gets its own cache instance.
    assert scopes[0] is not scopes[1]
