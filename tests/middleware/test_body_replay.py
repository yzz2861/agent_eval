from __future__ import annotations

import hashlib
import time

import pytest

from starlette.applications import Starlette
from starlette.datastructures import UploadFile
from starlette.middleware.body_replay import (
    BODY_REPLAY_CACHE_SCOPE_KEY,
    BodyReplayCacheExceeded,
    BodyReplayMiddleware,
    RequestBodyCache,
)
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from tests.types import TestClientFactory


def receive_from_chunks(chunks: list[bytes]) -> Receive:
    messages: list[Message] = [{"type": "http.request", "body": chunk, "more_body": True} for chunk in chunks]
    messages.append({"type": "http.request", "body": b"", "more_body": False})
    iterator = iter(messages)

    async def receive() -> Message:
        return next(iterator, {"type": "http.disconnect"})

    return receive


async def consume_first_pass(cache: RequestBodyCache) -> list[Message]:
    messages = []
    while True:
        message = await cache.receive()
        messages.append(message)
        if message["type"] == "http.request" and not message.get("more_body", False):
            return messages


async def replay_once(cache: RequestBodyCache) -> list[bytes]:
    chunks = []
    while True:
        message = await cache.receive()
        assert message["type"] == "http.request"
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            return chunks


@pytest.mark.anyio
async def test_small_body_stays_in_memory() -> None:
    cache = RequestBodyCache(receive_from_chunks([b"hello ", b"world"]), memory_threshold=1024)
    forwarded = await consume_first_pass(cache)
    assert b"".join(message.get("body", b"") for message in forwarded) == b"hello world"
    assert cache.in_memory
    assert cache.size == 11
    assert b"".join(await replay_once(cache)) == b"hello world"
    await cache.aclose()


@pytest.mark.anyio
async def test_large_body_rolls_over_to_temp_file() -> None:
    chunks = [b"aaa", b"bb", b"ccccc", b"d", b"eeee"]
    body = b"".join(chunks)
    cache = RequestBodyCache(
        receive_from_chunks(chunks),
        memory_threshold=8,
        replay_chunk_size=4,
    )
    await consume_first_pass(cache)
    assert not cache.in_memory
    assert cache.size == len(body)

    replayed = await replay_once(cache)
    # A spilled body is streamed back from disk in bounded chunks, never
    # loaded back into memory as a whole.
    assert all(len(chunk) <= 4 for chunk in replayed)
    assert b"".join(replayed) == body
    # The cache can be replayed by any number of consumers.
    assert b"".join(await replay_once(cache)) == body
    await cache.aclose()


@pytest.mark.anyio
async def test_empty_body_replays() -> None:
    cache = RequestBodyCache(receive_from_chunks([]))
    await consume_first_pass(cache)
    assert cache.in_memory
    assert cache.size == 0
    assert await replay_once(cache) == [b""]
    await cache.aclose()


@pytest.mark.anyio
async def test_cache_hard_limit_stops_receiving() -> None:
    receive_calls = 0

    async def receive() -> Message:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.request", "body": b"12345", "more_body": True}

    cache = RequestBodyCache(receive, max_cache_size=9)
    await cache.receive()
    with pytest.raises(BodyReplayCacheExceeded):
        await cache.receive()
    # The limit stops the cache from pulling more bytes off the network.
    assert receive_calls == 2
    await cache.aclose()


@pytest.mark.anyio
async def test_disconnect_message_is_forwarded() -> None:
    messages = iter([{"type": "http.disconnect"}])

    async def receive() -> Message:
        return next(messages)  # type: ignore[return-value]

    cache = RequestBodyCache(receive)
    assert await cache.receive() == {"type": "http.disconnect"}
    await cache.aclose()


@pytest.mark.anyio
async def test_aclose_releases_temp_file() -> None:
    cache = RequestBodyCache(receive_from_chunks([b"x" * 100]), memory_threshold=1)
    await consume_first_pass(cache)
    assert not cache.in_memory
    file = cache._file
    assert file is not None
    await cache.aclose()
    assert file.closed
    assert cache._file is None
    await cache.aclose()  # Closing twice is a no-op.
    with pytest.raises(RuntimeError, match="closed"):
        await cache.receive()


def test_invalid_configuration() -> None:
    async def receive() -> Message:  # pragma: no cover
        return {"type": "http.disconnect"}

    with pytest.raises(ValueError, match="memory_threshold"):
        RequestBodyCache(receive, memory_threshold=-1)
    with pytest.raises(ValueError, match="max_cache_size"):
        RequestBodyCache(receive, max_cache_size=-1)
    with pytest.raises(ValueError, match="replay_chunk_size"):
        RequestBodyCache(receive, replay_chunk_size=0)


class BodyHashMiddleware:
    """Stands in for a signature verification middleware: reads the whole body."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        body = await request.body()
        scope["body_sha256"] = hashlib.sha256(body).hexdigest()
        scope["body_length"] = len(body)
        await self.app(scope, receive, send)


def test_middleware_reads_body_then_endpoint_reads_multipart(test_client_factory: TestClientFactory) -> None:
    file_content = bytes(range(256)) * 8

    async def upload(request: Request) -> JSONResponse:
        async with request.form() as form:
            upload_file = form["file"]
            assert isinstance(upload_file, UploadFile)
            content = await upload_file.read()
        cache = request.scope[BODY_REPLAY_CACHE_SCOPE_KEY]
        return JSONResponse(
            {
                "file_sha256": hashlib.sha256(content).hexdigest(),
                "body_length": request.scope["body_length"],
                "cache_in_memory": cache.in_memory,
            }
        )

    app = BodyReplayMiddleware(
        BodyHashMiddleware(Starlette(routes=[Route("/", upload, methods=["POST"])])),
        memory_threshold=64,
    )
    client = test_client_factory(app)
    response = client.post("/", files={"file": ("data.bin", file_content, "application/octet-stream")})
    assert response.status_code == 200
    assert response.json()["file_sha256"] == hashlib.sha256(file_content).hexdigest()
    # The middleware consumed the whole multipart body, and the endpoint still
    # parsed it in full: no bytes were lost between the two consumers.
    assert response.json()["body_length"] == int(response.request.headers["content-length"])
    # A body larger than the threshold was spilled out of memory.
    assert response.json()["cache_in_memory"] is False


def test_middleware_reads_body_then_endpoint_streams(test_client_factory: TestClientFactory) -> None:
    async def stream_length(request: Request) -> PlainTextResponse:
        chunks = []
        async for chunk in request.stream():
            chunks.append(chunk)
        cache = request.scope[BODY_REPLAY_CACHE_SCOPE_KEY]
        return PlainTextResponse(f"{len(b''.join(chunks))}:{request.scope['body_length']}:{cache.in_memory}")

    app = BodyReplayMiddleware(
        BodyHashMiddleware(Starlette(routes=[Route("/", stream_length, methods=["POST"])])),
        memory_threshold=100,
    )
    client = test_client_factory(app)
    response = client.post("/", content=b"x" * 5000)
    assert response.status_code == 200
    assert response.text == "5000:5000:False"

    response = client.post("/", content=b"small")
    assert response.text == "5:5:True"


def test_cache_is_released_after_request(test_client_factory: TestClientFactory) -> None:
    caches: list[RequestBodyCache] = []

    async def endpoint(request: Request) -> PlainTextResponse:
        await request.body()
        caches.append(request.scope[BODY_REPLAY_CACHE_SCOPE_KEY])
        return PlainTextResponse("ok")

    app = BodyReplayMiddleware(
        Starlette(routes=[Route("/", endpoint, methods=["POST"])]),
        memory_threshold=1,
    )
    client = test_client_factory(app)
    response = client.post("/", content=b"x" * 100)
    assert response.status_code == 200
    assert len(caches) == 1
    cache = caches[0]
    for _ in range(100):  # The app task may finish just after the response is sent.
        if cache._closed:
            break
        time.sleep(0.01)
    assert cache._closed
    assert cache._file is None


def test_cache_is_released_when_middleware_raises(test_client_factory: TestClientFactory) -> None:
    caches: list[RequestBodyCache] = []

    class RaisingSignatureMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            request = Request(scope, receive)
            await request.body()
            caches.append(scope[BODY_REPLAY_CACHE_SCOPE_KEY])
            raise RuntimeError("invalid signature")

    async def endpoint(request: Request) -> PlainTextResponse:  # pragma: no cover
        return PlainTextResponse("unreachable")

    app = BodyReplayMiddleware(
        RaisingSignatureMiddleware(Starlette(routes=[Route("/", endpoint, methods=["POST"])])),
        memory_threshold=1,
    )
    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.post("/", content=b"x" * 100)
    assert response.status_code == 500
    assert len(caches) == 1
    assert caches[0]._closed
    assert caches[0]._file is None


def test_cache_limit_exceeded_propagates(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> PlainTextResponse:  # pragma: no cover
        await request.body()
        return PlainTextResponse("unreachable")

    app = BodyReplayMiddleware(
        Starlette(routes=[Route("/", endpoint, methods=["POST"])]),
        max_cache_size=10,
    )
    client = test_client_factory(app)
    with pytest.raises(BodyReplayCacheExceeded):
        client.post("/", content=b"x" * 100)


def test_non_http_scope_passthrough(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert scope["type"] == "lifespan"
        assert BODY_REPLAY_CACHE_SCOPE_KEY not in scope
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    middleware = BodyReplayMiddleware(app)
    client = test_client_factory(middleware)
    with client:
        pass
