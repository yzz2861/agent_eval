from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib

import pytest

import aiohttp
from aiohttp import web


def digest_header(data: bytes, *algorithms: str) -> str:
    members = []
    for algorithm in algorithms:
        digest = hashlib.new(algorithm, data).digest()
        encoded = base64.b64encode(digest).decode("ascii")
        members.append(f"{algorithm}=:{encoded}:")
    return ", ".join(members)


BODY = b"archive-content" * 128


@pytest.fixture
def digest_app():
    body = BODY
    compressed = gzip.compress(body, mtime=0)

    async def plain(request: web.Request) -> web.Response:
        return web.Response(
            body=body,
            headers={"Content-Digest": digest_header(body, "sha-256")},
        )

    async def chunked(request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(
            headers={"Content-Digest": digest_header(body, "sha-256")}
        )
        await response.prepare(request)
        await response.write(body[:16])
        await response.write(body[16:])
        return response

    async def gzipped(request: web.Request) -> web.Response:
        return web.Response(
            body=compressed,
            headers={
                "Content-Encoding": "gzip",
                "Content-Digest": digest_header(body, "sha-256"),
            },
        )

    async def bad_gzip(request: web.Request) -> web.Response:
        return web.Response(
            body=b"not gzip",
            headers={
                "Content-Encoding": "gzip",
                "Content-Digest": digest_header(body, "sha-256"),
            },
        )

    async def multiple_algorithms(request: web.Request) -> web.Response:
        return web.Response(
            body=body,
            headers={
                "Content-Digest": digest_header(body, "sha-256", "sha-512")
            },
        )

    async def unsupported_algorithm(request: web.Request) -> web.Response:
        return web.Response(
            body=body,
            headers={"Content-Digest": digest_header(body, "sha-1")},
        )

    async def no_digest(request: web.Request) -> web.Response:
        return web.Response(body=body)

    app = web.Application()
    app.router.add_get("/plain", plain)
    app.router.add_get("/chunked", chunked)
    app.router.add_get("/gzip", gzipped)
    app.router.add_get("/bad-gzip", bad_gzip)
    app.router.add_get("/multiple", multiple_algorithms)
    app.router.add_get("/unsupported", unsupported_algorithm)
    app.router.add_get("/no-digest", no_digest)
    return app


async def test_verify_gzip_read(aiohttp_client, digest_app) -> None:
    client = await aiohttp_client(digest_app)
    session = client.session
    async with session.get(
        "/gzip",
        content_digest_verification=aiohttp.ContentDigestVerification.IF_PRESENT,
    ) as response:
        data = await response.read()
        assert data == BODY
        assert response.content_digest_verified


async def test_verify_chunked_iteration(aiohttp_client, digest_app) -> None:
    client = await aiohttp_client(digest_app)
    chunks: list[bytes] = []
    async with client.get(
        "/chunked",
        content_digest_verification=aiohttp.ContentDigestVerification.IF_PRESENT,
    ) as response:
        assert not response.content_digest_verified
        async for chunk in response.content.iter_chunked(7):
            assert not response.content_digest_verified
            chunks.append(chunk)
    assert b"".join(chunks) == BODY
    assert response.content_digest_verified


async def test_verify_multiple_algorithms(aiohttp_client, digest_app) -> None:
    client = await aiohttp_client(digest_app)
    async with client.get(
        "/multiple",
        content_digest_verification=aiohttp.ContentDigestVerification.IF_PRESENT,
    ) as response:
        assert await response.read() == BODY
        assert response.content_digest_verified


async def test_missing_digest_optional_is_not_verified(
    aiohttp_client, digest_app
) -> None:
    client = await aiohttp_client(digest_app)
    async with client.get(
        "/no-digest",
        content_digest_verification=aiohttp.ContentDigestVerification.IF_PRESENT,
    ) as response:
        assert await response.read() == BODY
        assert not response.content_digest_verified


async def test_missing_digest_required_fails(aiohttp_client, digest_app) -> None:
    client = await aiohttp_client(digest_app)
    with pytest.raises(aiohttp.ContentDigestError):
        response = await client.get(
            "/no-digest",
            content_digest_verification=aiohttp.ContentDigestVerification.REQUIRED,
        )
        await response.read()


async def test_unsupported_digest_optional_is_ignored(
    aiohttp_client, digest_app
) -> None:
    client = await aiohttp_client(digest_app)
    async with client.get(
        "/unsupported",
        content_digest_verification=aiohttp.ContentDigestVerification.IF_PRESENT,
    ) as response:
        assert await response.read() == BODY
        assert not response.content_digest_verified


async def test_bad_compression_fails(aiohttp_client, digest_app) -> None:
    client = await aiohttp_client(digest_app)
    with pytest.raises(aiohttp.ClientPayloadError):
        response = await client.get(
            "/bad-gzip",
            content_digest_verification=aiohttp.ContentDigestVerification.REQUIRED,
        )
        await response.read()


async def test_digest_mismatch_closes_connection() -> None:
    loop = asyncio.get_running_loop()
    body = b"archive-content"
    good_digest = base64.b64encode(hashlib.sha256(b"different").digest()).decode()

    class Protocol(asyncio.Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:
            self.transport = transport

        def data_received(self, data: bytes) -> None:
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: %d\r\n"
                b"Content-Digest: sha-256=:%s:\r\n"
                b"\r\n%s" % (len(body), good_digest.encode(), body)
            )
            self.transport.write(response)

    server = await loop.create_server(Protocol, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    connector = aiohttp.TCPConnector(limit=1)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            response = await session.get(
                f"http://127.0.0.1:{port}/",
                content_digest_verification=(
                    aiohttp.ContentDigestVerification.IF_PRESENT
                ),
            )
            with pytest.raises(aiohttp.ContentDigestError):
                await response.read()
            assert not response.content_digest_verified
            assert not connector._conns
    finally:
        await connector.close()
        server.close()
        await server.wait_closed()


async def test_chunked_digest_mismatch_closes_connection() -> None:
    loop = asyncio.get_running_loop()
    body = b"archive-content"
    digest = base64.b64encode(hashlib.sha256(b"different").digest()).decode()

    class Protocol(asyncio.Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:
            self.transport = transport

        def data_received(self, data: bytes) -> None:
            self.transport.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Content-Digest: sha-256=:%s:\r\n\r\n"
                b"%x\r\n%s\r\n0\r\n\r\n"
                % (digest.encode(), len(body), body)
            )

    server = await loop.create_server(Protocol, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    connector = aiohttp.TCPConnector(limit=1)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            response = await session.get(
                f"http://127.0.0.1:{port}/",
                content_digest_verification=(
                    aiohttp.ContentDigestVerification.IF_PRESENT
                ),
            )
            chunks = []
            with pytest.raises(aiohttp.ContentDigestError):
                async for chunk in response.content.iter_chunked(4):
                    chunks.append(chunk)
            assert b"".join(chunks) == body
            assert not response.content_digest_verified
            assert not connector._conns
    finally:
        await connector.close()
        server.close()
        await server.wait_closed()


async def test_truncated_content_digest_does_not_verify() -> None:
    loop = asyncio.get_running_loop()
    body = b"archive-content"
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()

    class Protocol(asyncio.Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:
            self.transport = transport

        def data_received(self, data: bytes) -> None:
            self.transport.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: %d\r\n"
                b"Content-Digest: sha-256=:%s:\r\n\r\n%s"
                % (len(body) + 1, digest.encode(), body)
            )
            self.transport.close()

    server = await loop.create_server(Protocol, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with aiohttp.ClientSession() as session:
        with pytest.raises(aiohttp.ClientPayloadError):
            await session.get(
                f"http://127.0.0.1:{port}/",
                content_digest_verification=(
                    aiohttp.ContentDigestVerification.REQUIRED
                ),
            )
    server.close()
    await server.wait_closed()


async def test_early_close_does_not_verify() -> None:
    loop = asyncio.get_running_loop()
    body = b"x" * 65536
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()

    class Protocol(asyncio.Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:
            self.transport = transport

        def data_received(self, data: bytes) -> None:
            self.transport.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: %d\r\n"
                b"Content-Digest: sha-256=:%s:\r\n\r\n%s"
                % (len(body), digest.encode(), body)
            )

    server = await loop.create_server(Protocol, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with aiohttp.ClientSession() as session:
        response = await session.get(
            f"http://127.0.0.1:{port}/",
            content_digest_verification=(
                aiohttp.ContentDigestVerification.IF_PRESENT
            ),
        )
        await response.content.read(1)
        assert not response.content_digest_verified
        response.release()
        assert not response.content_digest_verified

    server.close()
    await server.wait_closed()


async def test_early_close_unverified_does_not_return_connection() -> None:
    loop = asyncio.get_running_loop()
    body = b"x" * 65536
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode()

    class Protocol(asyncio.Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:
            self.transport = transport

        def data_received(self, data: bytes) -> None:
            self.transport.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: %d\r\n"
                b"Content-Digest: sha-256=:%s:\r\n\r\n%s"
                % (len(body), digest.encode(), body)
            )

    server = await loop.create_server(Protocol, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    connector = aiohttp.TCPConnector(limit=1)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            response = await session.get(
                f"http://127.0.0.1:{port}/",
                content_digest_verification=(
                    aiohttp.ContentDigestVerification.IF_PRESENT
                ),
            )
            await response.content.read(1)
            response.release()
            assert not connector._conns
    finally:
        await connector.close()
        server.close()
        await server.wait_closed()


async def test_malformed_content_digest_fails() -> None:
    loop = asyncio.get_running_loop()
    body = b"archive-content"

    class Protocol(asyncio.Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:
            self.transport = transport

        def data_received(self, data: bytes) -> None:
            self.transport.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: %d\r\n"
                b"Content-Digest: sha-256=not-a-digest\r\n\r\n%s"
                % (len(body), body)
            )

    server = await loop.create_server(Protocol, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with aiohttp.ClientSession() as session:
        with pytest.raises(aiohttp.ContentDigestError):
            await session.get(
                f"http://127.0.0.1:{port}/",
                content_digest_verification=(
                    aiohttp.ContentDigestVerification.IF_PRESENT
                ),
            )
    server.close()
    await server.wait_closed()
