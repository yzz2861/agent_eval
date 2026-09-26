from __future__ import annotations

import ssl

import hpack
import hyperframe.frame
import pytest
import trio as concurrency

import httpcore
from tests.tls_server import (
    AsyncLoopbackBackend,
    RecordingTLSServer,
    client_ssl_context,
)

SINGLE_RESPONSE = [
    b"HTTP/1.1 200 OK\r\n",
    b"Content-Type: plain/text\r\n",
    b"Content-Length: 13\r\n",
    b"\r\n",
    b"Hello, world!",
]


@pytest.mark.anyio
async def test_update_ssl_context_closes_idle_connections():
    """
    Idle connections are closed immediately when the SSL context is updated.
    """
    network_backend = httpcore.AsyncMockBackend(SINGLE_RESPONSE)

    async with httpcore.AsyncConnectionPool(network_backend=network_backend) as pool:
        await pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]

        await pool.update_ssl_context(ssl.create_default_context())
        assert pool.connections == []

        # New requests create connections in the new generation.
        await pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]


@pytest.mark.anyio
async def test_update_ssl_context_drains_active_connections():
    """
    Active connections are retired when the SSL context is updated. They
    remain usable for in-flight requests, but are not assigned new requests,
    and are closed once they have drained.
    """
    network_backend = httpcore.AsyncMockBackend(SINGLE_RESPONSE)

    async with httpcore.AsyncConnectionPool(network_backend=network_backend) as pool:
        async with pool.stream("GET", "https://example.com/") as response:
            await pool.update_ssl_context(ssl.create_default_context())

            # New requests are assigned to a new connection, not the retired one.
            await pool.request("GET", "https://example.com/")
            assert [repr(c) for c in pool.connections] == [
                "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 1]>",
                "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>",
            ]

            # The in-flight request on the retired connection completes as usual.
            await response.aread()
            assert response.content == b"Hello, world!"

        # The retired connection is closed once it has drained.
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]


@pytest.mark.anyio
async def test_update_ssl_context_twice():
    """
    Updating the SSL context multiple times retires the connections from
    every previous generation. Connections from earlier generations must
    never be assigned new requests.
    """
    network_backend = httpcore.AsyncMockBackend(SINGLE_RESPONSE)

    async with httpcore.AsyncConnectionPool(network_backend=network_backend) as pool:
        # First generation, with a connection that is idle on update.
        await pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]

        await pool.update_ssl_context(ssl.create_default_context())
        assert pool.connections == []

        # Second generation, with a connection that is active on update.
        async with pool.stream("GET", "https://example.com/") as response:
            await pool.update_ssl_context(ssl.create_default_context())

            # Third generation requests must not reuse either of the
            # previous generation connections.
            await pool.request("GET", "https://example.com/")
            assert [repr(c) for c in pool.connections] == [
                "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 1]>",
                "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>",
            ]
            await response.aread()

        # The second generation connection has drained and been closed.
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]


@pytest.mark.anyio
async def test_update_ssl_context_with_http2():
    """
    Retired HTTP/2 connections must not accept any new streams. New requests
    are assigned to a new connection in the new generation.
    """
    network_backend = httpcore.AsyncMockBackend(
        buffer=[
            hyperframe.frame.SettingsFrame().serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=1, data=b"Hello, world!", flags=["END_STREAM"]
            ).serialize(),
        ],
        http2=True,
    )

    async with httpcore.AsyncConnectionPool(network_backend=network_backend) as pool:
        async with pool.stream("GET", "https://example.com/") as response:
            assert response.status == 200

            await pool.update_ssl_context(ssl.create_default_context())

            # A second request would normally reuse the HTTP/2 connection
            # with a new stream. After the update it requires a new connection.
            second = await pool.request("GET", "https://example.com/")
            assert second.status == 200
            assert [repr(c) for c in pool.connections] == [
                "<AsyncHTTPConnection ['https://example.com:443', HTTP/2, ACTIVE, Request Count: 1]>",
                "<AsyncHTTPConnection ['https://example.com:443', HTTP/2, IDLE, Request Count: 1]>",
            ]

            await response.aread()
            assert response.content == b"Hello, world!"

        # The retired connection is closed once it has drained.
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/2, IDLE, Request Count: 1]>"
        ]


@pytest.mark.trio
async def test_update_ssl_context_with_queued_request():
    """
    Requests that are still queued when the SSL context is updated are
    assigned to connections in the new generation.
    """
    network_backend = httpcore.AsyncMockBackend(SINGLE_RESPONSE)
    statuses = []

    async def send_queued_request(pool):
        response = await pool.request("GET", "https://example.com/")
        statuses.append(response.status)

    async with httpcore.AsyncConnectionPool(
        network_backend=network_backend, max_connections=1
    ) as pool:
        async with concurrency.open_nursery() as nursery:
            async with pool.stream("GET", "https://example.com/") as response:
                # Queue up a second request while the only connection is busy.
                nursery.start_soon(send_queued_request, pool)
                await concurrency.sleep(0.1)

                await pool.update_ssl_context(ssl.create_default_context())
                await response.aread()

            # Closing the response drains the retired connection, allowing
            # the queued request to be assigned to a new connection.

        assert statuses == [200]
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]


@pytest.mark.anyio
async def test_update_ssl_context_with_pool_timeout():
    """
    A queued request that is cancelled or times out while a retired
    connection is draining must not be assigned to the retired connection.
    """
    network_backend = httpcore.AsyncMockBackend(SINGLE_RESPONSE)

    async with httpcore.AsyncConnectionPool(
        network_backend=network_backend, max_connections=1
    ) as pool:
        async with pool.stream("GET", "https://example.com/") as response:
            await pool.update_ssl_context(ssl.create_default_context())

            # The pool is at its connection limit, and the retired connection
            # cannot acquire new requests, so this request times out queued.
            with pytest.raises(httpcore.PoolTimeout):
                await pool.request(
                    "GET",
                    "https://example.com/",
                    extensions={"timeout": {"pool": 0.01}},
                )

            await response.aread()

        # The retired connection has drained. New requests use a new connection.
        await pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]


@pytest.mark.trio
async def test_update_ssl_context_with_tls_client_certificates():
    """
    Updating the SSL context switches the client certificate presented on
    subsequent connections, while in-flight requests on existing
    connections continue to completion.
    """
    server = RecordingTLSServer()
    try:
        network_backend = AsyncLoopbackBackend(server)
        async with httpcore.AsyncConnectionPool(
            ssl_context=client_ssl_context("client-a.pem"),
            network_backend=network_backend,
        ) as pool:
            async with pool.stream("GET", "https://example.com/stream") as response:
                assert response.status == 200

                # Switch the client certificate while the stream on the
                # original connection is still in-flight.
                await pool.update_ssl_context(client_ssl_context("client-b.pem"))

                # Subsequent requests use a new connection, presenting
                # the updated client certificate.
                second = await pool.request("GET", "https://example.com/")
                assert second.status == 200

                # The in-flight request on the previous generation
                # connection completes as usual.
                server.release_stream()
                await response.aread()
                assert response.content == b"Hello, world!"

        assert server.client_cert_names == ["client-a", "client-b"]
        assert server.handshake_failures == 0
    finally:
        server.close()


@pytest.mark.trio
async def test_update_ssl_context_with_failing_handshake():
    """
    If a connection in the new generation fails to establish, the request
    fails rather than falling back to a connection from the previous
    generation.
    """
    server = RecordingTLSServer()
    try:
        network_backend = AsyncLoopbackBackend(server)
        async with httpcore.AsyncConnectionPool(
            ssl_context=client_ssl_context("client-a.pem"),
            network_backend=network_backend,
        ) as pool:
            async with pool.stream("GET", "https://example.com/stream") as response:
                assert response.status == 200

                # Switch to a client certificate that the server does not trust.
                await pool.update_ssl_context(client_ssl_context("client-rogue.pem"))

                # The request fails, rather than being assigned to the
                # retired connection from the previous generation.
                with pytest.raises(httpcore.NetworkError):
                    await pool.request("GET", "https://example.com/")

                # The in-flight request on the previous generation
                # connection still completes as usual.
                server.release_stream()
                await response.aread()
                assert response.content == b"Hello, world!"

        for _ in range(100):
            if server.handshake_failures:
                break
            await concurrency.sleep(0.01)
        assert server.client_cert_names == ["client-a"]
        assert server.handshake_failures == 1
    finally:
        server.close()
