import ssl

import pytest
import trio as concurrency

import httpcore
from tests.tls_server import (
    STREAM_BODY,
    AsyncSocketPairBackend,
    TLSServer,
    client_ssl_context,
)


async def wait_for(predicate) -> None:
    for _ in range(1000):
        if predicate():
            return
        await concurrency.sleep(0.01)
    raise RuntimeError("Timed out waiting for condition")


@pytest.mark.trio
async def test_update_ssl_context_switches_client_certificate():
    """
    After `update_ssl_context()`, idle connections from the previous
    generation are closed, and new connections use the new SSL context.
    """
    with TLSServer() as server:
        context_a = client_ssl_context("client-a")
        context_b = client_ssl_context("client-b")
        async with httpcore.AsyncConnectionPool(
            ssl_context=context_a, network_backend=AsyncSocketPairBackend(server)
        ) as pool:
            response = await pool.request("GET", server.url)
            assert response.status == 200
            assert len(pool.connections) == 1

            await pool.update_ssl_context(context_b)
            # The idle connection from the previous generation is closed.
            assert pool.connections == []

            response = await pool.request("GET", server.url)
            assert response.status == 200

        assert server.client_cert_cns == ["httpcore-client-a", "httpcore-client-b"]


@pytest.mark.trio
async def test_update_ssl_context_with_in_flight_stream():
    """
    A response that started before `update_ssl_context()` continues to
    stream to completion on its existing connection.
    """
    with TLSServer() as server:
        context_a = client_ssl_context("client-a")
        context_b = client_ssl_context("client-b")
        async with httpcore.AsyncConnectionPool(
            ssl_context=context_a, network_backend=AsyncSocketPairBackend(server)
        ) as pool:
            chunks = []

            async def receive_stream():
                async with pool.stream("GET", f"{server.url}/stream") as response:
                    async for chunk in response.aiter_stream():
                        chunks.append(chunk)

            async with concurrency.open_nursery() as nursery:
                nursery.start_soon(receive_stream)
                # Wait until the response has started streaming.
                await wait_for(lambda: len(chunks) == 1)

                await pool.update_ssl_context(context_b)
                server.stream_release.set()

            # The in-flight stream read to completion on the old connection.
            assert b"".join(chunks) == STREAM_BODY
            # The drained connection was closed once it became idle.
            assert pool.connections == []

            response = await pool.request("GET", server.url)
            assert response.status == 200

        assert server.client_cert_cns == ["httpcore-client-a", "httpcore-client-b"]


@pytest.mark.trio
async def test_update_ssl_context_with_queued_request():
    """
    Requests that are queued but not yet assigned to a connection are
    migrated to the new generation when the SSL context is switched.
    """
    with TLSServer() as server:
        context_a = client_ssl_context("client-a")
        context_b = client_ssl_context("client-b")
        async with httpcore.AsyncConnectionPool(
            ssl_context=context_a,
            max_connections=1,
            network_backend=AsyncSocketPairBackend(server),
        ) as pool:
            bodies = []
            statuses = []

            async def receive_stream():
                async with pool.stream("GET", f"{server.url}/stream") as response:
                    await response.aread()
                    bodies.append(response.content)

            async def queued_request():
                response = await pool.request("GET", server.url)
                statuses.append(response.status)

            async with concurrency.open_nursery() as nursery:
                nursery.start_soon(receive_stream)
                await wait_for(lambda: server.stream_requested.is_set())

                nursery.start_soon(queued_request)
                await wait_for(lambda: "1 queued" in repr(pool))

                await pool.update_ssl_context(context_b)
                server.stream_release.set()

            assert bodies == [STREAM_BODY]
            assert statuses == [200]

        # The queued request went out on a new connection using the new
        # client certificate, rather than the drained connection.
        assert server.client_cert_cns == ["httpcore-client-a", "httpcore-client-b"]


@pytest.mark.trio
async def test_update_ssl_context_twice():
    """
    Switching the SSL context twice in a row must not allow connections
    from a previous generation to be re-used.
    """
    with TLSServer() as server:
        context_a = client_ssl_context("client-a")
        context_b = client_ssl_context("client-b")
        context_a2 = client_ssl_context("client-a")
        async with httpcore.AsyncConnectionPool(
            ssl_context=context_a, network_backend=AsyncSocketPairBackend(server)
        ) as pool:
            async with concurrency.open_nursery() as nursery:
                nursery.start_soon(pool.request, "GET", f"{server.url}/stream")
                await wait_for(lambda: server.stream_requested.is_set())

                await pool.update_ssl_context(context_b)
                await pool.update_ssl_context(context_a2)
                server.stream_release.set()

            response = await pool.request("GET", server.url)
            assert response.status == 200

        # The original connection was not re-lent. A brand new connection
        # was established for the final request.
        assert server.client_cert_cns == ["httpcore-client-a", "httpcore-client-a"]
        assert len(server.connections) == 2


@pytest.mark.trio
async def test_update_ssl_context_with_response_closed_early():
    """
    A response that is closed before being fully read, at around the same
    time as the SSL context is switched, must not allow its connection to
    be re-used.
    """
    with TLSServer() as server:
        context_a = client_ssl_context("client-a")
        context_b = client_ssl_context("client-b")
        async with httpcore.AsyncConnectionPool(
            ssl_context=context_a, network_backend=AsyncSocketPairBackend(server)
        ) as pool:

            async def read_headers_only():
                async with pool.stream("GET", f"{server.url}/stream") as response:
                    # The response is closed without the body being read.
                    assert response.status == 200

            async with concurrency.open_nursery() as nursery:
                nursery.start_soon(read_headers_only)
                await wait_for(lambda: server.stream_requested.is_set())

                await pool.update_ssl_context(context_b)
                server.stream_release.set()

            # The abandoned connection was closed, not returned to the pool.
            assert pool.connections == []

            response = await pool.request("GET", server.url)
            assert response.status == 200

        assert server.client_cert_cns == ["httpcore-client-a", "httpcore-client-b"]


@pytest.mark.trio
async def test_update_ssl_context_with_failing_new_context():
    """
    If connections cannot be established with the new SSL context, then
    connections from the previous generation must not be re-used.
    """
    with TLSServer() as server:
        context_a = client_ssl_context("client-a")
        # A context that does not trust the test CA, so that new
        # connections fail while the TLS configuration is broken.
        broken_context = ssl.create_default_context()
        async with httpcore.AsyncConnectionPool(
            ssl_context=context_a, network_backend=AsyncSocketPairBackend(server)
        ) as pool:
            response = await pool.request("GET", server.url)
            assert response.status == 200

            await pool.update_ssl_context(broken_context)
            with pytest.raises(httpcore.ConnectError):
                await pool.request("GET", server.url)

            # The failed connection is gone, and the retired connection
            # was not re-lent.
            assert pool.connections == []
            await wait_for(lambda: server.failed_handshakes == 1)
            assert server.client_cert_cns == ["httpcore-client-a"]

            # Once a working SSL context is restored the pool recovers.
            await pool.update_ssl_context(client_ssl_context("client-b"))
            response = await pool.request("GET", server.url)
            assert response.status == 200

        assert server.client_cert_cns == ["httpcore-client-a", "httpcore-client-b"]


@pytest.mark.trio
async def test_update_ssl_context_retires_http2_connections():
    """
    A retired HTTP/2 connection must not accept any new streams. New
    requests open a new connection using the new SSL context, even while
    the previous HTTP/2 connection is still active.
    """
    with TLSServer(http2=True) as server:
        context_a = client_ssl_context("client-a")
        context_b = client_ssl_context("client-b")
        async with httpcore.AsyncConnectionPool(
            ssl_context=context_a,
            http2=True,
            network_backend=AsyncSocketPairBackend(server),
        ) as pool:
            bodies = []

            async def receive_stream():
                async with pool.stream("GET", f"{server.url}/stream") as response:
                    await response.aread()
                    bodies.append(response.content)

            async with concurrency.open_nursery() as nursery:
                nursery.start_soon(receive_stream)
                await wait_for(lambda: server.stream_requested.is_set())

                await pool.update_ssl_context(context_b)

                # Sent while the previous HTTP/2 connection is still active.
                response = await pool.request("GET", server.url)
                assert response.status == 200
                server.stream_release.set()

            assert bodies == [STREAM_BODY]

        connections = server.connections
        assert server.client_cert_cns == ["httpcore-client-a", "httpcore-client-b"]
        assert connections[0].alpn_protocol == "h2"
        assert connections[1].alpn_protocol == "h2"
        # The retired HTTP/2 connection only ever served the first stream.
        assert connections[0].request_count == 1
        assert connections[1].request_count == 1
