from __future__ import annotations

import ssl

import hpack
import hyperframe.frame
import pytest
from tests import concurrency

import httpcore
from tests.tls_server import (
    LoopbackBackend,
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



def test_update_ssl_context_closes_idle_connections():
    """
    Idle connections are closed immediately when the SSL context is updated.
    """
    network_backend = httpcore.MockBackend(SINGLE_RESPONSE)

    with httpcore.ConnectionPool(network_backend=network_backend) as pool:
        pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]

        pool.update_ssl_context(ssl.create_default_context())
        assert pool.connections == []

        # New requests create connections in the new generation.
        pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]



def test_update_ssl_context_drains_active_connections():
    """
    Active connections are retired when the SSL context is updated. They
    remain usable for in-flight requests, but are not assigned new requests,
    and are closed once they have drained.
    """
    network_backend = httpcore.MockBackend(SINGLE_RESPONSE)

    with httpcore.ConnectionPool(network_backend=network_backend) as pool:
        with pool.stream("GET", "https://example.com/") as response:
            pool.update_ssl_context(ssl.create_default_context())

            # New requests are assigned to a new connection, not the retired one.
            pool.request("GET", "https://example.com/")
            assert [repr(c) for c in pool.connections] == [
                "<HTTPConnection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 1]>",
                "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>",
            ]

            # The in-flight request on the retired connection completes as usual.
            response.read()
            assert response.content == b"Hello, world!"

        # The retired connection is closed once it has drained.
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]



def test_update_ssl_context_twice():
    """
    Updating the SSL context multiple times retires the connections from
    every previous generation. Connections from earlier generations must
    never be assigned new requests.
    """
    network_backend = httpcore.MockBackend(SINGLE_RESPONSE)

    with httpcore.ConnectionPool(network_backend=network_backend) as pool:
        # First generation, with a connection that is idle on update.
        pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]

        pool.update_ssl_context(ssl.create_default_context())
        assert pool.connections == []

        # Second generation, with a connection that is active on update.
        with pool.stream("GET", "https://example.com/") as response:
            pool.update_ssl_context(ssl.create_default_context())

            # Third generation requests must not reuse either of the
            # previous generation connections.
            pool.request("GET", "https://example.com/")
            assert [repr(c) for c in pool.connections] == [
                "<HTTPConnection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 1]>",
                "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>",
            ]
            response.read()

        # The second generation connection has drained and been closed.
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]



def test_update_ssl_context_with_http2():
    """
    Retired HTTP/2 connections must not accept any new streams. New requests
    are assigned to a new connection in the new generation.
    """
    network_backend = httpcore.MockBackend(
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

    with httpcore.ConnectionPool(network_backend=network_backend) as pool:
        with pool.stream("GET", "https://example.com/") as response:
            assert response.status == 200

            pool.update_ssl_context(ssl.create_default_context())

            # A second request would normally reuse the HTTP/2 connection
            # with a new stream. After the update it requires a new connection.
            second = pool.request("GET", "https://example.com/")
            assert second.status == 200
            assert [repr(c) for c in pool.connections] == [
                "<HTTPConnection ['https://example.com:443', HTTP/2, ACTIVE, Request Count: 1]>",
                "<HTTPConnection ['https://example.com:443', HTTP/2, IDLE, Request Count: 1]>",
            ]

            response.read()
            assert response.content == b"Hello, world!"

        # The retired connection is closed once it has drained.
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/2, IDLE, Request Count: 1]>"
        ]



def test_update_ssl_context_with_queued_request():
    """
    Requests that are still queued when the SSL context is updated are
    assigned to connections in the new generation.
    """
    network_backend = httpcore.MockBackend(SINGLE_RESPONSE)
    statuses = []

    def send_queued_request(pool):
        response = pool.request("GET", "https://example.com/")
        statuses.append(response.status)

    with httpcore.ConnectionPool(
        network_backend=network_backend, max_connections=1
    ) as pool:
        with concurrency.open_nursery() as nursery:
            with pool.stream("GET", "https://example.com/") as response:
                # Queue up a second request while the only connection is busy.
                nursery.start_soon(send_queued_request, pool)
                concurrency.sleep(0.1)

                pool.update_ssl_context(ssl.create_default_context())
                response.read()

            # Closing the response drains the retired connection, allowing
            # the queued request to be assigned to a new connection.

        assert statuses == [200]
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]



def test_update_ssl_context_with_pool_timeout():
    """
    A queued request that is cancelled or times out while a retired
    connection is draining must not be assigned to the retired connection.
    """
    network_backend = httpcore.MockBackend(SINGLE_RESPONSE)

    with httpcore.ConnectionPool(
        network_backend=network_backend, max_connections=1
    ) as pool:
        with pool.stream("GET", "https://example.com/") as response:
            pool.update_ssl_context(ssl.create_default_context())

            # The pool is at its connection limit, and the retired connection
            # cannot acquire new requests, so this request times out queued.
            with pytest.raises(httpcore.PoolTimeout):
                pool.request(
                    "GET",
                    "https://example.com/",
                    extensions={"timeout": {"pool": 0.01}},
                )

            response.read()

        # The retired connection has drained. New requests use a new connection.
        pool.request("GET", "https://example.com/")
        assert [repr(c) for c in pool.connections] == [
            "<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]



def test_update_ssl_context_with_tls_client_certificates():
    """
    Updating the SSL context switches the client certificate presented on
    subsequent connections, while in-flight requests on existing
    connections continue to completion.
    """
    server = RecordingTLSServer()
    try:
        network_backend = LoopbackBackend(server)
        with httpcore.ConnectionPool(
            ssl_context=client_ssl_context("client-a.pem"),
            network_backend=network_backend,
        ) as pool:
            with pool.stream("GET", "https://example.com/stream") as response:
                assert response.status == 200

                # Switch the client certificate while the stream on the
                # original connection is still in-flight.
                pool.update_ssl_context(client_ssl_context("client-b.pem"))

                # Subsequent requests use a new connection, presenting
                # the updated client certificate.
                second = pool.request("GET", "https://example.com/")
                assert second.status == 200

                # The in-flight request on the previous generation
                # connection completes as usual.
                server.release_stream()
                response.read()
                assert response.content == b"Hello, world!"

        assert server.client_cert_names == ["client-a", "client-b"]
        assert server.handshake_failures == 0
    finally:
        server.close()



def test_update_ssl_context_with_failing_handshake():
    """
    If a connection in the new generation fails to establish, the request
    fails rather than falling back to a connection from the previous
    generation.
    """
    server = RecordingTLSServer()
    try:
        network_backend = LoopbackBackend(server)
        with httpcore.ConnectionPool(
            ssl_context=client_ssl_context("client-a.pem"),
            network_backend=network_backend,
        ) as pool:
            with pool.stream("GET", "https://example.com/stream") as response:
                assert response.status == 200

                # Switch to a client certificate that the server does not trust.
                pool.update_ssl_context(client_ssl_context("client-rogue.pem"))

                # The request fails, rather than being assigned to the
                # retired connection from the previous generation.
                with pytest.raises(httpcore.NetworkError):
                    pool.request("GET", "https://example.com/")

                # The in-flight request on the previous generation
                # connection still completes as usual.
                server.release_stream()
                response.read()
                assert response.content == b"Hello, world!"

        for _ in range(100):
            if server.handshake_failures:
                break
            concurrency.sleep(0.01)
        assert server.client_cert_names == ["client-a"]
        assert server.handshake_failures == 1
    finally:
        server.close()
