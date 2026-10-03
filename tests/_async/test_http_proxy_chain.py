import base64

import pytest

from httpcore import (
    AsyncConnectionPool,
    AsyncMockBackend,
    ConnectError,
    Proxy,
    ProxyError,
)
from tests.proxy_chain_server import (
    ROGUE_CERT,
    ROGUE_KEY,
    OriginServer,
    ProxyServer,
    client_ssl_context,
    server_ssl_context,
    wait_for,
)


@pytest.mark.anyio
async def test_proxy_chain_tunneling_mock_backend():
    """
    A two-hop proxy chain issues a CONNECT request to each proxy in turn.
    """
    network_backend = AsyncMockBackend(
        [
            # The response to the CONNECT request to the first proxy.
            b"HTTP/1.1 200 OK\r\n\r\n",
            # The response to the CONNECT request to the second proxy.
            b"HTTP/1.1 200 OK\r\n\r\n",
            # The response from the origin server, through the tunnel.
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!",
            # A second request reuses the established tunnel.
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!",
        ]
    )

    async with AsyncConnectionPool(
        proxy=[Proxy("http://localhost:8080/"), Proxy("http://localhost:8081/")],
        network_backend=network_backend,
    ) as pool:
        response = await pool.request("GET", "https://example.com/")
        assert response.status == 200
        assert response.content == b"Hello, world!"

        response = await pool.request("GET", "https://example.com/")
        assert response.status == 200
        assert response.content == b"Hello, world!"
        assert len(pool.connections) == 1


@pytest.mark.anyio
async def test_proxy_chain_error_identifies_hop_mock_backend():
    """
    A failure partway through the chain identifies the failing hop,
    and the partially established tunnel is closed.
    """
    network_backend = AsyncMockBackend(
        [
            # The response to the CONNECT request to the first proxy.
            b"HTTP/1.1 200 OK\r\n\r\n",
            # The second proxy refuses the CONNECT request.
            b"HTTP/1.1 407 Proxy Authentication Required\r\n",
            b"Content-Length: 0\r\n\r\n",
        ]
    )

    async with AsyncConnectionPool(
        proxy=[Proxy("http://localhost:8080/"), Proxy("http://localhost:8081/")],
        network_backend=network_backend,
    ) as pool:
        with pytest.raises(ProxyError) as exc_info:
            await pool.request("GET", "https://example.com/")

        message = str(exc_info.value)
        assert "hop 2" in message
        assert "407" in message
        assert pool.connections == []


@pytest.mark.anyio
async def test_proxy_chain_tunneling():
    """
    Send an HTTPS request via a chain of two HTTP proxies.
    """
    with (
        OriginServer(server_ssl_context()) as origin,
        ProxyServer(auth=("outer-user", "outer-pass")) as outer,
        ProxyServer(auth=("inner-user", "inner-pass")) as inner,
    ):
        async with AsyncConnectionPool(
            proxy=[
                Proxy(outer.url, auth=("outer-user", "outer-pass")),
                Proxy(inner.url, auth=("inner-user", "inner-pass")),
            ],
            ssl_context=client_ssl_context(),
        ) as pool:
            response = await pool.request(
                "GET", "https://127.0.0.1:%d/" % origin.port
            )
            assert response.status == 200
            assert response.content == b"Hello, world!"

            # Each proxy in the chain received a single CONNECT request,
            # addressed at the next hop in the chain.
            assert len(outer.requests) == 1
            assert len(inner.requests) == 1
            assert outer.requests[0].method == b"CONNECT"
            assert inner.requests[0].method == b"CONNECT"
            assert outer.requests[0].target == b"127.0.0.1:%d" % inner.port
            assert inner.requests[0].target == b"127.0.0.1:%d" % origin.port

            # Proxy credentials are scoped to their own hop, and are
            # never sent to any other hop or to the origin server.
            outer_auth = b"Basic " + base64.b64encode(b"outer-user:outer-pass")
            inner_auth = b"Basic " + base64.b64encode(b"inner-user:inner-pass")
            assert outer.requests[0].header(b"proxy-authorization") == outer_auth
            assert inner.requests[0].header(b"proxy-authorization") == inner_auth
            assert len(origin.requests) == 1
            assert origin.requests[0].header(b"proxy-authorization") is None


@pytest.mark.anyio
async def test_proxy_chain_connection_reuse():
    """
    A second request to the same origin reuses the established tunnel,
    without issuing any further CONNECT requests.
    """
    with (
        OriginServer(server_ssl_context()) as origin,
        ProxyServer() as outer,
        ProxyServer() as inner,
    ):
        async with AsyncConnectionPool(
            proxy=[Proxy(outer.url), Proxy(inner.url)],
            ssl_context=client_ssl_context(),
        ) as pool:
            response = await pool.request(
                "GET", "https://127.0.0.1:%d/" % origin.port
            )
            assert response.status == 200

            response = await pool.request(
                "GET", "https://127.0.0.1:%d/" % origin.port
            )
            assert response.status == 200
            assert response.content == b"Hello, world!"

            # The second request reused the existing connection,
            # so each proxy only ever saw a single CONNECT request.
            assert len(pool.connections) == 1
            assert len(outer.requests) == 1
            assert len(inner.requests) == 1
            assert len(origin.requests) == 2


@pytest.mark.anyio
async def test_proxy_chain_with_https_proxies():
    """
    Proxy chain hops may themselves use HTTPS, including TLS-in-TLS
    when several hops use HTTPS.
    """
    with (
        OriginServer(server_ssl_context()) as origin,
        ProxyServer(ssl_context=server_ssl_context()) as outer,
        ProxyServer(ssl_context=server_ssl_context()) as inner,
    ):
        async with AsyncConnectionPool(
            proxy=[
                Proxy(outer.url, ssl_context=client_ssl_context()),
                Proxy(inner.url, ssl_context=client_ssl_context()),
            ],
            ssl_context=client_ssl_context(),
        ) as pool:
            response = await pool.request(
                "GET", "https://127.0.0.1:%d/" % origin.port
            )
            assert response.status == 200
            assert response.content == b"Hello, world!"
            assert len(outer.requests) == 1
            assert len(inner.requests) == 1


@pytest.mark.anyio
async def test_proxy_chain_with_three_hops():
    """
    Proxy chains of more than two hops are supported.
    """
    with (
        OriginServer(server_ssl_context()) as origin,
        ProxyServer() as first,
        ProxyServer() as second,
        ProxyServer() as third,
    ):
        async with AsyncConnectionPool(
            proxy=[Proxy(first.url), Proxy(second.url), Proxy(third.url)],
            ssl_context=client_ssl_context(),
        ) as pool:
            response = await pool.request(
                "GET", "https://127.0.0.1:%d/" % origin.port
            )
            assert response.status == 200
            assert response.content == b"Hello, world!"
            assert first.requests[0].target == b"127.0.0.1:%d" % second.port
            assert second.requests[0].target == b"127.0.0.1:%d" % third.port
            assert third.requests[0].target == b"127.0.0.1:%d" % origin.port


@pytest.mark.anyio
async def test_proxy_chain_with_http_origin():
    """
    Plain HTTP requests are also tunnelled end-to-end through the chain.
    """
    with (
        OriginServer() as origin,
        ProxyServer() as outer,
        ProxyServer() as inner,
    ):
        async with AsyncConnectionPool(
            proxy=[Proxy(outer.url), Proxy(inner.url)],
        ) as pool:
            response = await pool.request(
                "GET", "http://127.0.0.1:%d/" % origin.port
            )
            assert response.status == 200
            assert response.content == b"Hello, world!"
            assert len(outer.requests) == 1
            assert len(inner.requests) == 1


@pytest.mark.anyio
async def test_proxy_chain_inner_proxy_authentication_required():
    """
    A 407 response from an inner proxy raises a ProxyError that
    identifies the failing hop, and closes the partial tunnel.
    """
    with (
        OriginServer(server_ssl_context()) as origin,
        ProxyServer() as outer,
        ProxyServer(auth=("inner-user", "inner-pass")) as inner,
    ):
        async with AsyncConnectionPool(
            proxy=[
                Proxy(outer.url),
                Proxy(inner.url, auth=("wrong-user", "wrong-pass")),
            ],
            ssl_context=client_ssl_context(),
        ) as pool:
            with pytest.raises(ProxyError) as exc_info:
                await pool.request("GET", "https://127.0.0.1:%d/" % origin.port)

            message = str(exc_info.value)
            assert "hop 2" in message
            assert "407" in message

            # The partially established tunnel is closed, both on the
            # client and on the outer proxy.
            assert pool.connections == []
            assert wait_for(lambda: outer.active_tunnels == 0)
            assert len(origin.requests) == 0


@pytest.mark.anyio
async def test_proxy_chain_outer_proxy_tls_failure():
    """
    A TLS failure against an HTTPS proxy hop raises a ProxyError
    that identifies the failing hop.
    """
    with (
        ProxyServer(ssl_context=server_ssl_context()) as outer,
        ProxyServer() as inner,
    ):
        async with AsyncConnectionPool(
            proxy=[
                # The outer proxy certificate is not trusted by this
                # SSL context, so the TLS handshake to the first hop fails.
                Proxy(outer.url, ssl_context=client_ssl_context(cafile=ROGUE_CERT)),
                Proxy(inner.url),
            ],
            ssl_context=client_ssl_context(),
        ) as pool:
            with pytest.raises(ProxyError) as exc_info:
                await pool.request("GET", "https://example.com/")

            assert "hop 1" in str(exc_info.value)
            assert pool.connections == []
            assert len(inner.requests) == 0


@pytest.mark.anyio
async def test_proxy_chain_target_tls_verification():
    """
    The TLS certificate of the origin server is verified against the
    pool SSL context, not against any of the proxy SSL contexts.
    """
    with (
        OriginServer(server_ssl_context(certfile=ROGUE_CERT, keyfile=ROGUE_KEY))
        as origin,
        ProxyServer() as outer,
        ProxyServer() as inner,
    ):
        async with AsyncConnectionPool(
            proxy=[Proxy(outer.url), Proxy(inner.url)],
            ssl_context=client_ssl_context(),
        ) as pool:
            # The origin presents a certificate that is not signed by
            # the trusted CA, so the final TLS handshake fails.
            with pytest.raises(ConnectError):
                await pool.request("GET", "https://127.0.0.1:%d/" % origin.port)

            assert pool.connections == []
            assert wait_for(lambda: outer.active_tunnels == 0)
            assert wait_for(lambda: inner.active_tunnels == 0)


@pytest.mark.anyio
async def test_single_proxy_configuration_still_supported():
    """
    Existing single-proxy configurations continue to work.
    """
    with (
        OriginServer(server_ssl_context()) as origin,
        ProxyServer() as proxy_server,
    ):
        async with AsyncConnectionPool(
            proxy=Proxy(proxy_server.url),
            ssl_context=client_ssl_context(),
        ) as pool:
            response = await pool.request(
                "GET", "https://127.0.0.1:%d/" % origin.port
            )
            assert response.status == 200
            assert response.content == b"Hello, world!"
            assert len(proxy_server.requests) == 1
