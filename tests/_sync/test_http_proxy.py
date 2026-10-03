import ssl
import typing

import hpack
import hyperframe.frame
import pytest

import httpcore
from httpcore import (
    SOCKET_OPTION,
    ConnectionPool,
    MockBackend,
    MockStream,
    NetworkStream,
    Origin,
    Proxy,
    ProxyError,
)


class ChainMockStream(MockStream):
    def __init__(
        self,
        backend: "ChainMockBackend",
        responses: list[bytes],
    ) -> None:
        super().__init__([])
        self._backend = backend
        self._closed = False

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> NetworkStream:
        self._backend.tls_hostnames.append(server_hostname)
        self._backend.ssl_contexts.append(ssl_context)
        return self

    def read(self, max_bytes: int, timeout: typing.Optional[float] = None) -> bytes:
        if self._closed:
            from httpcore._exceptions import ReadError

            raise ReadError("Connection closed")
        return self._backend.next_response()

    def write(self, buffer: bytes, timeout: typing.Optional[float] = None) -> None:
        self._backend.writes[-1] += buffer

    def close(self) -> None:
        self._closed = True
        self._backend.closed_streams.append(self)
        super().close()


class ChainMockBackend(MockBackend):
    def __init__(
        self,
        connect_responses: list[bytes],
        final_responses: list[bytes],
    ) -> None:
        super().__init__(connect_responses)
        self.connect_responses = connect_responses
        self.final_responses = list(final_responses)
        self.response_queue = list(connect_responses)
        self.writes: list[bytes] = []
        self.tls_hostnames: list[str | None] = []
        self.ssl_contexts: list[ssl.SSLContext] = []
        self.connect_attempts = 0
        self.closed_streams: list[ChainMockStream] = []

    def next_response(self) -> bytes:
        if not self.response_queue:
            self.response_queue.extend(self.final_responses)
        return self.response_queue.pop(0)

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: typing.Optional[float] = None,
        local_address: typing.Optional[str] = None,
        socket_options: typing.Optional[typing.Iterable[SOCKET_OPTION]] = None,
    ) -> NetworkStream:
        self.connect_attempts += 1
        self.writes.append(b"")
        return ChainMockStream(self, [])


class TLSErrorMockStream(ChainMockStream):
    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> NetworkStream:
        from httpcore._exceptions import ConnectError

        raise ConnectError("TLS handshake failed")


class TLSErrorMockBackend(ChainMockBackend):
    def __init__(self) -> None:
        super().__init__([], [])

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: typing.Optional[float] = None,
        local_address: typing.Optional[str] = None,
        socket_options: typing.Optional[typing.Iterable[SOCKET_OPTION]] = None,
    ) -> NetworkStream:
        self.connect_attempts += 1
        return TLSErrorMockStream(self, [])



def test_proxy_forwarding():
    """
    Send an HTTP request via a proxy.
    """
    network_backend = MockBackend(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )

    with ConnectionPool(
        proxy=Proxy("http://localhost:8080/"),
        max_connections=10,
        network_backend=network_backend,
    ) as proxy:
        # Sending an intial request, which once complete will return to the pool, IDLE.
        with proxy.stream("GET", "http://example.com/") as response:
            info = [repr(c) for c in proxy.connections]
            assert info == [
                "<ForwardHTTPConnection ['http://localhost:8080', HTTP/1.1, ACTIVE, Request Count: 1]>"
            ]
            response.read()

        assert response.status == 200
        assert response.content == b"Hello, world!"
        info = [repr(c) for c in proxy.connections]
        assert info == [
            "<ForwardHTTPConnection ['http://localhost:8080', HTTP/1.1, IDLE, Request Count: 1]>"
        ]
        assert proxy.connections[0].is_idle()
        assert proxy.connections[0].is_available()
        assert not proxy.connections[0].is_closed()

        # A connection on a forwarding proxy can only handle HTTP requests to the same origin.
        assert proxy.connections[0].can_handle_request(
            Origin(b"http", b"example.com", 80)
        )
        assert not proxy.connections[0].can_handle_request(
            Origin(b"http", b"other.com", 80)
        )
        assert not proxy.connections[0].can_handle_request(
            Origin(b"https", b"example.com", 443)
        )
        assert not proxy.connections[0].can_handle_request(
            Origin(b"https", b"other.com", 443)
        )



def test_proxy_tunneling():
    """
    Send an HTTPS request via a proxy.
    """
    network_backend = MockBackend(
        [
            # The initial response to the proxy CONNECT
            b"HTTP/1.1 200 OK\r\n\r\n",
            # The actual response from the remote server
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )

    with ConnectionPool(
        proxy=Proxy("http://localhost:8080/"),
        network_backend=network_backend,
    ) as proxy:
        # Sending an intial request, which once complete will return to the pool, IDLE.
        with proxy.stream("GET", "https://example.com/") as response:
            info = [repr(c) for c in proxy.connections]
            assert info == [
                "<TunnelHTTPConnection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 1]>"
            ]
            response.read()

        assert response.status == 200
        assert response.content == b"Hello, world!"
        info = [repr(c) for c in proxy.connections]
        assert info == [
            "<TunnelHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]
        assert proxy.connections[0].is_idle()
        assert proxy.connections[0].is_available()
        assert not proxy.connections[0].is_closed()

        # A connection on a tunneled proxy can only handle HTTPS requests to the same origin.
        assert not proxy.connections[0].can_handle_request(
            Origin(b"http", b"example.com", 80)
        )
        assert not proxy.connections[0].can_handle_request(
            Origin(b"http", b"other.com", 80)
        )
        assert proxy.connections[0].can_handle_request(
            Origin(b"https", b"example.com", 443)
        )
        assert not proxy.connections[0].can_handle_request(
            Origin(b"https", b"other.com", 443)
        )


# We need to adapt the mock backend here slightly in order to deal
# with the proxy case. We do not want the initial connection to the proxy
# to indicate an HTTP/2 connection, but we do want it to indicate HTTP/2
# once the SSL upgrade has taken place.
class HTTP1ThenHTTP2Stream(MockStream):
    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: typing.Optional[str] = None,
        timeout: typing.Optional[float] = None,
    ) -> NetworkStream:
        self._http2 = True
        return self


class HTTP1ThenHTTP2Backend(MockBackend):
    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: typing.Optional[float] = None,
        local_address: typing.Optional[str] = None,
        socket_options: typing.Optional[typing.Iterable[SOCKET_OPTION]] = None,
    ) -> NetworkStream:
        return HTTP1ThenHTTP2Stream(list(self._buffer))



def test_proxy_tunneling_http2():
    """
    Send an HTTP/2 request via a proxy.
    """
    network_backend = HTTP1ThenHTTP2Backend(
        [
            # The initial response to the proxy CONNECT
            b"HTTP/1.1 200 OK\r\n\r\n",
            # The actual response from the remote server
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
    )

    with ConnectionPool(
        proxy=Proxy("http://localhost:8080/"),
        network_backend=network_backend,
        http2=True,
    ) as proxy:
        # Sending an intial request, which once complete will return to the pool, IDLE.
        with proxy.stream("GET", "https://example.com/") as response:
            info = [repr(c) for c in proxy.connections]
            assert info == [
                "<TunnelHTTPConnection ['https://example.com:443', HTTP/2, ACTIVE, Request Count: 1]>"
            ]
            response.read()

        assert response.status == 200
        assert response.content == b"Hello, world!"
        info = [repr(c) for c in proxy.connections]
        assert info == [
            "<TunnelHTTPConnection ['https://example.com:443', HTTP/2, IDLE, Request Count: 1]>"
        ]
        assert proxy.connections[0].is_idle()
        assert proxy.connections[0].is_available()
        assert not proxy.connections[0].is_closed()

        # A connection on a tunneled proxy can only handle HTTPS requests to the same origin.
        assert not proxy.connections[0].can_handle_request(
            Origin(b"http", b"example.com", 80)
        )
        assert not proxy.connections[0].can_handle_request(
            Origin(b"http", b"other.com", 80)
        )
        assert proxy.connections[0].can_handle_request(
            Origin(b"https", b"example.com", 443)
        )
        assert not proxy.connections[0].can_handle_request(
            Origin(b"https", b"other.com", 443)
        )



def test_proxy_tunneling_with_403():
    """
    Send an HTTPS request via a proxy.
    """
    network_backend = MockBackend(
        [
            b"HTTP/1.1 403 Permission Denied\r\n" b"\r\n",
        ]
    )

    with ConnectionPool(
        proxy=Proxy("http://localhost:8080/"),
        network_backend=network_backend,
    ) as proxy:
        with pytest.raises(ProxyError) as exc_info:
            proxy.request("GET", "https://example.com/")
        assert str(exc_info.value) == "403 Permission Denied"
        assert not proxy.connections



def test_proxy_tunneling_with_auth():
    """
    Send an authenticated HTTPS request via a proxy.
    """
    network_backend = MockBackend(
        [
            # The initial response to the proxy CONNECT
            b"HTTP/1.1 200 OK\r\n\r\n",
            # The actual response from the remote server
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )

    with ConnectionPool(
        proxy=Proxy(
            url="http://localhost:8080/",
            auth=("username", "password"),
        ),
        network_backend=network_backend,
    ) as proxy:
        response = proxy.request("GET", "https://example.com/")
        assert response.status == 200
        assert response.content == b"Hello, world!"


def test_proxy_headers():
    proxy = Proxy(
        url="http://localhost:8080/",
        auth=("username", "password"),
    )
    assert proxy.headers == [
        (b"Proxy-Authorization", b"Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
    ]



def test_proxy_chain_headers_sni_and_reuse():
    network_backend = ChainMockBackend(
        [
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        ],
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 5\r\n",
            b"\r\n",
            b"hello",
        ]
    )
    outer_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    inner_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    destination_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    chain = httpcore.ProxyChain(
        [
            httpcore.Proxy(
                "https://outer.example:8080/",
                auth=("outer", "secret"),
                ssl_context=outer_context,
            ),
            httpcore.Proxy(
                "https://inner.example:8081/",
                auth=("inner", "secret"),
                ssl_context=inner_context,
            ),
        ]
    )

    with ConnectionPool(
        proxy_chain=chain,
        ssl_context=destination_context,
        network_backend=network_backend,
    ) as pool:
        response = pool.request("GET", "https://destination.example/")
        assert response.content == b"hello"
        response = pool.request("GET", "https://destination.example/")
        assert response.content == b"hello"

        assert len(pool.connections) == 1
        assert network_backend.connect_attempts == 1
        assert network_backend.tls_hostnames == [
            "outer.example",
            "inner.example",
            "destination.example",
        ]
        assert network_backend.ssl_contexts == [
            outer_context,
            inner_context,
            destination_context,
        ]
        wire_bytes = network_backend.writes[0]
        assert b"CONNECT inner.example:8081" in wire_bytes
        assert b"CONNECT destination.example:443" in wire_bytes
        assert b"Basic b3V0ZXI6c2VjcmV0" in wire_bytes
        assert b"Basic aW5uZXI6c2VjcmV0" in wire_bytes
        assert wire_bytes.count(b"GET / HTTP/1.1") == 2
        reused_request = wire_bytes.rsplit(b"GET / HTTP/1.1", 1)[1]
        assert b"Proxy-Authorization" not in reused_request



def test_proxy_chain_407_reports_hop_and_closes():
    network_backend = ChainMockBackend(
        [
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        ],
        [],
    )
    chain = httpcore.ProxyChain(
        [
            httpcore.Proxy("https://outer.example:8080/"),
            httpcore.Proxy("http://inner.example:8081/"),
        ]
    )

    with ConnectionPool(
        proxy_chain=chain,
        network_backend=network_backend,
    ) as pool:
        with pytest.raises(ProxyError, match=r"hop 2/2.*CONNECT response"):
            pool.request("GET", "https://destination.example/")
        assert not pool.connections
        assert len(network_backend.closed_streams) == 1



def test_proxy_chain_outer_tls_failure_reports_hop_and_closes():
    network_backend = TLSErrorMockBackend()
    chain = httpcore.ProxyChain(
        [
            httpcore.Proxy("https://outer.example:8080/"),
            httpcore.Proxy("http://inner.example:8081/"),
        ]
    )

    with ConnectionPool(
        proxy_chain=chain,
        network_backend=network_backend,
    ) as pool:
        with pytest.raises(ProxyError, match=r"hop 1/2.*TLS handshake"):
            pool.request("GET", "https://destination.example/")
        assert not pool.connections
        assert len(network_backend.closed_streams) == 1
