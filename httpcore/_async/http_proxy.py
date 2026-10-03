from __future__ import annotations

import base64
import logging
import ssl
import typing

from .._backends.auto import AutoBackend
from .._backends.base import SOCKET_OPTION, AsyncNetworkBackend, AsyncNetworkStream
from .._exceptions import ConnectError, ConnectTimeout, ProxyError
from .._models import (
    URL,
    Origin,
    Proxy,
    ProxyChain,
    Request,
    Response,
    enforce_bytes,
    enforce_headers,
    enforce_url,
)
from .._ssl import default_ssl_context
from .._synchronization import AsyncLock
from .._trace import Trace
from .connection import AsyncHTTPConnection, exponential_backoff
from .connection_pool import AsyncConnectionPool
from .http11 import AsyncHTTP11Connection
from .interfaces import AsyncConnectionInterface

ByteOrStr = typing.Union[bytes, str]
HeadersAsSequence = typing.Sequence[typing.Tuple[ByteOrStr, ByteOrStr]]
HeadersAsMapping = typing.Mapping[ByteOrStr, ByteOrStr]


logger = logging.getLogger("httpcore.proxy")


def merge_headers(
    default_headers: typing.Sequence[tuple[bytes, bytes]] | None = None,
    override_headers: typing.Sequence[tuple[bytes, bytes]] | None = None,
) -> list[tuple[bytes, bytes]]:
    """
    Append default_headers and override_headers, de-duplicating if a key exists
    in both cases.
    """
    default_headers = [] if default_headers is None else list(default_headers)
    override_headers = [] if override_headers is None else list(override_headers)
    has_override = set(key.lower() for key, value in override_headers)
    default_headers = [
        (key, value)
        for key, value in default_headers
        if key.lower() not in has_override
    ]
    return default_headers + override_headers


class AsyncHTTPProxy(AsyncConnectionPool):  # pragma: nocover
    """
    A connection pool that sends requests via an HTTP proxy.
    """

    def __init__(
        self,
        proxy_url: URL | bytes | str | None = None,
        proxy_auth: tuple[bytes | str, bytes | str] | None = None,
        proxy_headers: HeadersAsMapping | HeadersAsSequence | None = None,
        proxy_chain: ProxyChain | None = None,
        ssl_context: ssl.SSLContext | None = None,
        proxy_ssl_context: ssl.SSLContext | None = None,
        max_connections: int | None = 10,
        max_keepalive_connections: int | None = None,
        keepalive_expiry: float | None = None,
        http1: bool = True,
        http2: bool = False,
        retries: int = 0,
        local_address: str | None = None,
        uds: str | None = None,
        network_backend: AsyncNetworkBackend | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> None:
        """
        A connection pool for making HTTP requests.

        Parameters:
            proxy_url: The URL to use when connecting to the proxy server.
                For example `"http://127.0.0.1:8080/"`.
            proxy_auth: Any proxy authentication as a two-tuple of
                (username, password). May be either bytes or ascii-only str.
            proxy_headers: Any HTTP headers to use for the proxy requests.
                For example `{"Proxy-Authorization": "Basic <username>:<password>"}`.
            ssl_context: An SSL context to use for verifying connections.
                If not specified, the default `httpcore.default_ssl_context()`
                will be used.
            proxy_ssl_context: The same as `ssl_context`, but for a proxy server rather than a remote origin.
            max_connections: The maximum number of concurrent HTTP connections that
                the pool should allow. Any attempt to send a request on a pool that
                would exceed this amount will block until a connection is available.
            max_keepalive_connections: The maximum number of idle HTTP connections
                that will be maintained in the pool.
            keepalive_expiry: The duration in seconds that an idle HTTP connection
                may be maintained for before being expired from the pool.
            http1: A boolean indicating if HTTP/1.1 requests should be supported
                by the connection pool. Defaults to True.
            http2: A boolean indicating if HTTP/2 requests should be supported by
                the connection pool. Defaults to False.
            retries: The maximum number of retries when trying to establish
                a connection.
            local_address: Local address to connect from. Can also be used to
                connect using a particular address family. Using
                `local_address="0.0.0.0"` will connect using an `AF_INET` address
                (IPv4), while using `local_address="::"` will connect using an
                `AF_INET6` address (IPv6).
            uds: Path to a Unix Domain Socket to use instead of TCP sockets.
            network_backend: A backend instance to use for handling network I/O.
        """
        if proxy_chain is not None:
            super().__init__(
                proxy_chain=proxy_chain,
                ssl_context=ssl_context,
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive_connections,
                keepalive_expiry=keepalive_expiry,
                http1=http1,
                http2=http2,
                network_backend=network_backend,
                retries=retries,
                local_address=local_address,
                uds=uds,
                socket_options=socket_options,
            )
            return

        if proxy_url is None:
            raise TypeError("proxy_url is required when proxy_chain is not given")

        super().__init__(
            ssl_context=ssl_context,
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
            http1=http1,
            http2=http2,
            network_backend=network_backend,
            retries=retries,
            local_address=local_address,
            uds=uds,
            socket_options=socket_options,
        )

        self._proxy_url = enforce_url(proxy_url, name="proxy_url")
        if (
            self._proxy_url.scheme == b"http" and proxy_ssl_context is not None
        ):  # pragma: no cover
            raise RuntimeError(
                "The `proxy_ssl_context` argument is not allowed for the http scheme"
            )

        self._ssl_context = ssl_context
        self._proxy_ssl_context = proxy_ssl_context
        self._proxy_headers = enforce_headers(proxy_headers, name="proxy_headers")
        if proxy_auth is not None:
            username = enforce_bytes(proxy_auth[0], name="proxy_auth")
            password = enforce_bytes(proxy_auth[1], name="proxy_auth")
            userpass = username + b":" + password
            authorization = b"Basic " + base64.b64encode(userpass)
            self._proxy_headers = [
                (b"Proxy-Authorization", authorization)
            ] + self._proxy_headers

    def create_connection(self, origin: Origin) -> AsyncConnectionInterface:
        if origin.scheme == b"http":
            return AsyncForwardHTTPConnection(
                proxy_origin=self._proxy_url.origin,
                proxy_headers=self._proxy_headers,
                remote_origin=origin,
                keepalive_expiry=self._keepalive_expiry,
                network_backend=self._network_backend,
                proxy_ssl_context=self._proxy_ssl_context,
            )
        return AsyncTunnelHTTPConnection(
            proxy_origin=self._proxy_url.origin,
            proxy_headers=self._proxy_headers,
            remote_origin=origin,
            ssl_context=self._ssl_context,
            proxy_ssl_context=self._proxy_ssl_context,
            keepalive_expiry=self._keepalive_expiry,
            http1=self._http1,
            http2=self._http2,
            network_backend=self._network_backend,
        )


class AsyncForwardHTTPConnection(AsyncConnectionInterface):
    def __init__(
        self,
        proxy_origin: Origin,
        remote_origin: Origin,
        proxy_headers: HeadersAsMapping | HeadersAsSequence | None = None,
        keepalive_expiry: float | None = None,
        network_backend: AsyncNetworkBackend | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
        proxy_ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._connection = AsyncHTTPConnection(
            origin=proxy_origin,
            keepalive_expiry=keepalive_expiry,
            network_backend=network_backend,
            socket_options=socket_options,
            ssl_context=proxy_ssl_context,
        )
        self._proxy_origin = proxy_origin
        self._proxy_headers = enforce_headers(proxy_headers, name="proxy_headers")
        self._remote_origin = remote_origin

    async def handle_async_request(self, request: Request) -> Response:
        headers = merge_headers(self._proxy_headers, request.headers)
        url = URL(
            scheme=self._proxy_origin.scheme,
            host=self._proxy_origin.host,
            port=self._proxy_origin.port,
            target=bytes(request.url),
        )
        proxy_request = Request(
            method=request.method,
            url=url,
            headers=headers,
            content=request.stream,
            extensions=request.extensions,
        )
        return await self._connection.handle_async_request(proxy_request)

    def can_handle_request(self, origin: Origin) -> bool:
        return origin == self._remote_origin

    async def aclose(self) -> None:
        await self._connection.aclose()

    def info(self) -> str:
        return self._connection.info()

    def is_available(self) -> bool:
        return self._connection.is_available()

    def has_expired(self) -> bool:
        return self._connection.has_expired()

    def is_idle(self) -> bool:
        return self._connection.is_idle()

    def is_closed(self) -> bool:
        return self._connection.is_closed()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.info()}]>"


class AsyncTunnelHTTPConnection(AsyncConnectionInterface):
    def __init__(
        self,
        remote_origin: Origin,
        proxies: typing.Sequence[Proxy] | None = None,
        proxy_origin: Origin | None = None,
        ssl_context: ssl.SSLContext | None = None,
        proxy_ssl_context: ssl.SSLContext | None = None,
        proxy_headers: typing.Sequence[tuple[bytes, bytes]] | None = None,
        forward_origin: Origin | None = None,
        keepalive_expiry: float | None = None,
        http1: bool = True,
        http2: bool = False,
        network_backend: AsyncNetworkBackend | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
        retries: int = 0,
        local_address: str | None = None,
        uds: str | None = None,
    ) -> None:
        if proxies is None:
            if proxy_origin is None:
                raise ValueError("Either 'proxies' or 'proxy_origin' is required.")
            proxies = [
                Proxy(
                    url=URL(
                        scheme=proxy_origin.scheme,
                        host=proxy_origin.host,
                        port=proxy_origin.port,
                    ),
                    headers=proxy_headers or [],
                    ssl_context=proxy_ssl_context,
                )
            ]

        self._proxies = list(proxies)
        self._proxy_origin = proxy_origin
        self._remote_origin = remote_origin
        self._forward_origin = forward_origin
        self._ssl_context = ssl_context
        self._keepalive_expiry = keepalive_expiry
        self._http1 = http1
        self._http2 = http2
        self._network_backend = (
            AutoBackend() if network_backend is None else network_backend
        )
        self._socket_options = socket_options
        self._retries = retries
        self._local_address = local_address
        self._uds = uds
        self._connection: AsyncConnectionInterface | None = None
        self._connect_lock = AsyncLock()
        self._connected = False
        self._connect_failed = False

    async def handle_async_request(self, request: Request) -> Response:
        async with self._connect_lock:
            if not self._connected:
                try:
                    self._connection = await self._connect(request)
                    self._connected = True
                except BaseException:
                    self._connected = False
                    self._connection = None
                    self._connect_failed = True
                    raise
        assert self._connection is not None
        return await self._connection.handle_async_request(request)

    async def _connect(self, request: Request) -> AsyncConnectionInterface:
        timeouts = request.extensions.get("timeout", {})
        timeout = timeouts.get("connect", None)
        first_proxy = self._proxies[0]
        first_target = (
            self._proxies[1].url.origin
            if len(self._proxies) > 1
            else (self._forward_origin or self._remote_origin)
        )
        stream = None
        first_connection = None
        try:
            stream = await self._open_first_stream(first_proxy, request, timeout)
            if first_proxy.url.scheme == b"https":
                stream = await self._start_proxy_tls(
                    stream=stream,
                    proxy=first_proxy,
                    hop=1,
                    stage="TLS handshake",
                    request=request,
                    timeout=timeout,
                )
            first_connection = AsyncHTTP11Connection(
                origin=first_proxy.url.origin,
                stream=stream,
                keepalive_expiry=self._keepalive_expiry,
            )
            stream = await self._connect_hop(
                connection=first_connection,
                proxy=first_proxy,
                target_origin=first_target,
                hop=1,
                request=request,
                timeout=timeout,
            )
        except ProxyError:
            if first_connection is not None:
                await first_connection.aclose()
            raise
        except Exception as exc:
            stream_for_close = first_connection or stream
            if stream_for_close is not None:
                await stream_for_close.aclose()
            raise self._proxy_error(exc, hop=1, stage="TCP connection")
        else:
            first_connection = None

        try:
            for hop in range(2, len(self._proxies) + 1):
                proxy = self._proxies[hop - 1]
                if proxy.url.scheme == b"https":
                    stream = await self._start_proxy_tls(
                        stream=stream,
                        proxy=proxy,
                        hop=hop,
                        stage="TLS handshake",
                        request=request,
                        timeout=timeout,
                    )

                target_origin = (
                    self._proxies[hop].url.origin
                    if hop < len(self._proxies)
                    else (self._forward_origin or self._remote_origin)
                )
                connection = AsyncHTTP11Connection(
                    origin=proxy.url.origin,
                    stream=stream,
                    keepalive_expiry=self._keepalive_expiry,
                )
                stream = await self._connect_hop(
                    connection=connection,
                    proxy=proxy,
                    target_origin=target_origin,
                    hop=hop,
                    request=request,
                )

            if self._forward_origin is None and self._remote_origin.scheme == b"https":
                ssl_context = (
                    default_ssl_context()
                    if self._ssl_context is None
                    else self._ssl_context
                )
                alpn_protocols = ["http/1.1", "h2"] if self._http2 else ["http/1.1"]
                ssl_context.set_alpn_protocols(alpn_protocols)
                tls_kwargs = {
                    "ssl_context": ssl_context,
                    "server_hostname": request.extensions.get("sni_hostname")
                    or self._remote_origin.host.decode("ascii"),
                    "timeout": timeout,
                }
                try:
                    async with Trace("start_tls", logger, request, tls_kwargs) as trace:
                        stream = await stream.start_tls(**tls_kwargs)
                        trace.return_value = stream
                except Exception as exc:
                    await stream.aclose()
                    raise self._proxy_error(
                        exc,
                        hop=len(self._proxies),
                        stage="destination TLS handshake",
                    )

            origin = self._forward_origin or self._remote_origin
            ssl_object = stream.get_extra_info("ssl_object")
            http2_negotiated = (
                ssl_object is not None
                and ssl_object.selected_alpn_protocol() == "h2"
            )

            if http2_negotiated or (
                self._forward_origin is None
                and self._remote_origin.scheme == b"https"
                and self._http2
                and not self._http1
            ):
                from .http2 import AsyncHTTP2Connection

                return AsyncHTTP2Connection(
                    origin=self._remote_origin,
                    stream=stream,
                    keepalive_expiry=self._keepalive_expiry,
                )

            return AsyncHTTP11Connection(
                origin=origin,
                stream=stream,
                keepalive_expiry=self._keepalive_expiry,
            )
        except ProxyError:
            raise
        except Exception as exc:
            await stream.aclose()
            raise self._proxy_error(exc, hop=len(self._proxies), stage="connection")

    async def _open_first_stream(
        self, proxy: Proxy, request: Request, timeout: float | None
    ) -> AsyncNetworkStream:
        retries_left = self._retries
        delays = exponential_backoff(factor=0.5)

        while True:
            try:
                if self._uds is None:
                    kwargs = {
                        "host": proxy.url.origin.host.decode("ascii"),
                        "port": proxy.url.origin.port,
                        "local_address": self._local_address,
                        "timeout": timeout,
                        "socket_options": self._socket_options,
                    }
                    async with Trace("connect_tcp", logger, request, kwargs) as trace:
                        stream = await self._network_backend.connect_tcp(**kwargs)
                        trace.return_value = stream
                else:
                    kwargs = {
                        "path": self._uds,
                        "timeout": timeout,
                        "socket_options": self._socket_options,
                    }
                    async with Trace(
                        "connect_unix_socket", logger, request, kwargs
                    ) as trace:
                        stream = await self._network_backend.connect_unix_socket(
                            **kwargs
                        )
                        trace.return_value = stream
                return stream
            except (ConnectError, ConnectTimeout):
                if retries_left <= 0:
                    raise
                retries_left -= 1
                delay = next(delays)
                await self._network_backend.sleep(delay)

    async def _connect_hop(
        self,
        *,
        connection: AsyncConnectionInterface,
        proxy: Proxy,
        target_origin: Origin,
        hop: int,
        request: Request,
        timeout: float | None = None,
    ) -> AsyncNetworkStream:
        target = b"%b:%d" % (target_origin.host, target_origin.port)
        connect_url = URL(
            scheme=proxy.url.scheme,
            host=proxy.url.origin.host,
            port=proxy.url.origin.port,
            target=target,
        )
        connect_headers = merge_headers(
            [(b"Host", target), (b"Accept", b"*/*")], proxy.headers
        )
        connect_request = Request(
            method=b"CONNECT",
            url=connect_url,
            headers=connect_headers,
            extensions=request.extensions,
        )
        try:
            connect_response = await connection.handle_async_request(connect_request)
        except Exception as exc:
            await connection.aclose()
            if hop == 1:
                raise self._proxy_error(exc, hop=hop, stage="CONNECT request")
            raise self._proxy_error(exc, hop=hop, stage="CONNECT request")

        if not 200 <= connect_response.status < 300:
            reason_bytes = connect_response.extensions.get("reason_phrase", b"")
            reason_str = reason_bytes.decode("ascii", errors="ignore")
            msg = "%d %s" % (connect_response.status, reason_str)
            await connection.aclose()
            if len(self._proxies) == 1:
                raise ProxyError(msg)
            raise self._proxy_error(
                ProxyError(msg), hop=hop, stage="CONNECT response"
            )

        return connect_response.extensions["network_stream"]

    async def _start_proxy_tls(
        self,
        *,
        stream: AsyncNetworkStream,
        proxy: Proxy,
        hop: int,
        stage: str,
        request: Request,
        timeout: float | None,
    ) -> AsyncNetworkStream:
        ssl_context = (
            default_ssl_context()
            if proxy.ssl_context is None
            else proxy.ssl_context
        )
        ssl_context.set_alpn_protocols(["http/1.1"])
        kwargs = {
            "ssl_context": ssl_context,
            "server_hostname": proxy.url.origin.host.decode("ascii"),
            "timeout": timeout,
        }
        try:
            async with Trace("start_tls", logger, request, kwargs) as trace:
                stream = await stream.start_tls(**kwargs)
                trace.return_value = stream
        except Exception as exc:
            await stream.aclose()
            raise self._proxy_error(exc, hop=hop, stage=stage)
        return stream

    def _proxy_error(self, exc: Exception, *, hop: int, stage: str) -> ProxyError:
        proxy = self._proxies[hop - 1]
        origin = proxy.url.origin
        message = (
            f"Proxy chain failed at hop {hop}/{len(self._proxies)} "
            f"({origin}) during {stage}: {exc}"
        )
        return ProxyError(message)

    def can_handle_request(self, origin: Origin) -> bool:
        return origin == self._remote_origin

    async def aclose(self) -> None:
        if self._connection is not None:
            await self._connection.aclose()

    def info(self) -> str:
        if self._connection is None:
            return "CONNECTION FAILED" if self._connect_failed else "CONNECTING"
        return self._connection.info()

    def is_available(self) -> bool:
        return False if self._connection is None else self._connection.is_available()

    def has_expired(self) -> bool:
        if self._connection is None:
            return self._connect_failed
        return self._connection.has_expired()

    def is_idle(self) -> bool:
        return False if self._connection is None else self._connection.is_idle()

    def is_closed(self) -> bool:
        if self._connection is None:
            return self._connect_failed
        return self._connection.is_closed()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.info()}]>"
