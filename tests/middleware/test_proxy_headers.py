from __future__ import annotations

import contextlib
import ipaddress
from typing import TYPE_CHECKING

import httpx2
import pytest
from websockets.asyncio.client import connect

from tests.response import Response
from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGIReceiveEvent, ASGISendCallable, ASGISendEvent, HTTPScope, Scope
from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware, _TrustedHosts

if TYPE_CHECKING:
    from uvicorn.protocols.http.h11_impl import H11Protocol
    from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
    from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol
    from uvicorn.protocols.websockets.wsproto_impl import WSProtocol


X_FORWARDED_FOR = "X-Forwarded-For"
X_FORWARDED_PROTO = "X-Forwarded-Proto"
FORWARDED = "Forwarded"


async def default_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    scheme = scope["scheme"]  # type: ignore
    if (client := scope["client"]) is None:  # type: ignore
        client_addr = "NONE"  # pragma: no cover
    else:
        host, port = client
        with contextlib.suppress(ValueError):
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        client_addr = f"{host}:{port}"

    response = Response(f"{scheme}://{client_addr}", media_type="text/plain")
    await response(scope, receive, send)


def make_httpx2_client(
    trusted_hosts: str | list[str],
    client: tuple[str, int] = ("127.0.0.1", 123),
    forwarded_headers: bool = False,
) -> httpx2.AsyncClient:
    """Create async client for use in test cases.

    Args:
        trusted_hosts: trusted_hosts for proxy middleware
        client: transport client to use
        forwarded_headers: enable RFC 7239 Forwarded header support
    """

    app = ProxyHeadersMiddleware(default_app, trusted_hosts, forwarded_headers=forwarded_headers)
    transport = httpx2.ASGITransport(app=app, client=client)  # type: ignore
    return httpx2.AsyncClient(transport=transport, base_url="http://testserver")


# Note: we vary the format here to also test some of the functionality
# of the _TrustedHosts.__init__ method.
_TRUSTED_NOTHING: list[str] = []
_TRUSTED_EVERYTHING = "*"
_TRUSTED_EVERYTHING_LIST = ["*"]
_TRUSTED_IPv4_ADDRESSES = "127.0.0.1, 10.0.0.1"
_TRUSTED_IPv4_NETWORKS = ["127.0.0.0/8", "10.0.0.0/8"]
_TRUSTED_IPv6_ADDRESSES = [
    "2001:db8::",
    "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
    "2001:db8:3333:4444:5555:6666:1.2.3.4",  # This is a dual address
    "::11.22.33.44",  # This is a dual address
]
_TRUSTED_IPv6_NETWORKS = "2001:db8:abcd:0012::0/64"
_TRUSTED_LITERALS = "some-literal , unix:///foo/bar  ,  /foo/bar, garba*gewith*"


@pytest.mark.parametrize(
    ("init_hosts", "test_host", "expected"),
    [
        ## Never Trust trust
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_NOTHING, "127.0.0.0", False),
        (_TRUSTED_NOTHING, "127.0.0.1", False),
        (_TRUSTED_NOTHING, "127.1.1.1", False),
        (_TRUSTED_NOTHING, "127.255.255.255", False),
        (_TRUSTED_NOTHING, "10.0.0.0", False),
        (_TRUSTED_NOTHING, "10.0.0.1", False),
        (_TRUSTED_NOTHING, "10.1.1.1", False),
        (_TRUSTED_NOTHING, "10.255.255.255", False),
        (_TRUSTED_NOTHING, "192.168.0.0", False),
        (_TRUSTED_NOTHING, "192.168.0.1", False),
        (_TRUSTED_NOTHING, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_NOTHING, "2001:db8::", False),
        (_TRUSTED_NOTHING, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_NOTHING, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_NOTHING, "::", False),
        (_TRUSTED_NOTHING, "::1", False),
        (
            _TRUSTED_NOTHING,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_NOTHING, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_NOTHING, "a:b:c:d::", False),
        (_TRUSTED_NOTHING, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_NOTHING, "some-literal", False),
        (_TRUSTED_NOTHING, "unix:///foo/bar", False),
        (_TRUSTED_NOTHING, "/foo/bar", False),
        (_TRUSTED_NOTHING, "*", False),
        (_TRUSTED_NOTHING, "another-literal", False),
        (_TRUSTED_NOTHING, "unix:///another/path", False),
        (_TRUSTED_NOTHING, "/another/path", False),
        (_TRUSTED_NOTHING, "", False),
        ## Always trust
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_EVERYTHING, "127.0.0.0", True),
        (_TRUSTED_EVERYTHING, "127.0.0.1", True),
        (_TRUSTED_EVERYTHING, "127.1.1.1", True),
        (_TRUSTED_EVERYTHING, "127.255.255.255", True),
        (_TRUSTED_EVERYTHING, "10.0.0.0", True),
        (_TRUSTED_EVERYTHING, "10.0.0.1", True),
        (_TRUSTED_EVERYTHING, "10.1.1.1", True),
        (_TRUSTED_EVERYTHING, "10.255.255.255", True),
        (_TRUSTED_EVERYTHING, "192.168.0.0", True),
        (_TRUSTED_EVERYTHING, "192.168.0.1", True),
        (_TRUSTED_EVERYTHING, "1.1.1.1", True),
        (_TRUSTED_EVERYTHING_LIST, "1.1.1.1", True),
        # Test IPv6 Addresses
        (_TRUSTED_EVERYTHING, "2001:db8::", True),
        (_TRUSTED_EVERYTHING, "2001:db8:abcd:0012::0", True),
        (_TRUSTED_EVERYTHING, "2001:db8:abcd:0012::1:1", True),
        (_TRUSTED_EVERYTHING, "::", True),
        (_TRUSTED_EVERYTHING, "::1", True),
        (
            _TRUSTED_EVERYTHING,
            "2001:db8:3333:4444:5555:6666:102:304",
            True,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_EVERYTHING, "::b16:212c", True),  # aka ::11.22.33.44
        (_TRUSTED_EVERYTHING, "a:b:c:d::", True),
        (_TRUSTED_EVERYTHING, "::a:b:c:d", True),
        (_TRUSTED_EVERYTHING_LIST, "::a:b:c:d", True),
        # Test Literals
        (_TRUSTED_EVERYTHING, "some-literal", True),
        (_TRUSTED_EVERYTHING, "unix:///foo/bar", True),
        (_TRUSTED_EVERYTHING, "/foo/bar", True),
        (_TRUSTED_EVERYTHING, "*", True),
        (_TRUSTED_EVERYTHING, "another-literal", True),
        (_TRUSTED_EVERYTHING, "unix:///another/path", True),
        (_TRUSTED_EVERYTHING, "/another/path", True),
        (_TRUSTED_EVERYTHING, "", True),
        (_TRUSTED_EVERYTHING_LIST, "", True),
        ## Trust IPv4 Addresses
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv4_ADDRESSES, "127.0.0.0", False),
        (_TRUSTED_IPv4_ADDRESSES, "127.0.0.1", True),
        (_TRUSTED_IPv4_ADDRESSES, "127.1.1.1", False),
        (_TRUSTED_IPv4_ADDRESSES, "127.255.255.255", False),
        (_TRUSTED_IPv4_ADDRESSES, "10.0.0.0", False),
        (_TRUSTED_IPv4_ADDRESSES, "10.0.0.1", True),
        (_TRUSTED_IPv4_ADDRESSES, "10.1.1.1", False),
        (_TRUSTED_IPv4_ADDRESSES, "10.255.255.255", False),
        (_TRUSTED_IPv4_ADDRESSES, "192.168.0.0", False),
        (_TRUSTED_IPv4_ADDRESSES, "192.168.0.1", False),
        (_TRUSTED_IPv4_ADDRESSES, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv4_ADDRESSES, "2001:db8::", False),
        (_TRUSTED_IPv4_ADDRESSES, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_IPv4_ADDRESSES, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_IPv4_ADDRESSES, "::", False),
        (_TRUSTED_IPv4_ADDRESSES, "::1", False),
        (
            _TRUSTED_IPv4_ADDRESSES,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv4_ADDRESSES, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_IPv4_ADDRESSES, "a:b:c:d::", False),
        (_TRUSTED_IPv4_ADDRESSES, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv4_ADDRESSES, "some-literal", False),
        (_TRUSTED_IPv4_ADDRESSES, "unix:///foo/bar", False),
        (_TRUSTED_IPv4_ADDRESSES, "*", False),
        (_TRUSTED_IPv4_ADDRESSES, "/foo/bar", False),
        (_TRUSTED_IPv4_ADDRESSES, "another-literal", False),
        (_TRUSTED_IPv4_ADDRESSES, "unix:///another/path", False),
        (_TRUSTED_IPv4_ADDRESSES, "/another/path", False),
        (_TRUSTED_IPv4_ADDRESSES, "", False),
        ## Trust IPv6 Addresses
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv6_ADDRESSES, "127.0.0.0", False),
        (_TRUSTED_IPv6_ADDRESSES, "127.0.0.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "127.1.1.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "127.255.255.255", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.0.0.0", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.0.0.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.1.1.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.255.255.255", False),
        (_TRUSTED_IPv6_ADDRESSES, "192.168.0.0", False),
        (_TRUSTED_IPv6_ADDRESSES, "192.168.0.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv6_ADDRESSES, "2001:db8::", True),
        (_TRUSTED_IPv6_ADDRESSES, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_IPv6_ADDRESSES, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_IPv6_ADDRESSES, "::", False),
        (_TRUSTED_IPv6_ADDRESSES, "::1", False),
        (
            _TRUSTED_IPv6_ADDRESSES,
            "2001:db8:3333:4444:5555:6666:102:304",
            True,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv6_ADDRESSES, "::b16:212c", True),  # aka ::11.22.33.44
        (_TRUSTED_IPv6_ADDRESSES, "a:b:c:d::", False),
        (_TRUSTED_IPv6_ADDRESSES, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv6_ADDRESSES, "some-literal", False),
        (_TRUSTED_IPv6_ADDRESSES, "unix:///foo/bar", False),
        (_TRUSTED_IPv6_ADDRESSES, "*", False),
        (_TRUSTED_IPv6_ADDRESSES, "/foo/bar", False),
        (_TRUSTED_IPv6_ADDRESSES, "another-literal", False),
        (_TRUSTED_IPv6_ADDRESSES, "unix:///another/path", False),
        (_TRUSTED_IPv6_ADDRESSES, "/another/path", False),
        (_TRUSTED_IPv6_ADDRESSES, "", False),
        ## Trust IPv4 Networks
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv4_NETWORKS, "127.0.0.0", True),
        (_TRUSTED_IPv4_NETWORKS, "127.0.0.1", True),
        (_TRUSTED_IPv4_NETWORKS, "127.1.1.1", True),
        (_TRUSTED_IPv4_NETWORKS, "127.255.255.255", True),
        (_TRUSTED_IPv4_NETWORKS, "10.0.0.0", True),
        (_TRUSTED_IPv4_NETWORKS, "10.0.0.1", True),
        (_TRUSTED_IPv4_NETWORKS, "10.1.1.1", True),
        (_TRUSTED_IPv4_NETWORKS, "10.255.255.255", True),
        (_TRUSTED_IPv4_NETWORKS, "192.168.0.0", False),
        (_TRUSTED_IPv4_NETWORKS, "192.168.0.1", False),
        (_TRUSTED_IPv4_NETWORKS, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv4_NETWORKS, "2001:db8::", False),
        (_TRUSTED_IPv4_NETWORKS, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_IPv4_NETWORKS, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_IPv4_NETWORKS, "::", False),
        (_TRUSTED_IPv4_NETWORKS, "::1", False),
        (
            _TRUSTED_IPv4_NETWORKS,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv4_NETWORKS, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_IPv4_NETWORKS, "a:b:c:d::", False),
        (_TRUSTED_IPv4_NETWORKS, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv4_NETWORKS, "some-literal", False),
        (_TRUSTED_IPv4_NETWORKS, "unix:///foo/bar", False),
        (_TRUSTED_IPv4_NETWORKS, "*", False),
        (_TRUSTED_IPv4_NETWORKS, "/foo/bar", False),
        (_TRUSTED_IPv4_NETWORKS, "another-literal", False),
        (_TRUSTED_IPv4_NETWORKS, "unix:///another/path", False),
        (_TRUSTED_IPv4_NETWORKS, "/another/path", False),
        (_TRUSTED_IPv4_NETWORKS, "", False),
        ## Trust IPv6 Networks
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv6_NETWORKS, "127.0.0.0", False),
        (_TRUSTED_IPv6_NETWORKS, "127.0.0.1", False),
        (_TRUSTED_IPv6_NETWORKS, "127.1.1.1", False),
        (_TRUSTED_IPv6_NETWORKS, "127.255.255.255", False),
        (_TRUSTED_IPv6_NETWORKS, "10.0.0.0", False),
        (_TRUSTED_IPv6_NETWORKS, "10.0.0.1", False),
        (_TRUSTED_IPv6_NETWORKS, "10.1.1.1", False),
        (_TRUSTED_IPv6_NETWORKS, "10.255.255.255", False),
        (_TRUSTED_IPv6_NETWORKS, "192.168.0.0", False),
        (_TRUSTED_IPv6_NETWORKS, "192.168.0.1", False),
        (_TRUSTED_IPv6_NETWORKS, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv6_NETWORKS, "2001:db8::", False),
        (_TRUSTED_IPv6_NETWORKS, "2001:db8:abcd:0012::0", True),
        (_TRUSTED_IPv6_NETWORKS, "2001:db8:abcd:0012::1:1", True),
        (_TRUSTED_IPv6_NETWORKS, "::", False),
        (_TRUSTED_IPv6_NETWORKS, "::1", False),
        (
            _TRUSTED_IPv6_NETWORKS,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv6_NETWORKS, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_IPv6_NETWORKS, "a:b:c:d::", False),
        (_TRUSTED_IPv6_NETWORKS, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv6_NETWORKS, "some-literal", False),
        (_TRUSTED_IPv6_NETWORKS, "unix:///foo/bar", False),
        (_TRUSTED_IPv6_NETWORKS, "*", False),
        (_TRUSTED_IPv6_NETWORKS, "/foo/bar", False),
        (_TRUSTED_IPv6_NETWORKS, "another-literal", False),
        (_TRUSTED_IPv6_NETWORKS, "unix:///another/path", False),
        (_TRUSTED_IPv6_NETWORKS, "/another/path", False),
        (_TRUSTED_IPv6_NETWORKS, "", False),
        ## Trust Literals
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_LITERALS, "127.0.0.0", False),
        (_TRUSTED_LITERALS, "127.0.0.1", False),
        (_TRUSTED_LITERALS, "127.1.1.1", False),
        (_TRUSTED_LITERALS, "127.255.255.255", False),
        (_TRUSTED_LITERALS, "10.0.0.0", False),
        (_TRUSTED_LITERALS, "10.0.0.1", False),
        (_TRUSTED_LITERALS, "10.1.1.1", False),
        (_TRUSTED_LITERALS, "10.255.255.255", False),
        (_TRUSTED_LITERALS, "192.168.0.0", False),
        (_TRUSTED_LITERALS, "192.168.0.1", False),
        (_TRUSTED_LITERALS, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_LITERALS, "2001:db8::", False),
        (_TRUSTED_LITERALS, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_LITERALS, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_LITERALS, "::", False),
        (_TRUSTED_LITERALS, "::1", False),
        (
            _TRUSTED_LITERALS,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_LITERALS, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_LITERALS, "a:b:c:d::", False),
        (_TRUSTED_LITERALS, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_LITERALS, "some-literal", True),
        (_TRUSTED_LITERALS, "unix:///foo/bar", True),
        (_TRUSTED_LITERALS, "*", False),
        (_TRUSTED_LITERALS, "/foo/bar", True),
        (_TRUSTED_LITERALS, "another-literal", False),
        (_TRUSTED_LITERALS, "unix:///another/path", False),
        (_TRUSTED_LITERALS, "/another/path", False),
        (_TRUSTED_LITERALS, "", False),
    ],
)
def test_forwarded_hosts(init_hosts: str | list[str], test_host: str, expected: bool) -> None:
    trusted_hosts = _TrustedHosts(init_hosts)
    assert (test_host in trusted_hosts) is expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted_hosts", "expected"),
    [
        # always trust
        ("*", "https://1.2.3.4:0"),
        # trusted proxy
        ("127.0.0.1", "https://1.2.3.4:0"),
        (["127.0.0.1"], "https://1.2.3.4:0"),
        # trusted proxy list
        (["127.0.0.1", "10.0.0.1"], "https://1.2.3.4:0"),
        ("127.0.0.1, 10.0.0.1", "https://1.2.3.4:0"),
        # trusted proxy network
        # https://github.com/Kludex/uvicorn/issues/1068#issuecomment-1004813267
        ("127.0.0.0/24, 10.0.0.1", "https://1.2.3.4:0"),
        # request from untrusted proxy
        ("192.168.0.1", "http://127.0.0.1:123"),
        # request from untrusted proxy network
        ("192.168.0.0/16", "http://127.0.0.1:123"),
        # request from client running on proxy server itself
        # https://github.com/Kludex/uvicorn/issues/1068#issuecomment-855371576
        (["127.0.0.1", "1.2.3.4"], "https://1.2.3.4:0"),
    ],
)
async def test_proxy_headers_trusted_hosts(trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx2_client(trusted_hosts) as client:
        headers = {X_FORWARDED_FOR: "1.2.3.4", X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded_for", "forwarded_proto", "expected"),
    [
        ("", "", "http://127.0.0.1:123"),
        ("", None, "http://127.0.0.1:123"),
        ("", "asdf", "http://127.0.0.1:123"),
        (" , ", "https", "https://127.0.0.1:123"),
        (", , ", "https", "https://127.0.0.1:123"),
        (" , 10.0.0.1", "https", "https://127.0.0.1:123"),
        ("9.9.9.9 , , , 10.0.0.1", "https", "https://127.0.0.1:123"),
        (", , 9.9.9.9", "https", "https://9.9.9.9:0"),
        (", , 9.9.9.9, , ", "https", "https://127.0.0.1:123"),
    ],
)
async def test_proxy_headers_trusted_hosts_malformed(
    forwarded_for: str,
    forwarded_proto: str | None,
    expected: str,
) -> None:
    async with make_httpx2_client("127.0.0.1, 10.0.0.0/8") as client:
        headers = {X_FORWARDED_FOR: forwarded_for}
        if forwarded_proto is not None:
            headers[X_FORWARDED_PROTO] = forwarded_proto
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted_hosts", "expected"),
    [
        # always trust
        ("*", "https://1.2.3.4:0"),
        # all proxies are trusted
        (["127.0.0.1", "10.0.2.1", "192.168.0.2"], "https://1.2.3.4:0"),
        # order doesn't matter
        (["10.0.2.1", "192.168.0.2", "127.0.0.1"], "https://1.2.3.4:0"),
        # should set first untrusted as remote address
        (["192.168.0.2", "127.0.0.1"], "https://10.0.2.1:0"),
        # Mixed literals and networks
        (["127.0.0.1", "10.0.0.0/8", "192.168.0.2"], "https://1.2.3.4:0"),
    ],
)
async def test_proxy_headers_multiple_proxies(trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx2_client(trusted_hosts) as client:
        headers = {X_FORWARDED_FOR: "1.2.3.4, 10.0.2.1, 192.168.0.2", X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted_hosts", "expected"),
    [
        # always trust
        ("*", "https://1.2.3.4:1234"),
        # all proxies are trusted
        (["127.0.0.1", "2001:db8::1", "192.168.0.2"], "https://1.2.3.4:1234"),
        # should set first untrusted as remote address
        (["192.168.0.2", "127.0.0.1"], "https://[2001:db8::1]:8080"),
        # Mixed literals and networks
        (["127.0.0.1", "2001:db8::/32", "192.168.0.2"], "https://1.2.3.4:1234"),
    ],
)
async def test_proxy_headers_multiple_proxies_with_ports(trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx2_client(trusted_hosts) as client:
        headers = {
            X_FORWARDED_FOR: "1.2.3.4:1234, [2001:db8::1]:8080, 192.168.0.2:9000",
            X_FORWARDED_PROTO: "https",
        }
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
async def test_proxy_headers_invalid_x_forwarded_for() -> None:
    async with make_httpx2_client("*") as client:
        headers = httpx2.Headers(
            {
                X_FORWARDED_FOR: "1.2.3.4, \xf0\xfd\xfd\xfd, unix:, ::1",
                X_FORWARDED_PROTO: "https",
            },
            encoding="latin-1",
        )
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "https://1.2.3.4:0"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded_for", "expected"),
    [
        # IPv4 without port
        ("1.2.3.4", "https://1.2.3.4:0"),
        # IPv4 with port
        ("1.2.3.4:1234", "https://1.2.3.4:1234"),
        # Bracketed IPv6 with port
        ("[2001:db8::1]:443", "https://[2001:db8::1]:443"),
        # Bracketed IPv6 without port
        ("[2001:db8::1]", "https://[2001:db8::1]:0"),
        # Bare IPv6 without port
        ("2001:db8::1", "https://[2001:db8::1]:0"),
        # Invalid IPv4 port falls back to the original host value
        ("1.2.3.4:notaport", "https://1.2.3.4:notaport:0"),
        # Invalid bracketed IPv6 port keeps the host and drops the port
        ("[2001:db8::1]:notaport", "https://[2001:db8::1]:0"),
        # Trailing data after a bracketed IPv6 host is left untouched
        ("[2001:db8::1]extra", "https://[2001:db8::1]extra:0"),
        # Malformed bracket is left untouched
        ("[2001:db8::1", "https://[2001:db8::1:0"),
    ],
)
async def test_proxy_headers_x_forwarded_for_port_shapes(forwarded_for: str, expected: str) -> None:
    async with make_httpx2_client("*") as client:
        headers = {X_FORWARDED_FOR: forwarded_for, X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    "forwarded_proto,expected",
    [
        ("http", "ws://1.2.3.4:0"),
        ("https", "wss://1.2.3.4:0"),
        ("ws", "ws://1.2.3.4:0"),
        ("wss", "wss://1.2.3.4:0"),
    ],
)
async def test_proxy_headers_websocket_x_forwarded_proto(
    forwarded_proto: str,
    expected: str,
    ws_protocol_cls: type[WSProtocol | WebSocketsSansIOProtocol],
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol],
    unused_tcp_port: int,
) -> None:
    async def websocket_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "websocket"
        scheme = scope["scheme"]
        assert scope["client"] is not None
        host, port = scope["client"]
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.send", "text": f"{scheme}://{host}:{port}"})
        await send({"type": "websocket.close"})

    app_with_middleware = ProxyHeadersMiddleware(websocket_app, trusted_hosts="*")
    config = Config(
        app=app_with_middleware,
        ws=ws_protocol_cls,
        http=http_protocol_cls,
        lifespan="off",
        port=unused_tcp_port,
    )

    async with run_server(config):
        url = f"ws://127.0.0.1:{unused_tcp_port}"
        headers = {X_FORWARDED_FOR: "1.2.3.4", X_FORWARDED_PROTO: forwarded_proto}
        async with connect(url, additional_headers=headers) as websocket:
            data = await websocket.recv()
            assert data == expected


@pytest.mark.anyio
async def test_proxy_headers_empty_x_forwarded_for() -> None:
    # fallback to the default behavior if x-forwarded-for is an empty list
    # https://github.com/Kludex/uvicorn/issues/1068#issuecomment-855371576
    async with make_httpx2_client("*") as client:
        headers = {X_FORWARDED_FOR: "", X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "https://127.0.0.1:123"


def _make_http_scope(headers: list[tuple[bytes, bytes]], scheme: str = "http") -> HTTPScope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": scheme,
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 80),
    }


async def _noop_receive() -> ASGIReceiveEvent:  # pragma: no cover
    return {"type": "http.disconnect"}


async def _noop_send(message: ASGISendEvent) -> None:  # pragma: no cover
    return None


@pytest.mark.anyio
async def test_proxy_headers_duplicate_x_forwarded_for_is_combined() -> None:
    captured: dict[str, tuple[str, int] | None] = {}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        captured["client"] = scope["client"]

    middleware = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")
    scope = _make_http_scope(
        [
            (b"x-forwarded-for", b"203.0.113.66, 198.51.100.23"),
            (b"x-forwarded-for", b"127.0.0.1"),
        ]
    )
    await middleware(scope, _noop_receive, _noop_send)
    assert captured["client"] == ("198.51.100.23", 0)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("proto_headers", "expected"),
    [
        ([(b"x-forwarded-proto", b"https"), (b"x-forwarded-proto", b"http")], "http"),
        ([(b"x-forwarded-proto", b"http"), (b"x-forwarded-proto", b"https")], "https"),
    ],
)
async def test_proxy_headers_duplicate_x_forwarded_proto_uses_last(
    proto_headers: list[tuple[bytes, bytes]],
    expected: str,
) -> None:
    captured: dict[str, str] = {}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        captured["scheme"] = scope["scheme"]

    middleware = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")
    scope = _make_http_scope(proto_headers, scheme="http")
    await middleware(scope, _noop_receive, _noop_send)
    assert captured["scheme"] == expected


@pytest.mark.anyio
async def test_proxy_headers_haproxy_behind_alb() -> None:
    captured: dict[str, object] = {}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        captured["client"] = scope["client"]
        captured["scheme"] = scope["scheme"]

    middleware = ProxyHeadersMiddleware(app, trusted_hosts=["127.0.0.1", "10.0.0.1"])
    scope = _make_http_scope(
        [
            (b"x-forwarded-for", b"1.2.3.4"),
            (b"x-forwarded-for", b"10.0.0.1"),
            (b"x-forwarded-proto", b"https"),
            (b"x-forwarded-proto", b"https"),
        ],
        scheme="http",
    )
    await middleware(scope, _noop_receive, _noop_send)
    assert captured["client"] == ("1.2.3.4", 0)
    assert captured["scheme"] == "https"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted_hosts", "expected"),
    [
        # always trust
        ("*", "https://1.2.3.4:0"),
        # trusted proxy
        ("127.0.0.1", "https://1.2.3.4:0"),
        # request from untrusted proxy: the Forwarded header is ignored entirely
        ("192.168.0.1", "http://127.0.0.1:123"),
        ("192.168.0.0/16", "http://127.0.0.1:123"),
    ],
)
async def test_forwarded_headers_trusted_hosts(trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx2_client(trusted_hosts, forwarded_headers=True) as client:
        response = await client.get("/", headers={FORWARDED: "for=1.2.3.4;proto=https"})
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
async def test_forwarded_headers_disabled_by_default() -> None:
    # Forwarded headers are opt-in; without `forwarded_headers` they are ignored.
    async with make_httpx2_client("*") as client:
        response = await client.get("/", headers={FORWARDED: "for=1.2.3.4;proto=https"})
    assert response.status_code == 200
    assert response.text == "http://127.0.0.1:123"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded", "trusted_hosts", "expected"),
    [
        # all proxies are trusted: the client is the leftmost element
        (
            "for=1.2.3.4;proto=https, for=10.0.2.1, for=192.168.0.2",
            ["127.0.0.1", "10.0.2.1", "192.168.0.2"],
            "https://1.2.3.4:0",
        ),
        # the first untrusted element from the direct peer becomes the client,
        # and the scheme comes from that same element
        (
            "for=1.2.3.4;proto=https, for=10.0.2.1;proto=http, for=192.168.0.2",
            ["127.0.0.1", "192.168.0.2"],
            "http://10.0.2.1:0",
        ),
        # a forged prefix added by the client before the trusted proxy chain
        # never determines the exposed client or scheme
        (
            "for=9.9.9.9;proto=https, for=203.0.113.7;proto=http",
            "127.0.0.1",
            "http://203.0.113.7:0",
        ),
        # parameter names and the proto value are case-insensitive
        ('For="[2001:db8::1]:443";Proto=HTTPS', "*", "https://[2001:db8::1]:443"),
    ],
)
async def test_forwarded_headers_proxy_chain(forwarded: str, trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx2_client(trusted_hosts, forwarded_headers=True) as client:
        response = await client.get("/", headers={FORWARDED: forwarded})
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
async def test_forwarded_headers_multiple_header_fields() -> None:
    # Multiple Forwarded header fields are combined into a single chain.
    async with make_httpx2_client("127.0.0.1", forwarded_headers=True) as client:
        headers = httpx2.Headers(
            [
                (FORWARDED, "for=1.2.3.4"),
                (FORWARDED, "for=10.0.0.1;proto=https"),
            ]
        )
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "https://10.0.0.1:0"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded", "expected"),
    [
        # IPv4 with port
        ("for=192.0.2.43:4711;proto=https", "https://192.0.2.43:4711"),
        # quoted bracketed IPv6 with port
        ('for="[2001:db8:cafe::17]:4711";proto=https', "https://[2001:db8:cafe::17]:4711"),
        # quoted bracketed IPv6 without port
        ('for="[2001:db8::1]";proto=https', "https://[2001:db8::1]:0"),
        # quoted IPv4
        ('for="192.0.2.43";proto=https', "https://192.0.2.43:0"),
        # quoted proto value
        ('for=192.0.2.43;proto="https"', "https://192.0.2.43:0"),
        # escapes, commas and semicolons inside quoted-strings do not split pairs
        ('by="proxy\\"a;b,c";for=192.0.2.43;proto=https', "https://192.0.2.43:0"),
        # unknown parameters are ignored
        ("for=192.0.2.43;by=203.0.113.60;host=example.com;proto=https", "https://192.0.2.43:0"),
    ],
)
async def test_forwarded_headers_value_shapes(forwarded: str, expected: str) -> None:
    async with make_httpx2_client("*", forwarded_headers=True) as client:
        response = await client.get("/", headers={FORWARDED: forwarded})
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded", "expected"),
    [
        # unknown and obfuscated identifiers are never exposed as the client,
        # but a proto attested by a trusted proxy is still applied
        ("for=unknown;proto=https", "https://127.0.0.1:123"),
        ("for=_hidden;proto=https", "https://127.0.0.1:123"),
        # an unknown identifier in the chain terminates the walk
        ("for=1.2.3.4, for=unknown", "http://127.0.0.1:123"),
        ("for=1.2.3.4, for=_obfuscated, for=10.0.0.1", "http://127.0.0.1:123"),
        # invalid values cannot be smuggled in as client addresses
        ("for=", "http://127.0.0.1:123"),
        ("for=not-an-ip", "http://127.0.0.1:123"),
        ("for=1.2.3.4:notaport", "http://127.0.0.1:123"),
        ("for=[2001:db8::1]extra", "http://127.0.0.1:123"),
        ("garbage", "http://127.0.0.1:123"),
        ("", "http://127.0.0.1:123"),
        (", ,", "http://127.0.0.1:123"),
    ],
)
async def test_forwarded_headers_invalid_identifiers(forwarded: str, expected: str) -> None:
    async with make_httpx2_client("127.0.0.1, 10.0.0.0/8", forwarded_headers=True) as client:
        response = await client.get("/", headers={FORWARDED: forwarded})
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
async def test_forwarded_headers_take_precedence_over_x_forwarded() -> None:
    # When both header families are present, Forwarded wins and the two
    # chains are never merged into a single identity.
    async with make_httpx2_client("127.0.0.1", forwarded_headers=True) as client:
        headers = {
            FORWARDED: "for=1.2.3.4;proto=https",
            X_FORWARDED_FOR: "9.9.9.9",
            X_FORWARDED_PROTO: "http",
        }
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "https://1.2.3.4:0"


@pytest.mark.anyio
async def test_forwarded_headers_fall_back_to_x_forwarded() -> None:
    # Without a Forwarded header, X-Forwarded-* headers are still applied.
    async with make_httpx2_client("127.0.0.1", forwarded_headers=True) as client:
        headers = {X_FORWARDED_FOR: "1.2.3.4", X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "https://1.2.3.4:0"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded_proto", "expected"),
    [
        ("http", "ws://1.2.3.4:0"),
        ("https", "wss://1.2.3.4:0"),
        ("ws", "ws://1.2.3.4:0"),
        ("wss", "wss://1.2.3.4:0"),
    ],
)
async def test_forwarded_headers_websocket(
    forwarded_proto: str,
    expected: str,
    ws_protocol_cls: type[WSProtocol | WebSocketsSansIOProtocol],
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol],
    unused_tcp_port: int,
) -> None:
    async def websocket_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "websocket"
        scheme = scope["scheme"]
        assert scope["client"] is not None
        host, port = scope["client"]
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.send", "text": f"{scheme}://{host}:{port}"})
        await send({"type": "websocket.close"})

    app_with_middleware = ProxyHeadersMiddleware(websocket_app, trusted_hosts="*", forwarded_headers=True)
    config = Config(
        app=app_with_middleware,
        ws=ws_protocol_cls,
        http=http_protocol_cls,
        lifespan="off",
        port=unused_tcp_port,
    )

    async with run_server(config):
        url = f"ws://127.0.0.1:{unused_tcp_port}"
        headers = {FORWARDED: f"for=1.2.3.4;proto={forwarded_proto}"}
        async with connect(url, additional_headers=headers) as websocket:
            data = await websocket.recv()
            assert data == expected
