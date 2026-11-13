from __future__ import annotations

import base64
import hashlib
import io
import logging
import re
from unittest.mock import patch

import pytest

from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import (
    LocationParseError,
    MaxRetryError,
    NewConnectionError,
    ProxyError,
)
from urllib3.poolmanager import ProxyManager
from urllib3.response import HTTPResponse
from urllib3.util.proxy import (
    ProxyAuthStrategy,
    redact_url_userinfo,
    strip_proxy_headers,
    strip_target_auth_headers,
)
from urllib3.util.retry import Retry
from urllib3.util.url import parse_url

from .port_helpers import find_unused_port


class FakeProxySocket:
    """Socket stand-in that plays scripted HTTP responses to CONNECT."""

    def __init__(self, responses: list[bytes]) -> None:
        self._responses = list(responses)
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def settimeout(self, timeout: object) -> None:
        pass

    def setsockopt(self, *args: object) -> None:
        pass

    def shutdown(self, *args: object) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def makefile(self, mode: str, buffering: int | None = None) -> io.BytesIO:
        response = self._responses.pop(0) if self._responses else b""
        return io.BytesIO(response)


RESPONSE_200 = b"HTTP/1.1 200 Connection established\r\n\r\n"
RESPONSE_407_BASIC = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="proxy"\r\n'
    b"Content-Length: 0\r\n\r\n"
)


def make_tunnel_conn(
    responses: list[bytes],
    *,
    proxy_auth: ProxyAuthStrategy | None = None,
    tunnel_headers: dict[str, str] | None = None,
    tunnel_host: str = "target.example",
) -> tuple[HTTPConnection, FakeProxySocket]:
    from urllib3._base_connection import ProxyConfig

    proxy_config = ProxyConfig(None, False, None, None, auth=proxy_auth)
    conn = HTTPConnection(
        "proxy.example",
        8080,
        proxy=parse_url("http://proxy.example:8080"),
        proxy_config=proxy_config,
    )
    conn.set_tunnel(tunnel_host, 443, headers=tunnel_headers)
    fake_socket = FakeProxySocket(responses)
    conn._new_conn = lambda: fake_socket  # type: ignore[method-assign]
    return conn, fake_socket


def connect_request_headers(data: bytes) -> dict[str, str]:
    """Parse the headers of a single raw CONNECT request."""
    head = data.split(b"\r\n\r\n")[0].decode("latin-1")
    lines = head.split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()
    return headers


class TestProxyManager:
    @pytest.mark.parametrize(
        "proxy_scheme, scheme",
        [("http", "http"), ("https", "http"), ("https", "https")],
    )
    @pytest.mark.parametrize("zone", ["1", "25", "251", "25ethA", "et%61"])
    @pytest.mark.parametrize("retry_kind", [None, "status", "connection"])
    def test_scoped_ipv6_request_target_matches_host(
        self, proxy_scheme: str, scheme: str, zone: str, retry_kind: str | None
    ) -> None:
        responses: list[HTTPResponse | Exception] = []
        if retry_kind == "status":
            responses.extend([HTTPResponse(status=503), HTTPResponse(status=503)])
        elif retry_kind == "connection":
            responses.extend([OSError("connection reset"), OSError("connection reset")])
        responses.append(HTTPResponse(status=200))

        with ProxyManager(
            f"{proxy_scheme}://proxy:8080", use_forwarding_for_https=True
        ) as manager:
            with patch.object(
                HTTPConnectionPool,
                "_make_request",
                side_effect=responses,
            ) as request:
                response = manager.urlopen(
                    "GET",
                    f"{scheme}://[FE80::1%25{zone}]:8080/path?x=%23#fragment",
                    retries=Retry(total=2, status_forcelist=[503]),
                )

        assert response.status == 200
        assert request.call_count == len(responses)
        for call in request.call_args_list:
            assert call.args[2] == f"{scheme}://[fe80::1%{zone}]:8080/path?x=%23"
            assert call.kwargs["headers"]["Host"] == f"[fe80::1%{zone}]:8080"

    @pytest.mark.parametrize("proxy_scheme", ["http", "https"])
    def test_proxy_headers(self, proxy_scheme: str) -> None:
        url = "http://pypi.org/project/urllib3/"
        proxy_url = f"{proxy_scheme}://something:1234"
        with ProxyManager(proxy_url) as p:
            # Verify default headers
            default_headers = {"Accept": "*/*", "Host": "pypi.org"}
            headers = p._set_proxy_headers(url)

            assert headers == default_headers

            # Verify default headers don't overwrite provided headers
            provided_headers = {
                "Accept": "application/json",
                "custom": "header",
                "Host": "test.python.org",
            }
            headers = p._set_proxy_headers(url, provided_headers)

            assert headers == provided_headers

            # Verify proxy with nonstandard port
            provided_headers = {"Accept": "application/json"}
            expected_headers = provided_headers.copy()
            expected_headers.update({"Host": "pypi.org:8080"})
            url_with_port = "http://pypi.org:8080/project/urllib3/"
            headers = p._set_proxy_headers(url_with_port, provided_headers)

            assert headers == expected_headers

    def test_default_port(self) -> None:
        with ProxyManager("http://something") as p:
            assert p.proxy is not None
            assert p.proxy.port == 80
        with ProxyManager("https://something") as p:
            assert p.proxy is not None
            assert p.proxy.port == 443

    def test_proxy_port_zero(self) -> None:
        with ProxyManager("http://proxy:0") as p:
            assert p.proxy is not None
            assert p.proxy.port == 0

    def test_invalid_scheme(self) -> None:
        with pytest.raises(AssertionError):
            ProxyManager("invalid://host/p")
        with pytest.raises(ValueError):
            ProxyManager("invalid://host/p")

    def test_proxy_tunnel(self) -> None:
        http_url = parse_url("http://example.com")
        https_url = parse_url("https://example.com")
        with ProxyManager("http://proxy:8080") as p:
            assert p._proxy_requires_url_absolute_form(http_url)
            assert p._proxy_requires_url_absolute_form(https_url) is False

        with ProxyManager("https://proxy:8080") as p:
            assert p._proxy_requires_url_absolute_form(http_url)
            assert p._proxy_requires_url_absolute_form(https_url) is False

        with ProxyManager("https://proxy:8080", use_forwarding_for_https=True) as p:
            assert p._proxy_requires_url_absolute_form(http_url)
            assert p._proxy_requires_url_absolute_form(https_url)

    @pytest.mark.parametrize("proxy_scheme", ["http", "https"])
    def test_absolute_form_request_target_strips_fragment_for_custom_pool(
        self, proxy_scheme: str
    ) -> None:
        class CustomConnectionPool:
            requested_urls: list[str] = []

            def __init__(self, host: str, port: int | None = None, **kw: object):
                pass

            def urlopen(self, method: str, url: str, **kw: object) -> HTTPResponse:
                self.requested_urls.append(url)
                return HTTPResponse(status=200)

        with ProxyManager(f"{proxy_scheme}://proxy:8080") as p:
            p.pool_classes_by_scheme = p.pool_classes_by_scheme.copy()
            p.pool_classes_by_scheme[proxy_scheme] = CustomConnectionPool
            response = p.urlopen(
                "GET",
                "http://example.com/path?x=1#marker=value",
            )

        assert response.status == 200
        assert CustomConnectionPool.requested_urls == ["http://example.com/path?x=1"]

    @pytest.mark.parametrize(
        "url",
        [
            "https://victim.example\r\nInjected/path",
            "https://[::1%25%0d%0a]/",
        ],
    )
    def test_proxy_connect_rejects_control_characters_in_tunnel_host(
        self, url: str
    ) -> None:
        with ProxyManager("http://proxy:8080") as p:
            with pytest.raises(LocationParseError):
                p.connection_from_url(url)

    @pytest.mark.parametrize("host", ["foo%.example", "foo%zz.example"])
    def test_proxy_connect_rejects_malformed_percent_escapes_in_tunnel_host(
        self, host: str
    ) -> None:
        with ProxyManager("http://proxy:8080") as p:
            with pytest.raises(LocationParseError):
                p.connection_from_host(host, scheme="https")

    def test_proxy_connect_retry(self) -> None:
        retry = Retry(total=None, connect=False)
        port = find_unused_port()
        with ProxyManager(f"http://localhost:{port}") as p:
            with pytest.raises(ProxyError) as ei:
                p.urlopen("HEAD", url="http://localhost/", retries=retry)
            assert isinstance(ei.value.original_error, NewConnectionError)

        retry = Retry(total=None, connect=2)
        with ProxyManager(f"http://localhost:{port}") as p:
            with pytest.raises(MaxRetryError) as ei1:
                p.urlopen("HEAD", url="http://localhost/", retries=retry)
            assert ei1.value.reason is not None
            assert isinstance(ei1.value.reason, ProxyError)
            assert isinstance(ei1.value.reason.original_error, NewConnectionError)


class TestProxyAuthStrategy:
    def test_basic_407_then_connect_succeeds(self) -> None:
        strategy = ProxyAuthStrategy("proxy-user", "proxy-pass", scheme="basic")
        conn, fake_socket = make_tunnel_conn(
            [RESPONSE_407_BASIC, RESPONSE_200], proxy_auth=strategy
        )

        conn.connect()

        assert conn._tunnel_completed
        assert len(fake_socket.sent) == 2
        expected = "Basic " + base64.b64encode(b"proxy-user:proxy-pass").decode()
        for request in fake_socket.sent:
            assert request.startswith(b"CONNECT target.example:443 HTTP/1.1\r\n")
            headers = connect_request_headers(request)
            # Proxy-Authorization only ever comes from the strategy.
            assert headers["Proxy-Authorization"] == expected
            # Target credentials never leak into the CONNECT request.
            assert "Authorization" not in headers

    def test_connect_strips_target_authorization_header(self) -> None:
        strategy = ProxyAuthStrategy("proxy-user", "proxy-pass")
        conn, fake_socket = make_tunnel_conn(
            [RESPONSE_407_BASIC, RESPONSE_200],
            proxy_auth=strategy,
            tunnel_headers={
                "Authorization": "Bearer target-token",
                "X-Custom": "keep-me",
            },
        )

        conn.connect()

        # Even on the 407 retry, the target Bearer token is not sent.
        for request in fake_socket.sent:
            assert b"Bearer target-token" not in request
            assert b"Authorization: " not in request.replace(
                b"Proxy-Authorization: ", b""
            )
            assert b"X-Custom: keep-me" in request

    def test_digest_challenge(self) -> None:
        nonce = "abc123nonce"
        response_407_digest = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Digest realm="proxy-realm", '
            b'nonce="%s", qop=auth, algorithm=MD5\r\n'
            b"Content-Length: 0\r\n\r\n" % nonce.encode()
        )
        strategy = ProxyAuthStrategy("proxy-user", "proxy-pass", scheme="digest")
        conn, fake_socket = make_tunnel_conn(
            [response_407_digest, RESPONSE_200], proxy_auth=strategy
        )

        conn.connect()

        assert len(fake_socket.sent) == 2
        first_headers = connect_request_headers(fake_socket.sent[0])
        # Digest cannot be answered before the first challenge.
        assert "Proxy-Authorization" not in first_headers

        second_headers = connect_request_headers(fake_socket.sent[1])
        authorization = second_headers["Proxy-Authorization"]
        assert authorization.startswith("Digest ")
        params = {
            k: v or v2
            for k, v, v2 in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', authorization)
        }
        assert params["username"] == "proxy-user"
        assert params["realm"] == "proxy-realm"
        assert params["nonce"] == nonce
        assert params["uri"] == "target.example:443"
        assert params["nc"] == "00000001"
        assert params["qop"] == "auth"
        cnonce = params["cnonce"]
        ha1 = hashlib.md5(b"proxy-user:proxy-realm:proxy-pass").hexdigest()
        ha2 = hashlib.md5(b"CONNECT:target.example:443").hexdigest()
        expected_response = hashlib.md5(
            f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}".encode()
        ).hexdigest()
        assert params["response"] == expected_response

    def test_digest_rejects_bad_challenge(self) -> None:
        # Challenge missing the required nonce: fail instead of looping.
        response_407_bad_digest = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Digest realm="proxy-realm"\r\n'
            b"Content-Length: 0\r\n\r\n"
        )
        strategy = ProxyAuthStrategy("proxy-user", "proxy-pass", scheme="digest")
        conn, fake_socket = make_tunnel_conn(
            [response_407_bad_digest], proxy_auth=strategy
        )

        with pytest.raises(OSError, match="Tunnel connection failed: 407"):
            conn.connect()
        assert len(fake_socket.sent) == 1

    def test_unsupported_challenge_scheme_fails_fast(self) -> None:
        response_407_negotiate = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Negotiate\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        strategy = ProxyAuthStrategy("proxy-user", "proxy-pass", scheme="basic")
        conn, fake_socket = make_tunnel_conn(
            [response_407_negotiate], proxy_auth=strategy
        )

        with pytest.raises(OSError, match="Tunnel connection failed: 407"):
            conn.connect()
        # No point retrying a challenge we can't answer.
        assert len(fake_socket.sent) == 1

    def test_scheme_only_basic_challenge(self) -> None:
        response_407_scheme_only = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Basic\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        strategy = ProxyAuthStrategy("proxy-user", "proxy-pass", scheme="basic")
        conn, fake_socket = make_tunnel_conn(
            [response_407_scheme_only, RESPONSE_200], proxy_auth=strategy
        )

        conn.connect()

        assert conn._tunnel_completed
        assert len(fake_socket.sent) == 2

    def test_challenge_retry_limit(self) -> None:
        strategy = ProxyAuthStrategy(
            "proxy-user", "proxy-pass", max_challenge_responses=2
        )
        conn, fake_socket = make_tunnel_conn(
            [RESPONSE_407_BASIC] * 10, proxy_auth=strategy
        )

        with pytest.raises(OSError, match="Tunnel connection failed: 407"):
            conn.connect()
        # Initial CONNECT plus two answered challenges, then it stops.
        assert len(fake_socket.sent) == 3

    def test_proxy_200_without_tunnel_fails(self) -> None:
        response_200_close = (
            b"HTTP/1.1 200 Connection established\r\n"
            b"Connection: close\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        conn, fake_socket = make_tunnel_conn([response_200_close])

        with pytest.raises(OSError, match="closed the connection"):
            conn.connect()
        assert len(fake_socket.sent) == 1
        assert not conn._tunnel_completed

    def test_tunnel_not_reestablished_on_reused_connection(self) -> None:
        conn, fake_socket = make_tunnel_conn([RESPONSE_200])
        conn.connect()
        assert conn._tunnel_completed

        conn._tunnel()
        # No second CONNECT is sent through the established tunnel.
        assert len(fake_socket.sent) == 1

    def test_special_characters_in_credentials(self) -> None:
        username = "user@corp.example"
        password = "p\x01ä ss"
        strategy = ProxyAuthStrategy(username, password)
        conn, fake_socket = make_tunnel_conn([RESPONSE_200], proxy_auth=strategy)

        conn.connect()

        headers = connect_request_headers(fake_socket.sent[0])
        scheme, _, value = headers["Proxy-Authorization"].partition(" ")
        assert scheme == "Basic"
        decoded = base64.b64decode(value).decode("latin-1")
        assert decoded == f"{username}:{password}"

    def test_credentials_redacted_from_error_and_repr(self) -> None:
        username = "unique-user@corp"
        password = "unique-p\x01ass"
        strategy = ProxyAuthStrategy(username, password)
        conn, _ = make_tunnel_conn([RESPONSE_407_BASIC] * 10, proxy_auth=strategy)

        with pytest.raises(OSError) as excinfo:
            conn.connect()

        assert username not in str(excinfo.value)
        assert password not in str(excinfo.value)
        assert username not in repr(strategy)
        assert password not in repr(strategy)
        assert "***" in repr(strategy)

    def test_credentials_not_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        username = "log-scan-user"
        password = "log-scan-pass"
        strategy = ProxyAuthStrategy(username, password)
        conn, _ = make_tunnel_conn([RESPONSE_407_BASIC] * 10, proxy_auth=strategy)

        with caplog.at_level(logging.DEBUG, logger="urllib3"):
            with pytest.raises(OSError):
                conn.connect()

        assert username not in caplog.text
        assert password not in caplog.text

    def test_invalid_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unsupported proxy auth scheme"):
            ProxyAuthStrategy("user", "pass", scheme="ntlm")

    def test_ipv6_tunnel_host(self) -> None:
        conn, fake_socket = make_tunnel_conn([RESPONSE_200], tunnel_host="::1")
        conn.connect()
        assert fake_socket.sent[0].startswith(b"CONNECT [::1]:443 HTTP/1.1\r\n")


class TestProxyManagerAuth:
    def test_proxy_auth_from_url_userinfo(self) -> None:
        with ProxyManager("http://user%40corp:p%40ss@proxy:8080") as p:
            assert p.proxy_auth is not None
            # Percent-encoded userinfo is decoded, including '@'.
            assert p.proxy_auth.username == "user@corp"
            assert p.proxy_auth.password == "p@ss"
            assert p.proxy_auth.scheme == "basic"
            assert p.proxy_config.auth is p.proxy_auth

    def test_proxy_auth_explicit_tuple_and_scheme(self) -> None:
        with ProxyManager(
            "http://proxy:8080",
            proxy_auth=("user", "pass"),
            proxy_auth_scheme="digest",
        ) as p:
            assert p.proxy_auth is not None
            assert p.proxy_auth.scheme == "digest"
            assert p.proxy_auth.username == "user"

    def test_proxy_auth_explicit_string(self) -> None:
        with ProxyManager("http://proxy:8080", proxy_auth="user:pass") as p:
            assert p.proxy_auth is not None
            assert p.proxy_auth.username == "user"
            assert p.proxy_auth.password == "pass"

    def test_proxy_auth_explicit_strategy_wins_over_url(self) -> None:
        strategy = ProxyAuthStrategy("explicit", "creds", scheme="digest")
        with ProxyManager(
            "http://url-user:url-pass@proxy:8080", proxy_auth=strategy
        ) as p:
            assert p.proxy_auth is strategy

    def test_proxy_auth_none_without_credentials(self) -> None:
        with ProxyManager("http://proxy:8080") as p:
            assert p.proxy_auth is None
            assert p.proxy_config.auth is None

    def test_proxy_auth_ipv6_url(self) -> None:
        with ProxyManager("http://user:p%40ss@[::1]:8080") as p:
            assert p.proxy_auth is not None
            assert p.proxy_auth.username == "user"
            assert p.proxy_auth.password == "p@ss"
            assert p.proxy is not None
            assert p.proxy.host == "[::1]"

    def test_proxy_auth_propagates_to_pool(self) -> None:
        with ProxyManager("http://user:pass@proxy:8080") as p:
            pool = p.connection_from_url("https://target.example/")
            assert pool.proxy_config is not None
            assert pool.proxy_config.auth is p.proxy_auth

    def test_proxy_url_userinfo_redacted_in_errors(self) -> None:
        assert (
            redact_url_userinfo(parse_url("http://user:secret@proxy:8080/p"))
            == "http://proxy:8080/p"
        )
        assert redact_url_userinfo("http://user:secret@proxy:8080") == (
            "http://proxy:8080"
        )
        assert redact_url_userinfo("http://proxy:8080") == "http://proxy:8080"

    def test_proxy_config_repr_redacts_credentials(self) -> None:
        with ProxyManager("http://unique-user:unique-pass@proxy:8080") as p:
            config_repr = repr(p.proxy_config)
            assert "unique-user" not in config_repr
            assert "unique-pass" not in config_repr


class TestProxyHeaderIsolation:
    def test_strip_proxy_headers(self) -> None:
        headers = {
            "Proxy-Authorization": "Basic abc",
            "Proxy-Connection": "keep-alive",
            "Authorization": "Bearer target-token",
            "X-Custom": "1",
        }
        stripped = strip_proxy_headers(headers)
        assert stripped == {
            "Authorization": "Bearer target-token",
            "X-Custom": "1",
        }

    def test_strip_target_auth_headers(self) -> None:
        headers = {
            "Authorization": "Bearer target-token",
            "Proxy-Authorization": "Basic abc",
            "X-Custom": "1",
        }
        stripped = strip_target_auth_headers(headers)
        assert stripped == {
            "Proxy-Authorization": "Basic abc",
            "X-Custom": "1",
        }

    def test_tunneled_request_headers_strip_proxy_headers(self) -> None:
        from urllib3.connectionpool import HTTPSConnectionPool

        pool = HTTPSConnectionPool(
            "target.example",
            443,
            _proxy=parse_url("http://proxy.example:8080"),
            _proxy_headers={"Proxy-Authorization": "Basic cHJveHk6Y3JlZHM="},
        )
        request_headers = {
            "Authorization": "Bearer target-token",
            "Proxy-Authorization": "Basic cHJveHk6Y3JlZHM=",
            "Proxy-Connection": "keep-alive",
        }
        with (
            patch.object(HTTPSConnectionPool, "_prepare_proxy"),
            patch.object(
                HTTPSConnectionPool,
                "_make_request",
                return_value=HTTPResponse(status=200),
            ) as make_request,
        ):
            pool.urlopen("GET", "/", headers=request_headers)

        sent_headers = make_request.call_args.kwargs["headers"]
        # Proxy credentials stay on the proxy hop only...
        assert "Proxy-Authorization" not in sent_headers
        assert "Proxy-Connection" not in sent_headers
        # ...while target credentials reach the target inside the tunnel.
        assert sent_headers["Authorization"] == "Bearer target-token"

    def test_prepare_proxy_drops_target_authorization(self) -> None:
        from unittest.mock import Mock

        from urllib3.connectionpool import HTTPSConnectionPool

        pool = HTTPSConnectionPool(
            "target.example",
            443,
            _proxy=parse_url("http://proxy.example:8080"),
            _proxy_headers={
                "Authorization": "Bearer target-token",
                "Proxy-Authorization": "Basic cHJveHk6Y3JlZHM=",
            },
        )
        conn = Mock()
        pool._prepare_proxy(conn)

        tunnel_headers = conn.set_tunnel.call_args.kwargs["headers"]
        assert "Authorization" not in tunnel_headers
        assert tunnel_headers["Proxy-Authorization"] == "Basic cHJveHk6Y3JlZHM="

    def test_retry_history_and_max_retry_error_redact_userinfo(self) -> None:
        retry = Retry(total=0)
        with pytest.raises(MaxRetryError) as excinfo:
            retry.increment(
                "GET",
                "http://history-user:history-pass@example.com/",
                error=NewConnectionError(None, "failed"),  # type: ignore[arg-type]
            )
        message = str(excinfo.value)
        assert "history-user" not in message
        assert "history-pass" not in message

        retry = Retry(total=1)
        new_retry = retry.increment(
            "GET",
            "http://history-user:history-pass@example.com/",
            error=NewConnectionError(None, "failed"),  # type: ignore[arg-type]
        )
        assert new_retry.history
        for entry in new_retry.history:
            assert entry.url is not None
            assert "history-user" not in entry.url
            assert "history-pass" not in entry.url
