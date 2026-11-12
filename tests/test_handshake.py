"""Tests for the HTTP/1.1 WebSocket handshake."""

from __future__ import annotations

import h11
import pytest

from wsproto import WSConnection
from wsproto.connection import CLIENT, SERVER, ConnectionState
from wsproto.events import AcceptConnection, Ping, RejectConnection, Request
from wsproto.handshake import (
    WEBSOCKET_REJECT_REASON_HEADER,
    H11Handshake,
    OriginPolicy,
    OriginRejectionReason,
)
from wsproto.utilities import (
    LocalProtocolError,
    RemoteProtocolError,
    generate_accept_token,
    normed_header_dict,
)

KEY = b"VQr8cvwwZ1fEk62PDq8J3A=="


def _request_bytes(
    host: bytes | None = b"example.com",
    origin: bytes | None = b"https://example.com",
    extra_headers: bytes = b"",
) -> bytes:
    lines = [b"GET / HTTP/1.1"]
    if host is not None:
        lines.append(b"Host: " + host)
    lines.extend(
        [
            b"Connection: Upgrade",
            b"Upgrade: websocket",
            b"Sec-WebSocket-Version: 13",
            b"Sec-WebSocket-Key: " + KEY,
        ],
    )
    if origin is not None:
        lines.append(b"Origin: " + origin)
    if extra_headers:
        lines.append(extra_headers)
    return b"\r\n".join(lines) + b"\r\n\r\n"


def _policy(**overrides: object) -> OriginPolicy:
    values: dict[str, object] = {
        "allowed_origins": ["https://example.com"],
        "allowed_hosts": ["example.com"],
    }
    values.update(overrides)
    return OriginPolicy(**values)


def _assert_policy_rejection(
    data: bytes,
    reason_code: str,
    policy: OriginPolicy | None = None,
) -> RejectConnection:
    server = H11Handshake(SERVER, origin_policy=policy or _policy())
    with pytest.raises(RemoteProtocolError) as exc_info:
        server.receive_data(data)
    assert exc_info.value.reason_code == reason_code
    rejection = exc_info.value.event_hint
    assert isinstance(rejection, RejectConnection)
    assert rejection.status_code == 403
    assert rejection.reason_code == reason_code

    client = h11.Connection(h11.CLIENT)
    client.receive_data(server.send(rejection))
    response = client.next_event()
    assert isinstance(response, h11.Response)
    assert response.status_code == 403
    headers = normed_header_dict(list(response.headers))
    assert headers[WEBSOCKET_REJECT_REASON_HEADER] == reason_code.encode("ascii")
    return rejection


def test_successful_handshake() -> None:
    client = H11Handshake(CLIENT)
    server = H11Handshake(SERVER)

    server.receive_data(client.send(Request(host="localhost", target="/")))
    assert isinstance(next(server.events()), Request)

    client.receive_data(server.send(AcceptConnection()))
    assert isinstance(next(client.events()), AcceptConnection)

    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN

    assert repr(client) == "H11Handshake(client=True, state=ConnectionState.OPEN)"
    assert repr(server) == "H11Handshake(client=False, state=ConnectionState.OPEN)"


def test_host_encoding() -> None:
    client = H11Handshake(CLIENT)
    server = H11Handshake(SERVER)
    data = client.send(Request(host="芝士汉堡", target="/"))
    assert b"Host: xn--7ks3rz39bh7u" in data
    server.receive_data(data)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "芝士汉堡"


@pytest.mark.parametrize("http", [b"HTTP/1.0", b"HTTP/1.1"])
def test_rejected_handshake(http: bytes) -> None:
    server = H11Handshake(SERVER)
    with pytest.raises(RemoteProtocolError):
        server.receive_data(
            b"GET / " + http + b"\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: VQr8cvwwZ1fEk62PDq8J3A==\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"\r\n",
        )


def test_initiate_upgrade_as_client() -> None:
    client = H11Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.initiate_upgrade_connection([], "/")


def test_send_invalid_event() -> None:
    client = H11Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(Ping())


def test_h11_multiple_headers_handshake() -> None:
    server = H11Handshake(SERVER)
    data = (
        b"GET wss://api.website.xyz/ws HTTP/1.1\r\n"
        b"Host: api.website.xyz\r\n"
        b"Connection: Upgrade\r\n"
        b"Pragma: no-cache\r\n"
        b"Cache-Control: no-cache\r\n"
        b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) "
        b"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36\r\n"
        b"Upgrade: websocket\r\n"
        b"Origin: https://website.xyz\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
        b"Sec-WebSocket-Key: tOzeAzi9xK7ADxxEdTzmaA==\r\n"
        b"Sec-WebSocket-Extensions: this-extension; isnt-seen, even-tho, it-should-be\r\n"
        b"Sec-WebSocket-Protocol: there-protocols\r\n"
        b"Sec-WebSocket-Protocol: arent-seen\r\n"
        b"Sec-WebSocket-Extensions: this-extension; were-gonna-see, and-another-extension; were-also; gonna-see=100; percent\r\n"
        b"Sec-WebSocket-Protocol: only-these-protocols, are-seen, from-the-request-object\r\n"
        b"\r\n"
    )
    server.receive_data(data)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.subprotocols == [
        "there-protocols",
        "arent-seen",
        "only-these-protocols",
        "are-seen",
        "from-the-request-object",
    ]
    assert request.extensions == [
        "this-extension; isnt-seen",
        "even-tho",
        "it-should-be",
        "this-extension; were-gonna-see",
        "and-another-extension; were-also; gonna-see=100; percent",
    ]


def test_origin_policy_same_origin_preserves_accept_token() -> None:
    server = H11Handshake(SERVER, origin_policy=_policy())
    server.receive_data(_request_bytes())
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "example.com"

    client = h11.Connection(h11.CLIENT)
    client.send(
        h11.Request(
            method=b"GET",
            target=b"/",
            headers=[
                (b"Host", b"example.com"),
                (b"Connection", b"Upgrade"),
                (b"Upgrade", b"websocket"),
                (b"Sec-WebSocket-Version", b"13"),
                (b"Sec-WebSocket-Key", KEY),
                (b"Origin", b"https://example.com"),
            ],
        ),
    )
    client.receive_data(server.send(AcceptConnection()))
    response = client.next_event()
    assert isinstance(response, h11.InformationalResponse)
    assert response.status_code == 101
    headers = normed_header_dict(list(response.headers))
    assert headers[b"sec-websocket-accept"] == generate_accept_token(KEY)


def test_origin_policy_rejects_cross_site_origin() -> None:
    rejection = _assert_policy_rejection(
        _request_bytes(origin=b"https://evil.example"),
        OriginRejectionReason.ORIGIN_HOST_MISMATCH,
    )
    assert b"evil.example" not in repr(rejection).encode("ascii")


def test_origin_policy_rejection_reason_reaches_client() -> None:
    client = H11Handshake(CLIENT)
    server = H11Handshake(SERVER, origin_policy=_policy())
    request_data = client.send(
        Request(
            host="example.com",
            target="/",
            extra_headers=[(b"origin", b"https://evil.example")],
        ),
    )
    with pytest.raises(RemoteProtocolError) as exc_info:
        server.receive_data(request_data)
    response_data = server.send(exc_info.value.event_hint)
    client.receive_data(response_data)
    rejection = next(client.events())
    assert isinstance(rejection, RejectConnection)
    assert rejection.status_code == 403
    assert rejection.reason_code == OriginRejectionReason.ORIGIN_HOST_MISMATCH


def test_origin_policy_rejects_missing_origin_by_default() -> None:
    _assert_policy_rejection(
        _request_bytes(origin=None),
        OriginRejectionReason.MISSING_ORIGIN,
    )


def test_origin_policy_allows_missing_origin_when_configured() -> None:
    server = H11Handshake(
        SERVER,
        origin_policy=_policy(allow_missing_origin=True),
    )
    server.receive_data(_request_bytes(origin=None))
    request = next(server.events())
    assert isinstance(request, Request)


def test_origin_policy_rejects_duplicate_origin() -> None:
    data = _request_bytes(extra_headers=b"Origin: https://evil.example")
    _assert_policy_rejection(
        data,
        OriginRejectionReason.DUPLICATE_ORIGIN,
    )


def test_origin_policy_rejects_duplicate_host() -> None:
    data = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Host: internal.example\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: websocket\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Key: " + KEY + b"\r\n"
        b"Origin: https://example.com\r\n"
        b"\r\n"
    )
    _assert_policy_rejection(
        data,
        OriginRejectionReason.DUPLICATE_HOST,
    )


def test_origin_policy_rejects_merged_host_header() -> None:
    _assert_policy_rejection(
        _request_bytes(host=b"internal.example, example.com"),
        OriginRejectionReason.DUPLICATE_HOST,
    )


def test_origin_policy_trusts_only_configured_proxy_header() -> None:
    policy = _policy(
        trust_proxy_host=True,
        proxy_host_header="x-real-host",
    )
    server = H11Handshake(SERVER, origin_policy=policy)
    server.receive_data(
        _request_bytes(
            host=b"127.0.0.1:8080",
            extra_headers=b"X-Real-Host: example.com",
        ),
    )
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "example.com"


def test_origin_policy_ignores_unconfigured_forwarded_host() -> None:
    policy = _policy(trust_proxy_host=True, proxy_host_header="x-real-host")
    rejection = _assert_policy_rejection(
        _request_bytes(
            host=b"127.0.0.1:8080",
            extra_headers=b"X-Forwarded-Host: example.com",
        ),
        OriginRejectionReason.HOST_NOT_ALLOWED,
        policy,
    )
    assert b"127.0.0.1" not in repr(rejection).encode("ascii")


def test_origin_policy_does_not_trust_proxy_header_by_default() -> None:
    _assert_policy_rejection(
        _request_bytes(
            host=b"127.0.0.1:8080",
            extra_headers=b"X-Forwarded-Host: example.com",
        ),
        OriginRejectionReason.HOST_NOT_ALLOWED,
    )


def test_origin_policy_rejects_duplicate_proxy_host() -> None:
    policy = _policy(trust_proxy_host=True, proxy_host_header="x-real-host")
    _assert_policy_rejection(
        _request_bytes(
            host=b"127.0.0.1:8080",
            extra_headers=b"X-Real-Host: example.com\r\nX-Real-Host: other.example",
        ),
        OriginRejectionReason.DUPLICATE_PROXY_HOST,
        policy,
    )


@pytest.mark.parametrize(
    ("origin", "reason_code"),
    [
        (b"https://example.com/path", OriginRejectionReason.INVALID_ORIGIN),
        (b"https://user:pass@example.com", OriginRejectionReason.ORIGIN_USERINFO_NOT_ALLOWED),
        (b"ftp://example.com", OriginRejectionReason.ORIGIN_SCHEME_NOT_ALLOWED),
        (b"not-a-uri", OriginRejectionReason.INVALID_ORIGIN),
    ],
)
def test_origin_policy_rejects_invalid_origins(
    origin: bytes,
    reason_code: str,
) -> None:
    _assert_policy_rejection(_request_bytes(origin=origin), reason_code)


def test_origin_policy_host_matching_is_case_insensitive() -> None:
    policy = _policy(
        allowed_origins=["https://EXAMPLE.com"],
        allowed_hosts=["Example.COM"],
    )
    server = H11Handshake(SERVER, origin_policy=policy)
    server.receive_data(
        _request_bytes(host=b"Example.COM", origin=b"https://EXAMPLE.com"),
    )
    request = next(server.events())
    assert isinstance(request, Request)


def test_origin_policy_must_name_proxy_header_when_trusting_proxy() -> None:
    with pytest.raises(ValueError, match="proxy_host_header"):
        OriginPolicy(trust_proxy_host=True)


def test_origin_policy_cli_upgrade_entry_uses_policy() -> None:
    server = H11Handshake(SERVER, origin_policy=_policy())
    with pytest.raises(RemoteProtocolError) as exc_info:
        server.initiate_upgrade_connection(
            [
                (b"Host", b"example.com"),
                (b"Connection", b"Upgrade"),
                (b"Upgrade", b"websocket"),
                (b"Sec-WebSocket-Version", b"13"),
                (b"Sec-WebSocket-Key", KEY),
                (b"Origin", b"https://evil.example"),
            ],
            "/",
        )
    assert exc_info.value.reason_code == OriginRejectionReason.ORIGIN_HOST_MISMATCH
    assert exc_info.value.event_hint.status_code == 403


def test_origin_policy_wsconnection_uses_policy() -> None:
    server = WSConnection(SERVER, origin_policy=_policy())
    with pytest.raises(RemoteProtocolError) as exc_info:
        server.receive_data(_request_bytes(origin=b"https://evil.example"))
    assert exc_info.value.event_hint.status_code == 403


def test_default_without_policy_accepts_cross_site_origin() -> None:
    server = H11Handshake(SERVER)
    server.receive_data(_request_bytes(origin=b"https://evil.example"))
    request = next(server.events())
    assert isinstance(request, Request)


def test_default_without_policy_accepts_duplicate_origin() -> None:
    server = H11Handshake(SERVER)
    server.receive_data(_request_bytes(extra_headers=b"Origin: https://evil.example"))
    request = next(server.events())
    assert isinstance(request, Request)


def test_default_without_policy_keeps_duplicate_host_as_bad_request() -> None:
    server = H11Handshake(SERVER)
    data = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Host: internal.example\r\n"
        b"Connection: Upgrade\r\n"
        b"Upgrade: websocket\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Key: " + KEY + b"\r\n"
        b"Origin: https://example.com\r\n"
        b"\r\n"
    )
    with pytest.raises(RemoteProtocolError) as exc_info:
        server.receive_data(data)
    assert exc_info.value.event_hint.status_code == 400
