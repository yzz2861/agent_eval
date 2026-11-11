from __future__ import annotations

import h11
import pytest

from wsproto.connection import CLIENT, SERVER, ConnectionState
from wsproto.events import AcceptConnection, Ping, RejectConnection, Request
from wsproto.extensions import PerMessageDeflate
from wsproto.handshake import H11Handshake
from wsproto.utilities import (
    LocalProtocolError,
    RemoteProtocolError,
    generate_accept_token,
)


def _extension_request(extension_headers: list[tuple[bytes, bytes]]) -> bytes:
    nonce = b"VQr8cvwwZ1fEk62PDq8J3A=="
    client = h11.Connection(h11.CLIENT)
    return client.send(
        h11.Request(
            method="GET",
            target="/",
            headers=[
                (b"Host", b"localhost"),
                (b"Connection", b"Upgrade"),
                (b"Upgrade", b"websocket"),
                (b"Sec-WebSocket-Version", b"13"),
                (b"Sec-WebSocket-Key", nonce),
                *extension_headers,
            ],
        ),
    )


def _server_with_extensions(extension_headers: list[tuple[bytes, bytes]]) -> H11Handshake:
    server = H11Handshake(SERVER)
    server.receive_data(_extension_request(extension_headers))
    next(server.events())
    return server


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


@pytest.mark.parametrize(
    "extension_header",
    [
        b"permessage-deflate; client_max_window_bits=8; client_max_window_bits=15",
        b"permessage-deflate; server_max_window_bits=15; server_max_window_bits=12",
        b"permessage-deflate; server_no_context_takeover=evil",
        b"permessage-deflate; client_no_context_takeoverX",
        b"permessage-deflate; client_max_window_bits=",
        b"permessage-deflate; client_max_window_bits=0x10",
        b"permessage-deflate; client_max_window_bits=010",
        b"permessage-deflate; client_max_window_bits=8",
        b"permessage-deflate; client_max_window_bits=16",
        b"permessage-deflate; bogus_parameter",
        b"permessage-deflate, permessage-deflate; client_max_window_bits=12",
    ],
)
def test_server_rejects_malformed_extension_offer(extension_header: bytes) -> None:
    server = H11Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(
            _extension_request(
                [(b"Sec-WebSocket-Extensions", extension_header)],
            ),
        )
    assert excinfo.value.event_hint == RejectConnection(status_code=400)
    assert server.state is ConnectionState.CONNECTING


def test_malformed_extension_never_reaches_upgrade_response() -> None:
    request = _extension_request(
        [
            (
                b"Sec-WebSocket-Extensions",
                b"permessage-deflate; client_max_window_bits=8; "
                b"client_max_window_bits=15",
            ),
        ],
    )
    server = H11Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(request)
    rejection = server.send(excinfo.value.event_hint)
    assert b"HTTP/1.1 400" in rejection
    assert b"Sec-WebSocket-Extensions" not in rejection
    assert b"client_max_window_bits" not in rejection


def test_server_accepts_browser_style_extension_offer() -> None:
    extension = PerMessageDeflate()
    server = _server_with_extensions(
        [
            (
                b"Sec-WebSocket-Extensions",
                b"permessage-deflate; CLIENT_MAX_WINDOW_BITS ; "
                b"SERVER_MAX_WINDOW_BITS = 12 ; SERVER_NO_CONTEXT_TAKEOVER",
            ),
        ],
    )

    response = server.send(AcceptConnection(extensions=[extension]))
    assert b"HTTP/1.1 101" in response
    assert (
        b"Sec-WebSocket-Extensions: permessage-deflate; "
        b"server_no_context_takeover; client_max_window_bits=15; "
        b"server_max_window_bits=12"
    ) in response
    assert extension.enabled()
    assert extension.server_no_context_takeover is True
    assert extension.server_max_window_bits == 12
    assert extension.client_max_window_bits == 15


def test_server_ignores_unknown_extension_without_echoing_it() -> None:
    extension = PerMessageDeflate()
    server = _server_with_extensions(
        [
            (
                b"Sec-WebSocket-Extensions",
                b"x-unknown; client_max_window_bits=8, "
                b"permessage-deflate; client_max_window_bits=12",
            ),
        ],
    )

    response = server.send(AcceptConnection(extensions=[extension]))
    assert b"HTTP/1.1 101" in response
    assert b"x-unknown" not in response
    assert b"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=12" in response


def test_server_ignores_unknown_extension_even_when_it_looks_invalid() -> None:
    server = _server_with_extensions(
        [(b"Sec-WebSocket-Extensions", b"x-unknown; client_max_window_bits=8")],
    )
    response = server.send(AcceptConnection(extensions=[PerMessageDeflate()]))
    assert b"HTTP/1.1 101" in response
    assert b"Sec-WebSocket-Extensions" not in response


def test_client_rejects_malformed_extension_response() -> None:
    client = H11Handshake(CLIENT)
    request_bytes = client.send(Request(host="localhost", target="/"))
    parsed = h11.Connection(h11.SERVER)
    parsed.receive_data(request_bytes)
    request = parsed.next_event()
    nonce = dict(request.headers)[b"sec-websocket-key"]
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + generate_accept_token(nonce) + b"\r\n"
        b"Sec-WebSocket-Extensions: permessage-deflate; "
        b"server_no_context_takeover=evil\r\n"
        b"\r\n"
    )
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(response)
    assert excinfo.value.event_hint == RejectConnection(status_code=400)
    assert client.state is ConnectionState.CONNECTING


def test_client_accepts_well_formed_extension_response() -> None:
    extension = PerMessageDeflate()
    client = H11Handshake(CLIENT)
    request_bytes = client.send(
        Request(host="localhost", target="/", extensions=[extension]),
    )
    parsed = h11.Connection(h11.SERVER)
    parsed.receive_data(request_bytes)
    request = parsed.next_event()
    nonce = dict(request.headers)[b"sec-websocket-key"]
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + generate_accept_token(nonce) + b"\r\n"
        b"Sec-WebSocket-Extensions: permessage-deflate; "
        b"client_max_window_bits=12; server_max_window_bits=13\r\n"
        b"\r\n"
    )
    client.receive_data(response)
    event = next(client.events())
    assert isinstance(event, AcceptConnection)
    assert client.state is ConnectionState.OPEN
    assert extension.enabled()
    assert extension.client_max_window_bits == 12
    assert extension.server_max_window_bits == 13
