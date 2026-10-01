from __future__ import annotations

from json import loads
from socket import AF_UNIX, SOCK_STREAM, socketpair
import struct

import h2.connection
import h2.events
import h11
import pytest
import trio

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.config import Config
from hypercorn.proxy_protocol import SIGNATURE
from hypercorn.trio.tcp_server import TCPServer
from hypercorn.trio.worker_context import WorkerContext
from ..helpers import FakeTCPSocket, echo_framework

PROXY_V2 = SIGNATURE + bytes([0x21, 0x11])
HTTP_REQUEST = (
    b"GET / HTTP/1.1"
    + bytes([0x0D, 0x0A])
    + b"Host: hypercorn"
    + bytes([0x0D, 0x0A])
    + b"Connection: close"
    + bytes([0x0D, 0x0A, 0x0D, 0x0A])
)


class TCPPresentingStream:
    """Wrap a real trio SocketStream but expose an IPv4 peer address."""

    def __init__(self, stream: trio.SocketStream, fake_socket: FakeTCPSocket) -> None:
        self._stream = stream
        self.socket = fake_socket

    async def send_all(self, data: bytes) -> None:
        await self._stream.send_all(data)

    async def send_eof(self) -> None:
        await self._stream.send_eof()

    async def receive_some(self, max_bytes: int | None = None) -> bytes:
        return await self._stream.receive_some(max_bytes)

    async def aclose(self) -> None:
        await self._stream.aclose()


def proxy_header(source: str, destination: str, source_port: int, destination_port: int) -> bytes:
    import socket

    return (
        PROXY_V2
        + struct.pack("!H", 12)
        + socket.inet_pton(socket.AF_INET, source)
        + socket.inet_pton(socket.AF_INET, destination)
        + struct.pack("!HH", source_port, destination_port)
    )


def local_header() -> bytes:
    return SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", 0)


def make_config(
    trusted: list[str] | None = None,
    header_timeout: float | None = 5,
    max_header_size: int = 16 * 1024,
) -> Config:
    config = Config()
    config.proxy_protocol_trusted_sources = trusted if trusted is not None else ["127.0.0.0/8"]
    config.proxy_protocol_header_timeout = header_timeout
    config.proxy_protocol_max_header_size = max_header_size
    return config


def make_sockets(
    peer: tuple[str, int] = ("127.0.0.1", 54321),
) -> tuple[trio.SocketStream, trio.SocketStream, FakeTCPSocket]:
    raw_server, raw_client = socketpair(AF_UNIX, SOCK_STREAM)
    server_stream = trio.SocketStream(trio.socket.from_stdlib_socket(raw_server))
    client_stream = trio.SocketStream(trio.socket.from_stdlib_socket(raw_client))
    fake_socket = FakeTCPSocket(server_stream.socket, peer=peer)
    return server_stream, client_stream, fake_socket


async def http1_response(client_stream: trio.SocketStream) -> bytes:
    client = h11.Connection(h11.CLIENT)
    data = bytearray()
    with trio.move_on_after(5) as cancel_scope:
        while True:
            chunk = await client_stream.receive_some(4096)
            if not chunk:
                break
            data.extend(chunk)
            client.receive_data(chunk)
            if client.their_state is h11.ERROR:
                break
            event = client.next_event()
            if isinstance(event, h11.EndOfMessage):
                break
            while event is not h11.NEED_DATA:
                if isinstance(event, h11.ConnectionClosed):
                    cancel_scope.cancel()
                    break
                event = client.next_event()
    return bytes(data)


@pytest.mark.trio
async def test_proxy_header_split_and_coalesced(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets()
    config = make_config()
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework), config, WorkerContext(None), {}, presented  # type: ignore
    )
    nursery.start_soon(server.run)

    preamble = proxy_header("203.0.113.5", "10.0.0.1", 33333, 443)
    for index in range(len(preamble)):
        await client_stream.send_all(preamble[index : index + 1])
    await client_stream.send_all(HTTP_REQUEST)

    response = await http1_response(client_stream)
    separator = bytes([0x0D, 0x0A, 0x0D, 0x0A])
    body = response.split(separator, 1)[1]
    scope = loads(body)["scope"]
    assert scope["client"] == ["203.0.113.5", 33333]
    assert scope["server"] == ["10.0.0.1", 443]
    assert scope["extensions"]["hypercorn.proxy_protocol"]["command"] == "proxy"
    await client_stream.aclose()


@pytest.mark.trio
async def test_proxy_header_with_http2_preface(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets()
    config = make_config()
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework), config, WorkerContext(None), {}, presented  # type: ignore
    )
    nursery.start_soon(server.run)

    h2_client = h2.connection.H2Connection()
    h2_client.initiate_connection()
    preface = h2_client.data_to_send()
    stream_id = h2_client.get_next_available_stream_id()
    h2_client.send_headers(
        stream_id,
        [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "hypercorn"),
            (":scheme", "http"),
        ],
    )
    h2_client.end_stream(stream_id)
    payload = proxy_header("198.51.100.7", "10.0.0.1", 4000, 443) + preface + h2_client.data_to_send()
    for index in range(0, len(payload), 3):
        await client_stream.send_all(payload[index : index + 3])

    events: list[object] = []
    with trio.move_on_after(5):
        while not any(isinstance(event, h2.events.ResponseReceived) for event in events):
            chunk = await client_stream.receive_some(65536)
            if not chunk:
                break
            events.extend(h2_client.receive_data(chunk))
    response = next(event for event in events if isinstance(event, h2.events.ResponseReceived))
    assert (b":status", b"200") in response.headers
    await client_stream.aclose()


@pytest.mark.trio
async def test_local_command_preserves_peer(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets()
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework), make_config(), WorkerContext(None), {}, presented  # type: ignore
    )
    nursery.start_soon(server.run)

    header = local_header()
    await client_stream.send_all(header[:7])
    await client_stream.send_all(header[7:] + HTTP_REQUEST)

    response = await http1_response(client_stream)
    separator = bytes([0x0D, 0x0A, 0x0D, 0x0A])
    scope = loads(response.split(separator, 1)[1])["scope"]
    assert scope["client"] == ["127.0.0.1", 54321]
    assert scope["extensions"]["hypercorn.proxy_protocol"]["command"] == "local"
    await client_stream.aclose()


@pytest.mark.trio
async def test_untrusted_source_rejected_before_app(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets(peer=("8.8.8.8", 4000))
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework), make_config(), WorkerContext(None), {}, presented  # type: ignore
    )
    nursery.start_soon(server.run)

    await client_stream.send_all(proxy_header("1.2.3.4", "10.0.0.1", 1, 2))
    received = b""
    with trio.move_on_after(2) as cancel_scope:
        received = await client_stream.receive_some(1024)
        cancel_scope.cancel()
    assert received == b""
    await client_stream.aclose()


@pytest.mark.trio
async def test_invalid_signature_rejected(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets()
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework), make_config(), WorkerContext(None), {}, presented  # type: ignore
    )
    nursery.start_soon(server.run)

    await client_stream.send_all(b"plain HTTP without a proxy header")
    received = b""
    with trio.move_on_after(2) as cancel_scope:
        received = await client_stream.receive_some(1024)
        cancel_scope.cancel()
    assert received == b""
    await client_stream.aclose()


@pytest.mark.trio
async def test_header_timeout_rejected(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets()
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework),
        make_config(header_timeout=0.1),
        WorkerContext(None),
        {},
        presented,  # type: ignore
    )
    nursery.start_soon(server.run)

    await client_stream.send_all(SIGNATURE)
    with trio.move_on_after(3):
        while True:
            chunk = await client_stream.receive_some(1024)
            if not chunk:
                break
    await client_stream.aclose()


@pytest.mark.trio
async def test_oversized_header_rejected(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets()
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework),
        make_config(max_header_size=64),
        WorkerContext(None),
        {},
        presented,  # type: ignore
    )
    nursery.start_soon(server.run)

    oversized = SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", 1024) + b"\x00" * 1024
    await client_stream.send_all(oversized)
    with trio.move_on_after(3):
        while True:
            chunk = await client_stream.receive_some(1024)
            if not chunk:
                break
    await client_stream.aclose()


@pytest.mark.trio
async def test_disabled_feature_passes_plain_http(nursery: trio.Nursery) -> None:
    server_stream, client_stream, fake_socket = make_sockets()
    presented = TCPPresentingStream(server_stream, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework), Config(), WorkerContext(None), {}, presented  # type: ignore
    )
    nursery.start_soon(server.run)

    await client_stream.send_all(HTTP_REQUEST)
    response = await http1_response(client_stream)
    assert b"HTTP/1.1 200" in response
    await client_stream.aclose()
