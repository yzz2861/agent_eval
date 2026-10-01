from __future__ import annotations

import asyncio
import json
import socket
import struct

import h2.connection
import h2.events
import pytest

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.proxy_protocol import SIGNATURE
from .helpers import SocketWriter
from ..helpers import FakeTCPSocket, echo_framework

PROXY_V2 = SIGNATURE + bytes([0x21, 0x11])
HTTP_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: hypercorn\r\nConnection: close\r\n\r\n"
)


def proxy_header(source: str, destination: str, source_port: int, destination_port: int) -> bytes:
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


def make_pair(
    peer: tuple[str, int] = ("127.0.0.1", 54321),
) -> tuple[socket.socket, socket.socket, FakeTCPSocket]:
    raw_server, raw_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    fake_socket = FakeTCPSocket(raw_server, peer=peer)
    return raw_server, raw_client, fake_socket


async def run_server(
    event_loop: asyncio.AbstractEventLoop,
    raw_server: socket.socket,
    fake_socket: FakeTCPSocket,
    config: Config,
) -> asyncio.Task:
    reader = asyncio.StreamReader(loop=event_loop)
    transport, protocol = await event_loop.connect_accepted_socket(
        lambda: asyncio.StreamReaderProtocol(reader, loop=event_loop), raw_server
    )
    writer = asyncio.StreamWriter(transport, protocol, reader, event_loop)
    socket_writer = SocketWriter(writer, fake_socket)
    server = TCPServer(
        ASGIWrapper(echo_framework),
        event_loop,
        config,
        WorkerContext(None),
        {},
        reader,
        socket_writer,  # type: ignore[arg-type]
    )
    return event_loop.create_task(server.run())


async def read_response(raw_client: socket.socket) -> bytes:
    raw_client.setblocking(False)
    loop = asyncio.get_running_loop()
    data = bytearray()
    while True:
        try:
            chunk = await loop.sock_recv(raw_client, 4096)
        except BlockingIOError:
            await asyncio.sleep(0)
            continue
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if b"\r\n\r\n" in data and data.endswith(b"}"):
            return bytes(data)


@pytest.mark.asyncio
async def test_proxy_header_split_and_coalesced() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair()
    task = await run_server(event_loop, raw_server, fake_socket, make_config())

    preamble = proxy_header("203.0.113.5", "10.0.0.1", 33333, 443)
    payload = preamble + HTTP_REQUEST
    # One byte at a time through the real kernel socket: arbitrary splitting.
    for index in range(len(preamble)):
        await event_loop.sock_sendall(raw_client, payload[index : index + 1])
        await asyncio.sleep(0)
    await event_loop.sock_sendall(raw_client, HTTP_REQUEST)

    response = await asyncio.wait_for(read_response(raw_client), timeout=5)
    body = response.split(b"\r\n\r\n", 1)[1]
    scope = json.loads(body)["scope"]
    assert scope["client"] == ["203.0.113.5", 33333]
    assert scope["server"] == ["10.0.0.1", 443]
    assert scope["extensions"]["hypercorn.proxy_protocol"]["command"] == "proxy"
    await asyncio.wait_for(task, timeout=5)
    raw_client.close()


@pytest.mark.asyncio
async def test_proxy_header_with_http2_preface() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair()
    task = await run_server(event_loop, raw_server, fake_socket, make_config())

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
    data = h2_client.data_to_send()
    assert preface.startswith(b"PRI * HTTP/2.0\r\n\r\nSM")

    payload = proxy_header("198.51.100.7", "10.0.0.1", 4000, 443) + preface + data
    # Split the coalesced preamble + HTTP/2 bytes into odd-sized chunks.
    for index in range(0, len(payload), 3):
        await event_loop.sock_sendall(raw_client, payload[index : index + 3])
        await asyncio.sleep(0)

    raw_client.setblocking(False)
    received = b""
    deadline = 5
    import time

    end = time.monotonic() + deadline
    h2_events = []
    while time.monotonic() < end:
        try:
            chunk = await event_loop.sock_recv(raw_client, 65536)
        except (BlockingIOError, ConnectionResetError):
            await asyncio.sleep(0.01)
            continue
        if not chunk:
            break
        received += chunk
        h2_events.extend(h2_client.receive_data(chunk))
        if any(isinstance(event, h2.events.ResponseReceived) for event in h2_events):
            break
    assert any(isinstance(event, h2.events.ResponseReceived) for event in h2_events)
    response = next(event for event in h2_events if isinstance(event, h2.events.ResponseReceived))
    assert (b":status", b"200") in response.headers
    raw_client.close()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_local_command_preserves_peer() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair()
    task = await run_server(event_loop, raw_server, fake_socket, make_config())

    await event_loop.sock_sendall(raw_client, local_header()[:10])
    await asyncio.sleep(0)
    await event_loop.sock_sendall(raw_client, local_header()[10:] + HTTP_REQUEST)

    response = await asyncio.wait_for(read_response(raw_client), timeout=5)
    scope = json.loads(response.split(b"\r\n\r\n", 1)[1])["scope"]
    assert scope["client"] == ["127.0.0.1", 54321]
    assert scope["extensions"]["hypercorn.proxy_protocol"]["command"] == "local"
    await asyncio.wait_for(task, timeout=5)
    raw_client.close()


@pytest.mark.asyncio
async def test_untrusted_source_rejected_before_app() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair(peer=("8.8.8.8", 4000))
    task = await run_server(event_loop, raw_server, fake_socket, make_config())

    await event_loop.sock_sendall(raw_client, proxy_header("1.2.3.4", "10.0.0.1", 1, 2))
    raw_client.setblocking(False)
    response = b""
    try:
        while True:
            chunk = await asyncio.wait_for(event_loop.sock_recv(raw_client, 1024), timeout=2)
            if not chunk:
                break
            response += chunk
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    assert response == b""
    await asyncio.wait_for(task, timeout=5)
    raw_client.close()


@pytest.mark.asyncio
async def test_invalid_signature_rejected() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair()
    task = await run_server(event_loop, raw_server, fake_socket, make_config())

    await event_loop.sock_sendall(raw_client, b"not a proxy header at all")
    raw_client.setblocking(False)
    try:
        response = await asyncio.wait_for(event_loop.sock_recv(raw_client, 1024), timeout=2)
    except (asyncio.TimeoutError, ConnectionResetError):
        response = b""
    assert response == b""
    await asyncio.wait_for(task, timeout=5)
    raw_client.close()


@pytest.mark.asyncio
async def test_header_timeout_rejected() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair()
    config = make_config(header_timeout=0.1)
    task = await run_server(event_loop, raw_server, fake_socket, config)

    await event_loop.sock_sendall(raw_client, SIGNATURE)  # Incomplete, then silent.
    await asyncio.wait_for(task, timeout=3)
    raw_client.close()


@pytest.mark.asyncio
async def test_oversized_header_rejected() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair()
    config = make_config(max_header_size=64)
    task = await run_server(event_loop, raw_server, fake_socket, config)

    oversized = SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", 1024) + b"\x00" * 1024
    await event_loop.sock_sendall(raw_client, oversized)
    await asyncio.wait_for(task, timeout=5)
    raw_client.close()


@pytest.mark.asyncio
async def test_disabled_feature_passes_plain_http() -> None:
    event_loop = asyncio.get_running_loop()
    raw_server, raw_client, fake_socket = make_pair()
    config = Config()
    task = await run_server(event_loop, raw_server, fake_socket, config)

    await event_loop.sock_sendall(raw_client, HTTP_REQUEST)
    response = await asyncio.wait_for(read_response(raw_client), timeout=5)
    assert b"HTTP/1.1 200" in response
    await asyncio.wait_for(task, timeout=5)
    raw_client.close()
