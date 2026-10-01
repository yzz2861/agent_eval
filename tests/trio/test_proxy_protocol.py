from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from typing import cast

import h2.connection
import h2.events
import pytest
import trio

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.config import Config
from hypercorn.proxy_protocol import SIGNATURE
from hypercorn.trio import tcp_server
from hypercorn.trio.tcp_server import TCPServer
from hypercorn.trio.worker_context import WorkerContext
from ..helpers import MockSocket


def proxy_header() -> bytes:
    payload = struct.pack(
        "!4s4sHH",
        socket.inet_aton("203.0.113.10"),
        socket.inet_aton("198.51.100.20"),
        5678,
        443,
    )
    payload += bytes([0x01]) + struct.pack("!H", 2) + b"h2"
    return SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(payload)) + payload


@pytest.mark.trio
@pytest.mark.parametrize(
        ("trusted_sources", "data"),
        [
            (["127.0.0.1"], SIGNATURE + b"\x22\x00\x00\x00"),
            (["10.0.0.1"], SIGNATURE + b"\x20\x00\x00\x00"),
        ],
    )
async def test_proxy_protocol_rejected_before_app(
    trusted_sources: list[str], data: bytes, nursery: trio.Nursery
) -> None:
    called = False

    async def framework(scope: dict, receive: Callable, send: Callable) -> None:
        nonlocal called
        called = True

    client_stream, server_stream = trio.testing.memory_stream_pair()
    server_stream.socket = MockSocket()
    config = Config()
    config.proxy_protocol_trusted_sources = trusted_sources
    server = TCPServer(ASGIWrapper(framework), config, WorkerContext(None), {}, server_stream)
    nursery.start_soon(server.run)
    await client_stream.send_all(data)
    await client_stream.send_all(b"")
    assert await client_stream.receive_some(1) == b""
    assert not called


@pytest.mark.trio
async def test_proxy_protocol_timeout_before_app(nursery: trio.Nursery) -> None:
    called = False

    async def framework(scope: dict, receive: Callable, send: Callable) -> None:
        nonlocal called
        called = True

    client_stream, server_stream = trio.testing.memory_stream_pair()
    server_stream = cast("trio.SSLStream[trio.SocketStream]", server_stream)
    server_stream.socket = MockSocket()
    config = Config()
    config.proxy_protocol_trusted_sources = ["127.0.0.1"]
    config.proxy_protocol_timeout = 0.01
    server = TCPServer(ASGIWrapper(framework), config, WorkerContext(None), {}, server_stream)
    nursery.start_soon(server.run)
    await trio.sleep(0.05)
    assert await client_stream.receive_some(1) == b""
    assert not called


@pytest.mark.trio
@pytest.mark.parametrize("protocol", ["http1", "http2"])
async def test_proxy_protocol_real_split_socket(
    protocol: str, monkeypatch: pytest.MonkeyPatch, nursery: trio.Nursery
) -> None:
    monkeypatch.setattr(tcp_server, "MAX_RECV", 1)
    send_channel, receive_channel = trio.open_memory_channel[dict](1)
    config = Config()
    config.proxy_protocol_trusted_sources = ["127.0.0.1"]
    config.proxy_protocol_timeout = 2
    monkeypatch.setattr(config, "is_trusted_proxy_protocol_source", lambda client: True)

    async def framework(scope: dict, receive: Callable, send: Callable) -> None:
        await send_channel.send(scope)
        while True:
            event = await receive()
            if event["type"] == "http.request" and not event.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def handler(stream: trio.SocketStream) -> None:
        await TCPServer(
            ASGIWrapper(framework), config, WorkerContext(None), {}, stream
        ).run()

    client_socket, server_socket = trio.socket.socketpair()
    client_stream = trio.SocketStream(client_socket)
    server_stream = trio.SocketStream(server_socket)
    nursery.start_soon(handler, server_stream)
    with trio.fail_after(2):
        if protocol == "http1":
            request = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
        else:
            h2_client = h2.connection.H2Connection()
            h2_client.initiate_connection()
            stream_id = h2_client.get_next_available_stream_id()
            h2_client.send_headers(
                stream_id,
                [
                    (":method", "GET"),
                    (":path", "/"),
                    (":authority", "example"),
                    (":scheme", "http"),
                ],
                end_stream=True,
            )
            request = h2_client.data_to_send()

        await client_stream.send_all(proxy_header() + request)
        scope = await receive_channel.receive()

        if protocol == "http1":
            assert b"204" in await client_stream.receive_some(1024)
        else:
            ended = False
            while not ended:
                events = h2_client.receive_data(await client_stream.receive_some(65536))
                ended = any(isinstance(event, h2.events.StreamEnded) for event in events)

        await client_stream.aclose()

    assert scope["client"] == ("203.0.113.10", 5678)
    extension = scope["extensions"]["hypercorn.proxy_protocol"]
    assert extension["server"] == ("198.51.100.20", 443)
    assert extension["tlvs"] == {1: b"h2"}
