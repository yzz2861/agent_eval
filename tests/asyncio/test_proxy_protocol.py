from __future__ import annotations

import asyncio
import socket
import struct

import h2.connection
import h2.events
import pytest

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio import tcp_server
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.proxy_protocol import SIGNATURE
from .helpers import MemoryReader, MemoryWriter


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


async def scope_app(scope: dict, receive, send, scopes: asyncio.Queue) -> None:
    scopes.put_nowait(scope)
    while True:
        event = await receive()
        if event["type"] == "http.request" and not event.get("more_body", False):
            break
    await send(
        {
            "type": "http.response.start",
            "status": 204,
            "headers": [],
        }
    )
    await send({"type": "http.response.body", "body": b""})


@pytest.mark.asyncio
@pytest.mark.parametrize(
        ("trusted_sources", "data"),
        [
            (["127.0.0.1"], SIGNATURE + b"\x22\x00\x00\x00"),
            (["10.0.0.1"], SIGNATURE + b"\x20\x00\x00\x00"),
        ],
    )
async def test_proxy_protocol_rejected_before_app(
    trusted_sources: list[str], data: bytes
) -> None:
    event_loop = asyncio.get_running_loop()
    called = False

    async def framework(scope: dict, receive, send) -> None:
        nonlocal called
        called = True

    reader = MemoryReader()
    writer = MemoryWriter()
    config = Config()
    config.proxy_protocol_trusted_sources = trusted_sources
    server = TCPServer(
        ASGIWrapper(framework),
        event_loop,
        config,
        WorkerContext(None),
        {},
        reader,  # type: ignore[arg-type]
        writer,  # type: ignore[arg-type]
    )
    task = event_loop.create_task(server.run())
    await reader.send(data)
    await task
    assert not called
    assert writer.is_closed


@pytest.mark.asyncio
async def test_proxy_protocol_timeout_before_app() -> None:
    event_loop = asyncio.get_running_loop()
    called = False

    async def framework(scope: dict, receive, send) -> None:
        nonlocal called
        called = True

    config = Config()
    config.proxy_protocol_trusted_sources = ["127.0.0.1"]
    config.proxy_protocol_timeout = 0.01
    reader = MemoryReader()
    writer = MemoryWriter()
    server = TCPServer(
        ASGIWrapper(framework),
        event_loop,
        config,
        WorkerContext(None),
        {},
        reader,  # type: ignore[arg-type]
        writer,  # type: ignore[arg-type]
    )
    task = event_loop.create_task(server.run())
    await asyncio.sleep(0.05)
    assert not called
    assert task.done()
    assert writer.is_closed
    assert not called


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["http1", "http2"])
async def test_proxy_protocol_real_split_socket(
    protocol: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tcp_server, "MAX_RECV", 1)
    scopes: asyncio.Queue[dict] = asyncio.Queue()
    config = Config()
    config.proxy_protocol_trusted_sources = ["127.0.0.1"]
    config.proxy_protocol_timeout = 2
    monkeypatch.setattr(config, "is_trusted_proxy_protocol_source", lambda client: True)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await TCPServer(
            ASGIWrapper(lambda scope, receive, send: scope_app(scope, receive, send, scopes)),
            asyncio.get_running_loop(),
            config,
            WorkerContext(None),
            {},
            reader,
            writer,
        ).run()

    client_socket, server_socket = socket.socketpair()
    client_socket.setblocking(False)
    server_socket.setblocking(False)
    try:
        client_reader, client_writer = await asyncio.open_connection(sock=client_socket)
        reader = asyncio.StreamReader()
        reader_protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await asyncio.get_running_loop().connect_accepted_socket(
            lambda: reader_protocol, server_socket
        )
        writer = asyncio.StreamWriter(
            transport, reader_protocol, reader, asyncio.get_running_loop()
        )
        task = asyncio.get_running_loop().create_task(handle(reader, writer))

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

        client_writer.write(proxy_header() + request)
        await client_writer.drain()
        scope = await asyncio.wait_for(scopes.get(), timeout=2)

        if protocol == "http1":
            assert b"204" in await client_reader.read(1024)
        else:
            ended = False
            while not ended:
                events = h2_client.receive_data(await client_reader.read(65536))
                ended = any(isinstance(event, h2.events.StreamEnded) for event in events)

        client_writer.close()
        await client_writer.wait_closed()
        await task
    finally:
        client_socket.close()
        server_socket.close()

    assert scope["client"] == ("203.0.113.10", 5678)
    extension = scope["extensions"]["hypercorn.proxy_protocol"]
    assert extension["server"] == ("198.51.100.20", 443)
    assert extension["tlvs"] == {1: b"h2"}
