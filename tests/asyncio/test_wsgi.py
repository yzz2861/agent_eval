from __future__ import annotations

import asyncio
from collections.abc import Callable

import h11
import pytest

from hypercorn.app_wrappers import WSGIWrapper
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from .helpers import MemoryReader, MemoryWriter


def rejecting_app(environ: dict, start_response: Callable) -> list[bytes]:
    # Reject the request having only read the first line of the body
    environ["wsgi.input"].readline()
    start_response("403 Forbidden", [("Content-Type", "text/plain"), ("Content-Length", "8")])
    return [b"rejected"]


@pytest.mark.asyncio
async def test_wsgi_rejection_sent_before_upload_completes() -> None:
    event_loop = asyncio.get_running_loop()
    server = TCPServer(
        WSGIWrapper(rejecting_app, 2**16),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(),  # type: ignore
    )
    task = event_loop.create_task(server.run())
    client = h11.Connection(h11.CLIENT)
    await server.reader.send(  # type: ignore
        client.send(
            h11.Request(
                method="POST",
                target="/",
                headers=[(b"host", b"hypercorn"), (b"content-length", b"1048576")],
            )
        )
    )
    # Only the first line of the promised 1MB body is sent
    await server.reader.send(client.send(h11.Data(data=b"first line\n")))  # type: ignore

    status = None
    body = b""
    while True:
        event = client.next_event()
        if event == h11.NEED_DATA:
            data = await asyncio.wait_for(server.writer.receive(), 5)  # type: ignore
            client.receive_data(data)
        elif isinstance(event, h11.Response):
            status = event.status_code
        elif isinstance(event, h11.Data):
            body += bytes(event.data)
        elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
            break

    # The rejection is sent whilst the upload is still incomplete
    assert status == 403
    assert body == b"rejected"

    server.reader.close()  # type: ignore
    await task
