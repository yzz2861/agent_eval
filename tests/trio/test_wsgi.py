from __future__ import annotations

from collections.abc import Callable
from typing import cast

import h11
import pytest
import trio

from hypercorn.app_wrappers import WSGIWrapper
from hypercorn.config import Config
from hypercorn.trio.tcp_server import TCPServer
from hypercorn.trio.worker_context import WorkerContext
from ..helpers import MockSocket


def rejecting_app(environ: dict, start_response: Callable) -> list[bytes]:
    # Reject the request having only read the first line of the body
    environ["wsgi.input"].readline()
    start_response("403 Forbidden", [("Content-Type", "text/plain"), ("Content-Length", "8")])
    return [b"rejected"]


@pytest.mark.trio
async def test_wsgi_rejection_sent_before_upload_completes(
    nursery: trio._core._run.Nursery,
) -> None:
    client_stream, server_stream = trio.testing.memory_stream_pair()
    server_stream = cast("trio.SSLStream[trio.SocketStream]", server_stream)
    server_stream.socket = MockSocket()
    server = TCPServer(
        WSGIWrapper(rejecting_app, 2**16), Config(), WorkerContext(None), {}, server_stream
    )
    nursery.start_soon(server.run)
    client = h11.Connection(h11.CLIENT)
    await client_stream.send_all(
        client.send(
            h11.Request(
                method="POST",
                target="/",
                headers=[(b"host", b"hypercorn"), (b"content-length", b"1048576")],
            )
        )
    )
    # Only the first line of the promised 1MB body is sent
    await client_stream.send_all(client.send(h11.Data(data=b"first line\n")))

    status = None
    body = b""
    with trio.move_on_after(5):
        while True:
            event = client.next_event()
            if event == h11.NEED_DATA:
                data = bytes(await client_stream.receive_some(1024))
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

    await client_stream.aclose()
