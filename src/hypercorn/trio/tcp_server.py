from __future__ import annotations

from collections.abc import Generator
from math import inf
from typing import Any

import trio

from .task_group import TaskGroup
from .worker_context import TrioSingleTask, WorkerContext
from ..config import Config
from ..events import Closed, Event, RawData, Updated
from ..protocol import ProtocolWrapper
from ..proxy_protocol import (
    ProxyProtocolError,
    ProxyProtocolNegotiator,
    ProxyProtocolData,
    proxy_protocol_scope_extension,
)
from ..typing import AppWrapper, ConnectionState, LifespanState
from ..utils import parse_socket_addr

MAX_RECV = 2**16


class TCPServer:
    def __init__(
        self,
        app: AppWrapper,
        config: Config,
        context: WorkerContext,
        state: LifespanState,
        stream: trio.SSLStream[trio.SocketStream],
    ) -> None:
        self.app = app
        self.config = config
        self.context = context
        self.protocol: ProtocolWrapper
        self.send_lock = trio.Lock()
        self.idle_task = TrioSingleTask()
        self.stream = stream
        self.state = state

    def __await__(self) -> Generator[Any]:
        return self.run().__await__()

    async def run(self) -> None:
        try:
            try:
                with trio.fail_after(self.config.ssl_handshake_timeout):
                    await self.stream.do_handshake()
            except (trio.BrokenResourceError, trio.TooSlowError):
                return  # Handshake failed
            alpn_protocol = self.stream.selected_alpn_protocol()
            socket = self.stream.transport_stream.socket
            ssl = True
        except AttributeError:  # Not SSL
            alpn_protocol = "http/1.1"
            socket = self.stream.socket
            ssl = False

        try:
            client = parse_socket_addr(socket.family, socket.getpeername())
            server = parse_socket_addr(socket.family, socket.getsockname())
            scope_extensions: dict[str, dict] = {}
            initial_data = b""

            if not ssl:
                proxy_data, initial_data = await self._read_proxy_protocol_preamble(client)
                if proxy_data is not None:
                    scope_extensions = proxy_protocol_scope_extension(proxy_data)
                    if proxy_data.command == "proxy":
                        client = proxy_data.client

            async with TaskGroup() as task_group:
                self._task_group = task_group
                self.protocol = ProtocolWrapper(
                    self.app,
                    self.config,
                    self.context,
                    task_group,
                    ConnectionState(self.state),
                    ssl,
                    client,
                    server,
                    self.protocol_send,
                    alpn_protocol,
                    scope_extensions,
                )
                await self.protocol.initiate()
                await self.idle_task.restart(self._task_group, self._idle_timeout)
                await self._read_data(initial_data)
        except (
            OSError,
            ProxyProtocolError,
            trio.BrokenResourceError,
            trio.ClosedResourceError,
            trio.TooSlowError,
        ):
            pass
        finally:
            await self._close()

    async def protocol_send(self, event: Event) -> None:
        if isinstance(event, RawData):
            async with self.send_lock:
                try:
                    with trio.CancelScope() as cancel_scope:
                        cancel_scope.shield = True
                        await self.stream.send_all(event.data)
                except (trio.BrokenResourceError, trio.ClosedResourceError):
                    await self.protocol.handle(Closed())
        elif isinstance(event, Closed):
            await self._close()
            await self.protocol.handle(Closed())
        elif isinstance(event, Updated):
            if event.idle:
                await self.idle_task.restart(self._task_group, self._idle_timeout)
            else:
                await self.idle_task.stop()

    async def _read_proxy_protocol_preamble(
        self, client: tuple[str, int] | None
    ) -> tuple[ProxyProtocolData | None, bytes]:
        if not self.config.proxy_protocol_trusted_sources:
            return None, b""

        negotiator = ProxyProtocolNegotiator(
            self.config.is_trusted_proxy_protocol_source(client)
        )
        with trio.fail_after(self.config.proxy_protocol_timeout):
            while True:
                data = await self.stream.receive_some(MAX_RECV)
                if data == b"":
                    raise ProxyProtocolError(
                        "Connection closed before the PROXY protocol preamble"
                    )

                proxy_data, remainder = negotiator.feed(bytes(data))
                if proxy_data is not None:
                    return proxy_data, remainder
                if remainder is not None:
                    return None, remainder

    async def _read_data(self, initial_data: bytes = b"") -> None:
        data = initial_data
        while True:
            try:
                if data == b"":
                    with trio.fail_after(self.config.read_timeout or inf):
                        data = await self.stream.receive_some(MAX_RECV)
            except (
                trio.ClosedResourceError,
                trio.BrokenResourceError,
                trio.TooSlowError,
            ):
                break
            else:
                await self.protocol.handle(RawData(bytes(data)))
                if data == b"":
                    break
                data = b""
        await self.protocol.handle(Closed())

    async def _close(self) -> None:
        try:
            await self.stream.send_eof()
        except (
            trio.BrokenResourceError,
            AttributeError,
            trio.BusyResourceError,
            trio.ClosedResourceError,
        ):
            # They're already gone, nothing to do
            # Or it is a SSL stream
            pass
        await self.stream.aclose()

    async def _idle_timeout(self) -> None:
        with trio.move_on_after(self.config.keep_alive_timeout):
            await self.context.terminated.wait()

        with trio.CancelScope(shield=True):
            await self._initiate_server_close()

    async def _initiate_server_close(self) -> None:
        await self.protocol.handle(Closed())
        await self.stream.aclose()
