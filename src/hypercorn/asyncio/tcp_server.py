from __future__ import annotations

import asyncio
from collections.abc import Generator
from ssl import SSLError
from typing import Any

from .task_group import TaskGroup
from .worker_context import AsyncioSingleTask, WorkerContext
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
        loop: asyncio.AbstractEventLoop,
        config: Config,
        context: WorkerContext,
        state: LifespanState,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.app = app
        self.config = config
        self.context = context
        self.loop = loop
        self.protocol: ProtocolWrapper
        self.reader = reader
        self.writer = writer
        self.send_lock = asyncio.Lock()
        self.state = state
        self.idle_task = AsyncioSingleTask()

    def __await__(self) -> Generator[Any]:
        return self.run().__await__()

    async def run(self) -> None:
        socket = self.writer.get_extra_info("socket")
        try:
            client = parse_socket_addr(socket.family, socket.getpeername())
            server = parse_socket_addr(socket.family, socket.getsockname())
            ssl_object = self.writer.get_extra_info("ssl_object")
            if ssl_object is not None:
                ssl = True
                alpn_protocol = ssl_object.selected_alpn_protocol()
            else:
                ssl = False
                alpn_protocol = "http/1.1"

            scope_extensions: dict[str, dict] = {}
            initial_data = b""
            if not ssl:
                proxy_data, initial_data = await self._read_proxy_protocol_preamble(client)
                if proxy_data is not None:
                    scope_extensions = proxy_protocol_scope_extension(proxy_data)
                    if proxy_data.command == "proxy":
                        client = proxy_data.client

            async with TaskGroup(self.loop) as task_group:
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
                await self.idle_task.restart(task_group, self._idle_timeout)
                await self._read_data(initial_data)
        except (OSError, ProxyProtocolError, asyncio.TimeoutError, TimeoutError):
            pass
        finally:
            await self._close()

    async def protocol_send(self, event: Event) -> None:
        if isinstance(event, RawData):
            async with self.send_lock:
                try:
                    self.writer.write(event.data)
                    await self.writer.drain()
                except (ConnectionError, RuntimeError):
                    await self.protocol.handle(Closed())
        elif isinstance(event, Closed):
            await self._close()
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
        deadline = self.loop.time() + self.config.proxy_protocol_timeout
        while True:
            data = await self._read_proxy_protocol_bytes(deadline)
            if data == b"":
                raise ProxyProtocolError("Connection closed before the PROXY protocol preamble")

            proxy_data, remainder = negotiator.feed(data)
            if proxy_data is not None:
                return proxy_data, remainder
            if remainder is not None:
                return None, remainder

    async def _read_proxy_protocol_bytes(self, deadline: float) -> bytes:
        return await asyncio.wait_for(
            self.reader.read(MAX_RECV), max(0.0, deadline - self.loop.time())
        )

    async def _read_data(self, initial_data: bytes = b"") -> None:
        data = initial_data
        while not self.reader.at_eof():
            try:
                if data == b"":
                    data = await asyncio.wait_for(
                        self.reader.read(MAX_RECV), self.config.read_timeout
                    )
            except (
                ConnectionError,
                OSError,
                asyncio.TimeoutError,
                TimeoutError,
                SSLError,
            ):
                break
            else:
                await self.protocol.handle(RawData(data))
                data = b""

        await self.protocol.handle(Closed())

    async def _close(self) -> None:
        try:
            self.writer.write_eof()
        except (NotImplementedError, OSError, RuntimeError):
            pass  # Likely SSL connection

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            RuntimeError,
            asyncio.CancelledError,
        ):
            pass  # Already closed
        finally:
            await self.idle_task.stop()

    async def _initiate_server_close(self) -> None:
        await self.protocol.handle(Closed())
        self.writer.close()

    async def _idle_timeout(self) -> None:
        try:
            await asyncio.wait_for(self.context.terminated.wait(), self.config.keep_alive_timeout)
        except asyncio.TimeoutError:
            pass
        await asyncio.shield(self._initiate_server_close())
