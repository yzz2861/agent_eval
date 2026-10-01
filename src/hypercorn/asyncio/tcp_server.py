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
from ..proxy_protocol import ProxyProtocolError, ProxyInfo, read_proxy_header
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
        proxy_info: ProxyInfo | None = None
        initial_data = b""
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
                if self.config.proxy_protocol_enabled:
                    if not self.config.is_proxy_protocol_trusted(client):
                        raise ProxyProtocolError("Untrusted PROXY protocol source")
                    proxy_info, initial_data = await self._read_proxy_header()
                    if proxy_info.client is not None:
                        client = proxy_info.client
                    if proxy_info.server is not None:
                        server = proxy_info.server

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
                    proxy_info,
                )
                await self.protocol.initiate()
                await self.idle_task.restart(task_group, self._idle_timeout)
                await self._read_data(initial_data)
        except OSError:
            pass
        except ProxyProtocolError:
            pass
        finally:
            await self._close()

    async def _read_proxy_header(self) -> tuple[ProxyInfo, bytes]:
        async def receive() -> bytes:
            try:
                return await self.reader.read(MAX_RECV)
            except (ConnectionError, OSError, SSLError) as error:
                raise ProxyProtocolError("Failed to read the PROXY protocol header") from error

        try:
            return await asyncio.wait_for(
                read_proxy_header(receive, self.config.proxy_protocol_max_header_size),
                self.config.proxy_protocol_header_timeout,
            )
        except asyncio.TimeoutError as error:
            raise ProxyProtocolError("Timed out reading the PROXY protocol header") from error

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

    async def _read_data(self, initial_data: bytes = b"") -> None:
        if initial_data:
            await self.protocol.handle(RawData(initial_data))
        while not self.reader.at_eof():
            try:
                data = await asyncio.wait_for(self.reader.read(MAX_RECV), self.config.read_timeout)
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
