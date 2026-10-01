from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from types import TracebackType
from typing import TYPE_CHECKING

from . import hdrs
from .client_exceptions import ClientConnectionResetError
from .http import HttpVersion11, StreamWriter
from .streams import StreamReader
from .typedefs import LooseHeaders
from .web_response import StreamResponse

if TYPE_CHECKING:
    from .web_request import BaseRequest

__all__ = ("TunnelConnection", "TunnelResponse")


class TunnelConnection:
    """Bidirectional byte channel for an established HTTP CONNECT tunnel."""

    __slots__ = ("_reader", "_writer", "_write_eof_sent")

    def __init__(
        self,
        reader: StreamReader,
        writer: StreamWriter,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._write_eof_sent = False

    @property
    def closed(self) -> bool:
        transport = self._writer.transport
        return transport is None or transport.is_closing()

    def get_extra_info(self, name: str, default: object = None) -> object:
        transport = self._writer.transport
        if transport is None:
            return default
        return transport.get_extra_info(name, default)

    async def read(self, n: int = -1) -> bytes:
        if n < 0:
            return await self._reader.readany()
        return await self._reader.read(n)

    async def readany(self) -> bytes:
        return await self._reader.readany()

    async def readexactly(self, n: int) -> bytes:
        return await self._reader.readexactly(n)

    def iter_chunked(self, n: int) -> AsyncIterator[bytes]:
        return self._reader.iter_chunked(n)

    def iter_any(self) -> AsyncIterator[bytes]:
        return self._reader.iter_any()

    async def write(
        self, data: bytes | bytearray | memoryview[int] | memoryview[bytes]
    ) -> None:
        if self._write_eof_sent:
            raise RuntimeError("Cannot write after write_eof()")
        await self._writer.write(data)

    async def drain(self) -> None:
        await self._writer.drain()

    async def write_eof(self) -> None:
        if self._write_eof_sent:
            return
        transport = self._writer.transport
        if transport is None or transport.is_closing():
            raise ClientConnectionResetError("Connection lost")
        await self._writer.drain()
        try:
            transport.write_eof()
        except (AttributeError, NotImplementedError, RuntimeError) as exc:
            raise RuntimeError("Transport does not support write EOF") from exc
        self._write_eof_sent = True

    def close(self) -> None:
        transport = self._writer.transport
        if transport is not None:
            transport.close()

    async def wait_closed(self) -> None:
        await self._reader.wait_eof()

    async def __aenter__(self) -> "TunnelConnection":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class TunnelResponse(StreamResponse):
    """Successful HTTP/1.1 CONNECT response which owns the tunnel."""

    _tunnel_response = True
    _tunnel_accepted = False

    def __init__(
        self,
        *,
        status: int = 200,
        reason: str | None = None,
        headers: LooseHeaders | None = None,
    ) -> None:
        super().__init__(status=status, reason=reason, headers=headers)
        self.force_close()
        self._tunnel: TunnelConnection | None = None

    @property
    def tunnel(self) -> TunnelConnection | None:
        return self._tunnel

    async def prepare(self, request: "BaseRequest") -> TunnelConnection:
        if self._eof_sent:
            if self._tunnel is None:
                raise RuntimeError("Tunnel response has already finished")
            return self._tunnel
        if self._tunnel is not None:
            return self._tunnel
        if request.method != hdrs.METH_CONNECT:
            raise RuntimeError("TunnelResponse can only answer CONNECT requests")
        if request.version != HttpVersion11:
            raise RuntimeError("CONNECT tunnels require HTTP/1.1")
        if not 200 <= self.status < 300:
            raise RuntimeError("A CONNECT tunnel requires a 2xx status code")

        await super().prepare(request)
        writer = request._payload_writer
        assert writer is not None
        reader = request.protocol.start_tunnel()
        request._payload = reader
        self._tunnel_accepted = True
        self._tunnel = TunnelConnection(reader, writer)
        return self._tunnel
