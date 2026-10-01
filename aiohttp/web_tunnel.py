"""HTTP CONNECT tunnel support.

After a successful ``CONNECT`` response the rest of the TCP connection is
an opaque byte stream.  :class:`TunnelResponse` hands both directions of
that stream to the application without exposing the private protocol and
transport objects.
"""

import asyncio
from typing import TYPE_CHECKING, Union

from . import hdrs
from .abc import AbstractStreamWriter
from .client_exceptions import ClientConnectionResetError
from .streams import StreamReader
from .web_exceptions import HTTPBadRequest
from .web_request import BaseRequest
from .web_response import StreamResponse

if TYPE_CHECKING:
    from .base_protocol import BaseProtocol

__all__ = ("TunnelResponse",)

_Bytes = Union[bytes, bytearray, "memoryview[int]", "memoryview[bytes]"]


class _TunnelPayloadParser:
    """Feed post-CONNECT bytes straight into a :class:`StreamReader`.

    It mirrors the feed_data/feed_eof interface used by the other upgraded
    protocols so that backpressure and EOF keep flowing through the
    protocol's read machinery.
    """

    def __init__(self, reader: StreamReader) -> None:
        self._reader = reader

    def feed_data(self, data: bytes) -> tuple[bool, bytes]:
        if data:
            self._reader.feed_data(data)
        return False, b""

    def feed_eof(self) -> None:
        if not self._reader.is_eof():
            self._reader.feed_eof()


class _TunnelWriter(AbstractStreamWriter):
    """Unframed writes to the transport after the CONNECT response."""

    length = None
    chunked = False

    def __init__(self, protocol: "BaseProtocol") -> None:
        self._protocol = protocol
        self._eof = False

    @property
    def transport(self) -> asyncio.BaseTransport | None:
        return self._protocol.transport

    def enable_chunking(self) -> None:
        raise RuntimeError("CONNECT tunnels do not support chunked encoding")

    def enable_compression(
        self, encoding: str = "deflate", strategy: int | None = None
    ) -> None:
        raise RuntimeError("CONNECT tunnels do not support compression")

    async def write_headers(
        self, status_line: str, headers: "object"
    ) -> None:  # pragma: no cover - never used on a tunnel writer
        raise RuntimeError("CONNECT tunnels do not support write_headers()")

    async def write(self, chunk: _Bytes) -> None:
        if not chunk:
            return
        if self._eof:
            raise RuntimeError("Cannot write after write_eof()")
        transport = self._protocol.transport
        if transport is None or transport.is_closing():
            raise ClientConnectionResetError("Cannot write to closing transport")
        size = len(chunk)
        self.output_size += size
        transport.write(chunk)
        await self.drain()

    async def write_eof(self, chunk: bytes = b"") -> None:
        if self._eof:
            return
        if chunk:
            await self.write(chunk)
        await self.drain()
        transport = self._protocol.transport
        if transport is not None and transport.can_write_eof():
            transport.write_eof()
        self._eof = True

    async def drain(self) -> None:
        if self._protocol.transport is not None and self._protocol._paused:
            await self._protocol._drain_helper()


class TunnelResponse(StreamResponse):
    """Bidirectional byte tunnel for an accepted HTTP ``CONNECT`` request.

    Return an instance from a handler and ``await`` :meth:`prepare` after
    authorizing the request.  The response object is then the channel:
    :meth:`read` reads bytes sent by the client and :meth:`write` sends raw
    bytes back, both with flow control.  Either side may signal EOF
    independently via :meth:`write_eof`; :meth:`close` releases the
    connection.

    The response only establishes the tunnel; it never connects to or
    authorizes the authority in ``request.rel_url`` itself.
    """

    _length_check = False

    def __init__(self, *, status: int = 200, reason: str | None = None) -> None:
        if not 200 <= status < 300:
            raise ValueError("TunnelResponse status must be a 2xx success status")
        super().__init__(status=status, reason=reason)
        self._reader: StreamReader | None = None
        self._tunnel_writer: _TunnelWriter | None = None
        self._protocol: BaseProtocol | None = None
        self._closing = False

    async def prepare(self, request: BaseRequest) -> None:  # type: ignore[override]
        if self._tunnel_writer is not None:
            return
        if request.method != hdrs.METH_CONNECT:
            raise HTTPBadRequest(text="CONNECT request is required")

        # A successful CONNECT response has no HTTP body, and the connection
        # cannot serve another request once tunneled.
        self.force_close()

        protocol = request.protocol
        self._protocol = protocol
        writer = await super().prepare(request)

        reader = request.content
        self._reader = reader
        # Install the byte parser before yielding on the header drain so
        # coalesced tunnel bytes and a pending FIN cannot be lost.
        protocol.set_parser(_TunnelPayloadParser(reader), raw_stream=True)
        protocol.keep_alive(False)
        protocol.set_tunnel(self)
        await writer.drain()
        self._tunnel_writer = _TunnelWriter(protocol)

    def _require_started(self) -> tuple[StreamReader, _TunnelWriter]:
        reader = self._reader
        writer = self._tunnel_writer
        if reader is None or writer is None:
            raise RuntimeError("Call prepare() before using the tunnel")
        return reader, writer

    @property
    def closed(self) -> bool:
        return self._eof_sent or self._closing

    async def read(self, n: int = -1) -> bytes:
        """Read up to ``n`` bytes from the client side of the tunnel."""
        reader, _ = self._require_started()
        return await reader.read(n)

    async def readany(self) -> bytes:
        """Read the next available chunk from the client."""
        reader, _ = self._require_started()
        return await reader.readany()

    async def readexactly(self, n: int) -> bytes:
        """Read exactly ``n`` bytes from the client."""
        reader, _ = self._require_started()
        return await reader.readexactly(n)

    def at_eof(self) -> bool:
        """Return True when the client has half-closed and all bytes are read."""
        reader, _ = self._require_started()
        return reader.at_eof()

    def _set_exception(self, exc: BaseException) -> None:
        reader = self._reader
        if reader is not None and not reader.is_eof():
            reader.set_exception(exc)

    def is_eof(self) -> bool:
        """Return True when the client side of the tunnel sent EOF."""
        reader, _ = self._require_started()
        return reader.is_eof()

    async def wait_eof(self) -> None:
        """Wait until the client side of the tunnel signals EOF."""
        reader, _ = self._require_started()
        await reader.wait_eof()

    def __aiter__(self) -> object:
        reader, _ = self._require_started()
        return reader.iter_any()

    async def write(self, data: _Bytes) -> None:  # type: ignore[override]
        """Write raw bytes to the client, waiting for backpressure."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data argument must be byte-ish (%r)" % type(data))
        _, writer = self._require_started()
        await writer.write(data)

    async def drain(self) -> None:  # type: ignore[override]
        """Wait for all buffered tunnel data to be written."""
        _, writer = self._require_started()
        await writer.drain()

    async def write_eof(self, data: bytes = b"") -> None:  # type: ignore[override]
        """Half-close the server-to-client direction.

        The client-to-server direction stays open until the client EOFs.
        """
        if self._eof_sent:
            return
        _, writer = self._require_started()
        await writer.write_eof(data)
        self._eof_sent = True

    def close(self) -> None:
        """Abruptly close the tunneled connection."""
        self._closing = True
        if self._protocol is not None:
            self._protocol.close()

    async def wait_closed(self) -> None:
        """Wait until the peer closes the client side of the tunnel."""
        reader, _ = self._require_started()
        await reader.wait_eof()
