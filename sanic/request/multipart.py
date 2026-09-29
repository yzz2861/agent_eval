from __future__ import annotations

from collections.abc import AsyncIterable, AsyncIterator
from typing import TYPE_CHECKING, Any

from sanic.exceptions import BadRequest
from sanic.headers import parse_content_header

from .form import decode_filename


if TYPE_CHECKING:
    from .types import Request


DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_HEADERS_SIZE = 8192
BODY_CHUNK_SIZE = 65536


async def request_body_chunks(request: Request) -> AsyncIterator[bytes]:
    """Yield the request body as an async stream of chunks.

    Uses an already loaded request.body when available, otherwise pulls
    chunks from request.stream without buffering the whole body.
    """
    if request.body:
        body = request.body
        for pos in range(0, len(body), BODY_CHUNK_SIZE):
            yield body[pos : pos + BODY_CHUNK_SIZE]
    elif request.stream is not None:
        async for data in request.stream:
            if data:
                yield data


class _ChunkSource:
    """Shared buffered view over an async iterable of body chunks."""

    def __init__(self, chunks: AsyncIterable[bytes]) -> None:
        self._chunks = chunks.__aiter__()
        self.buffer = bytearray()
        self.eof = False
        self.closed = False

    async def fill(self, need: int) -> bool:
        """Buffer at least need bytes. False means EOF or closed."""
        if self.closed:
            return False
        while len(self.buffer) < need and not self.eof:
            try:
                chunk = await self._chunks.__anext__()
            except StopAsyncIteration:
                self.eof = True
            else:
                if chunk:
                    self.buffer += chunk
        return len(self.buffer) >= need


class MultipartStream:
    """Streaming iterator over the parts of a multipart body.

    Parts are produced one at a time without buffering the whole request
    body in memory. A part whose Content-Type is itself multipart/*
    (for example multipart/mixed attachments nested inside
    multipart/form-data) is a container: call part.children() to
    descend into it and iterate its sub-parts layer by layer.

    Skipping a part without reading it only drains that part before
    moving on to the next one. Closing the stream stops consuming the
    request body entirely.
    """

    def __init__(
        self,
        chunks: AsyncIterable[bytes],
        boundary: bytes,
        *,
        max_headers_size: int = DEFAULT_MAX_HEADERS_SIZE,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> None:
        self._source = _ChunkSource(chunks)
        self._boundary = boundary
        self._max_headers_size = max_headers_size
        self._depth_left = max_depth
        self._path: tuple[str, ...] = ()
        self._is_root = True
        self._reset()

    @classmethod
    def _nested(
        cls, parent: MultipartStream, boundary: bytes, path: tuple[str, ...]
    ) -> MultipartStream:
        stream = cls.__new__(cls)
        stream._source = parent._source
        stream._boundary = boundary
        stream._max_headers_size = parent._max_headers_size
        stream._depth_left = parent._depth_left - 1
        stream._path = path
        stream._is_root = False
        stream._reset()
        return stream

    def _reset(self) -> None:
        self._delimiter = b"--" + self._boundary
        self._body_delimiter = b"\r\n--" + self._boundary
        self._state = "preamble"
        self._current_part: MultipartPart | None = None
        self._index = 0
        self._closed = False

    def __aiter__(self) -> MultipartStream:
        return self

    async def __aenter__(self) -> MultipartStream:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Stop the traversal and stop consuming the request body."""
        self._closed = True
        self._state = "done"
        self._current_part = None
        if self._is_root:
            self._source.closed = True

    async def __anext__(self) -> MultipartPart:
        if self._closed or self._state == "done":
            raise StopAsyncIteration
        if self._state == "body":
            # Drain only the remainder of the current part, then continue
            # with the next one.
            async for _ in self._chunks_until(self._body_delimiter):
                pass
        elif self._state == "preamble":
            async for _ in self._chunks_until(self._delimiter):
                pass
        if self._state != "headers":
            raise StopAsyncIteration
        part = await self._read_part()
        self._current_part = part
        self._state = "body"
        return part

    def _scan(self, delimiter: bytes) -> tuple[int, bool]:
        """Locate a validated delimiter in the buffered bytes.

        A delimiter only counts when followed by CRLF (next part) or
        a double dash (end of container), so lookalike byte sequences
        (for example a longer, similar boundary of a nested container)
        are not mistaken for it.

        Returns:
            tuple[int, bool]: The index of the delimiter and whether more
            bytes are needed to validate it. (-1, False) when absent.
        """
        buffer = self._source.buffer
        start = 0
        while True:
            index = buffer.find(delimiter, start)
            if index == -1:
                return -1, False
            end = index + len(delimiter)
            if end + 2 > len(buffer):
                return index, True
            if bytes(buffer[end : end + 2]) in (b"\r\n", b"--"):
                return index, False
            start = index + 1

    def _after_delimiter(self) -> None:
        buffer = self._source.buffer
        if bytes(buffer[:2]) == b"--":
            # Close delimiter: end of this container. The trailing CRLF
            # belongs to the parent delimiter (or the epilogue), so it
            # stays in the buffer.
            del buffer[:2]
            self._state = "done"
        else:
            del buffer[:2]
            self._state = "headers"

    async def _chunks_until(self, delimiter: bytes) -> AsyncIterator[bytes]:
        """Yield body bytes up to the next validated delimiter.

        Leaves the buffer positioned right after the delimiter line and
        updates the stream state to expect part headers or to be done.
        """
        source = self._source
        buffer = source.buffer
        keep = len(delimiter) + 2
        while True:
            index, pending = self._scan(delimiter)
            if index != -1 and not pending:
                if index:
                    chunk = bytes(buffer[:index])
                    del buffer[:index]
                    yield chunk
                del buffer[: len(delimiter)]
                self._after_delimiter()
                self._current_part = None
                return
            if index != -1:
                # A possible delimiter is split across chunks; emit what
                # precedes it and buffer more bytes to validate it.
                if index:
                    chunk = bytes(buffer[:index])
                    del buffer[:index]
                    yield chunk
                if not await source.fill(keep):
                    if buffer:
                        chunk = bytes(buffer)
                        buffer.clear()
                        yield chunk
                    self._state = "done"
                    self._current_part = None
                    return
                continue
            if len(buffer) > keep:
                chunk = bytes(buffer[:-keep])
                del buffer[:-keep]
                yield chunk
            if not await source.fill(len(buffer) + 1):
                if buffer:
                    chunk = bytes(buffer)
                    buffer.clear()
                    yield chunk
                self._state = "done"
                self._current_part = None
                return

    async def _read_part(self) -> MultipartPart:
        source = self._source
        buffer = source.buffer
        data = bytearray()
        while True:
            index = buffer.find(b"\r\n\r\n")
            if index != -1:
                data += buffer[:index]
                del buffer[: index + 4]
            else:
                # Keep back a few bytes: the terminator may be split
                # across network chunks.
                if len(buffer) > 3:
                    data += buffer[:-3]
                    del buffer[:-3]
            if len(data) > self._max_headers_size:
                raise BadRequest(
                    "Multipart part headers exceed the "
                    f"{self._max_headers_size} byte limit"
                )
            if index != -1:
                break
            if not await source.fill(len(buffer) + 1):
                raise BadRequest(
                    "Unexpected end of body inside multipart part headers"
                )

        headers: dict[str, str] = {}
        name = None
        filename = None
        content_type = "text/plain"
        content_type_params: dict[str, Any] = {}
        charset = "utf-8"
        for line in bytes(data).decode("utf-8", "replace").split("\r\n"):
            if not line or ":" not in line:
                continue
            field, _, value = line.partition(":")
            field = field.strip().lower()
            value = value.strip()
            headers[field] = value
            header_value, parameters = parse_content_header(value)
            if field == "content-disposition":
                name = parameters.get("name")
                filename = decode_filename(parameters)
            elif field == "content-type":
                content_type = header_value
                content_type_params = parameters
                charset = str(parameters.get("charset", "utf-8"))

        part = MultipartPart(
            stream=self,
            headers=headers,
            name=name,
            filename=filename,
            content_type=content_type,
            content_type_params=content_type_params,
            charset=charset,
            index=self._index,
        )
        self._index += 1
        return part


class MultipartPart:
    """A single part of a multipart body, with streaming body access.

    Attributes:
        headers (dict[str, str]): The part headers, lowercased by name.
        name (str | None): The Content-Disposition field name.
        filename (str | None): The decoded, NFC-normalized filename.
        content_type (str): The part content type.
        charset (str): The part charset, defaults to utf-8.
        index (int): Position of the part among its siblings.
        path (tuple[str, ...]): Field names from the root to this part.
    """

    def __init__(
        self,
        *,
        stream: MultipartStream,
        headers: dict[str, str],
        name: Any,
        filename: Any,
        content_type: str,
        content_type_params: dict[str, Any],
        charset: str,
        index: int,
    ) -> None:
        self._stream = stream
        self.headers = headers
        self.name = name
        self.filename = filename
        self.content_type = content_type
        self.content_type_params = content_type_params
        self.charset = charset
        self.index = index
        self.path = stream._path + ((name,) if name else ())

    def __repr__(self) -> str:
        return f"MultipartPart(name={self.name!r}, filename={self.filename!r})"

    @property
    def full_name(self) -> str:
        """Dotted path of field names from the root down to this part."""
        return ".".join(self.path)

    @property
    def is_container(self) -> bool:
        """Whether this part is itself a multipart container."""
        return self.content_type.startswith("multipart/")

    async def stream(self) -> AsyncIterator[bytes]:
        """Stream the remaining body bytes of this part."""
        reader = self._stream
        if reader._current_part is not self:
            raise BadRequest(
                f"Multipart part {self.full_name!r} is no longer readable"
            )
        async for chunk in reader._chunks_until(reader._body_delimiter):
            yield chunk

    async def read(self) -> bytes:
        """Read the remaining body of this part into memory."""
        return b"".join([chunk async for chunk in self.stream()])

    async def text(self) -> str:
        """Read the remaining body decoded with the part charset."""
        return (await self.read()).decode(self.charset)

    def children(self) -> MultipartStream:
        """Descend into a nested multipart container part."""
        if not self.is_container:
            raise BadRequest(
                f"Multipart part {self.full_name!r} is not a container"
            )
        if self._stream._current_part is not self:
            raise BadRequest(
                f"Multipart part {self.full_name!r} is no longer readable"
            )
        if self._stream._depth_left <= 0:
            raise BadRequest("Maximum multipart nesting depth exceeded")
        boundary = self.content_type_params.get("boundary")
        if not boundary:
            raise BadRequest(
                "Multipart container part is missing a boundary parameter"
            )
        return MultipartStream._nested(
            self._stream, str(boundary).encode("utf-8"), self.path
        )
