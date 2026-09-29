"""Streaming, layer-by-layer traversal of multipart request bodies.

Unlike sanic.request.form.parse_multipart_form, which parses a fully
buffered body, this module consumes the request body incrementally from
an async byte stream. It supports nested multipart containers (for
example multipart/mixed parts inside multipart/form-data) that can be
descended into one layer at a time, without ever buffering a whole part
in memory unless explicitly asked to.
"""

from __future__ import annotations

from typing import AsyncIterable, AsyncIterator, Optional

from sanic.exceptions import BadRequest
from sanic.headers import parse_content_header
from sanic.log import logger

from .form import parse_content_disposition_filename


DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_HEADER_SIZE = 8192

_HEADER_END = b"\r\n\r\n"
_TRANSPORT_PADDING = (b" ", b"\t")


class MultipartError(BadRequest):
    """Raised when a streaming multipart body cannot be parsed."""


class _ChunkSource:
    """Shared pull-based byte source over the request body stream.

    All readers of one traversal share a single instance, so nested
    containers read from the exact stream position where the parent
    part left off.
    """

    __slots__ = ("buffer", "closed", "eof", "_iterator")

    def __init__(self, stream: AsyncIterable[bytes]):
        self.buffer = bytearray()
        self.closed = False
        self.eof = False
        self._iterator = stream.__aiter__()

    async def fill(self, size: int) -> None:
        """Pull chunks until the buffer holds size bytes or input ends."""
        while len(self.buffer) < size and not self.eof and not self.closed:
            try:
                chunk = await self._iterator.__anext__()
            except StopAsyncIteration:
                self.eof = True
            else:
                if chunk:
                    self.buffer += chunk


class MultipartReader:
    """Streaming traversal of one layer of a multipart body.

    Parts are produced in order via next_part() or async iteration.
    Advancing to the next part automatically drains (skips) whatever
    remains of the current one. A part whose content type is another
    multipart media type may be opened as a nested reader with
    MultipartPart.open().
    """

    def __init__(
        self,
        stream: Optional[AsyncIterable[bytes]],
        boundary: bytes | str,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_header_size: int = DEFAULT_MAX_HEADER_SIZE,
        _source: Optional[_ChunkSource] = None,
        _depth: int = 0,
        _prefix: str = "",
        _path: tuple = (),
    ):
        if isinstance(boundary, str):
            boundary = boundary.encode("utf-8")
        if not boundary:
            raise MultipartError("Empty multipart boundary")
        self.boundary = boundary
        self.max_depth = max_depth
        self.max_header_size = max_header_size
        self._source = (
            _source if _source is not None else _ChunkSource(stream)  # type: ignore
        )
        self._depth = _depth
        self._prefix = _prefix
        self._path = _path
        self._delimiter = b"--" + boundary
        self._body_delimiter = b"\r\n--" + boundary
        self._started = False
        self._finished = False
        self._part_index = 0
        self._name_counts: dict[str, int] = {}
        self._current: Optional[MultipartPart] = None

    @classmethod
    def from_bytes(
        cls, body: bytes, boundary: bytes | str, **kwargs
    ) -> "MultipartReader":
        """Create a reader over an already buffered body."""

        async def source() -> AsyncIterator[bytes]:
            yield body

        return cls(source(), boundary, **kwargs)

    async def __aenter__(self) -> "MultipartReader":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def __aiter__(self) -> AsyncIterator["MultipartPart"]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator["MultipartPart"]:
        while True:
            part = await self.next_part()
            if part is None:
                return
            yield part

    async def close(self) -> None:
        """Stop the whole traversal.

        No further bytes are consumed from the request body; all readers
        sharing this traversal (including nested ones) stop producing
        parts.
        """
        self._finished = True
        self._source.closed = True

    async def next_part(self) -> Optional["MultipartPart"]:
        """Return the next part, or None when the container is exhausted.

        Any unread remainder of the previous part is drained first.
        """
        if self._finished or self._source.closed:
            return None
        if self._current is not None:
            await self._current.skip()
            self._current = None
        if self._finished or self._source.closed:
            return None
        if not self._started:
            self._started = True
            if not await self._consume_preamble():
                self._finished = True
                return None
        header_lines = await self._read_headers()
        if header_lines is None:
            self._finished = True
            return None
        part = self._make_part(header_lines)
        self._current = part
        return part

    async def _drain(self) -> None:
        """Consume all remaining parts (used when a parent part holding
        an active nested reader is skipped)."""
        while not self._finished and not self._source.closed:
            part = await self.next_part()
            if part is None:
                break
            await part.skip()

    async def _consume_preamble(self) -> bool:
        """Advance past everything up to and including the first
        delimiter line. Returns False if there are no parts."""
        delim = self._delimiter
        buf = self._source.buffer
        while True:
            idx = buf.find(delim)
            if idx == -1:
                if self._source.eof or self._source.closed:
                    return False
                keep = len(delim) + 2
                if len(buf) > keep:
                    del buf[: len(buf) - keep]
                await self._source.fill(len(buf) + 1)
                continue
            if idx > 0 and bytes(buf[idx - 2 : idx]) != b"\r\n":
                # Not at a line start; keep scanning.
                del buf[: idx + 1]
                continue
            match = await self._match_suffix(idx + len(delim))
            if match is None:
                del buf[: idx + 1]
                continue
            kind, end = match
            del buf[:end]
            return kind == "part"

    async def _match_suffix(self, pos: int) -> Optional[tuple[str, int]]:
        """Inspect the bytes following a boundary match at pos.

        Returns ("part" | "final", end) where end is the buffer index
        just after the delimiter line, or None if the match is not a
        real delimiter (for example a longer, similar boundary of a
        nested container).
        """
        buf = self._source.buffer
        i = pos
        kind = "part"
        while True:
            await self._source.fill(i + 1)
            if i >= len(buf):
                # The stream ends right after the boundary; tolerate a
                # missing trailing CRLF on the closing delimiter.
                return ("final", i)
            byte = bytes(buf[i : i + 1])
            if kind == "part" and byte == b"-":
                await self._source.fill(i + 2)
                if bytes(buf[i : i + 2]) == b"--":
                    kind = "final"
                    i += 2
                    continue
                return None
            if byte in _TRANSPORT_PADDING:
                i += 1
                continue
            if byte == b"\r":
                await self._source.fill(i + 2)
                if bytes(buf[i : i + 2]) == b"\r\n":
                    if kind == "final":
                        # The CRLF closing a container also serves as
                        # the leading CRLF of the parent container's
                        # next delimiter line; leave it in the buffer
                        # so the parent reader can still match it.
                        return (kind, i)
                    return (kind, i + 2)
                return None
            return None

    async def _read_headers(self) -> Optional[list[tuple[str, str]]]:
        """Read one part's header block, split across chunks as needed."""
        buf = self._source.buffer
        await self._source.fill(2)
        if bytes(buf[:2]) == b"\r\n":
            # Part with no headers at all.
            del buf[:2]
            return []
        while True:
            idx = buf.find(_HEADER_END)
            if idx != -1:
                if idx > self.max_header_size:
                    raise MultipartError(
                        "Multipart part headers exceed the "
                        f"{self.max_header_size} byte limit"
                    )
                raw = bytes(buf[:idx])
                del buf[: idx + 4]
                break
            if len(buf) > self.max_header_size:
                raise MultipartError(
                    "Multipart part headers exceed the "
                    f"{self.max_header_size} byte limit"
                )
            if self._source.eof or self._source.closed:
                raise MultipartError(
                    "Multipart stream ended inside part headers"
                )
            await self._source.fill(len(buf) + 1)
        headers = []
        for line in raw.split(b"\r\n"):
            if not line:
                continue
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError:
                raise MultipartError("Invalid multipart header encoding")
            field, _, value = text.partition(":")
            if not field:
                raise MultipartError("Invalid multipart header line")
            headers.append((field.strip().lower(), value.strip()))
        return headers

    def _make_part(
        self, header_lines: list[tuple[str, str]]
    ) -> "MultipartPart":
        headers: dict[str, str] = {}
        name: Optional[str] = None
        filename: Optional[str] = None
        content_type = "text/plain"
        charset = "utf-8"
        boundary: Optional[str] = None
        for field, value in header_lines:
            headers[field] = value
            if field == "content-disposition":
                _, params = parse_content_header(value)
                raw_name = params.get("name")
                name = str(raw_name) if raw_name is not None else None
                filename = parse_content_disposition_filename(params)
            elif field == "content-type":
                content_type, params = parse_content_header(value)
                charset = str(params.get("charset", "utf-8"))
                raw_boundary = params.get("boundary")
                boundary = (
                    str(raw_boundary) if raw_boundary is not None else None
                )
        index = self._part_index
        self._part_index += 1
        occurrence = 0
        if name is not None:
            occurrence = self._name_counts.get(name, 0)
            self._name_counts[name] = occurrence + 1
        if self._prefix:
            suffix = name if name is not None else str(index)
            field_name = f"{self._prefix}[{suffix}]"
        else:
            field_name = name if name is not None else f"[{index}]"
        path = (*self._path, name if name is not None else index)
        if name is None:
            logger.debug(
                "Form-data field does not have a 'name' parameter "
                "in the Content-Disposition header"
            )
        return MultipartPart(
            reader=self,
            headers=headers,
            name=name,
            filename=filename,
            content_type=content_type,
            charset=charset,
            boundary=boundary,
            index=index,
            occurrence=occurrence,
            field_name=field_name,
            path=path,
        )

    async def _iter_body(self) -> AsyncIterator[bytes]:
        """Yield the current part's body chunks, consuming the trailing
        delimiter line. Sets _finished when the closing delimiter of
        this container is reached."""
        delim = self._body_delimiter
        buf = self._source.buffer
        while True:
            idx = buf.find(delim)
            if idx == -1:
                if self._source.closed:
                    return
                if self._source.eof:
                    raise MultipartError(
                        "Multipart stream ended without a closing boundary"
                    )
                keep = len(delim) + 2
                if len(buf) > keep:
                    end = len(buf) - keep
                    yield bytes(buf[:end])
                    del buf[:end]
                await self._source.fill(len(buf) + 1)
                continue
            match = await self._match_suffix(idx + len(delim))
            if match is None:
                # A similar but longer boundary (for example one used by
                # a nested container) is body content, not a delimiter.
                yield bytes(buf[: idx + 2])
                del buf[: idx + 2]
                continue
            kind, stop = match
            if idx:
                yield bytes(buf[:idx])
            del buf[:stop]
            if kind == "final":
                self._finished = True
            return


class MultipartPart:
    """One part of a multipart container.

    Attributes:
        headers (dict[str, str]): The part's headers, lowercased names.
        name (str | None): The raw content-disposition name, if any.
        filename (str | None): The normalized filename, if any.
        content_type (str): The part's content type.
        charset (str): Charset parameter of the content type.
        index (int): Position among the siblings of this container.
        occurrence (int): Position among same-named siblings.
        field_name (str): Hierarchical field name, inheriting ancestor
            names (for example "attachments[2]").
        path (tuple): Hierarchical path of names/indexes from the root.
    """

    def __init__(
        self,
        *,
        reader: MultipartReader,
        headers: dict[str, str],
        name: Optional[str],
        filename: Optional[str],
        content_type: str,
        charset: str,
        boundary: Optional[str],
        index: int,
        occurrence: int,
        field_name: str,
        path: tuple,
    ):
        self._reader = reader
        self.headers = headers
        self.name = name
        self.filename = filename
        self.content_type = content_type
        self.charset = charset
        self.index = index
        self.occurrence = occurrence
        self.field_name = field_name
        self.path = path
        self._boundary = boundary
        self._child: Optional[MultipartReader] = None
        self._consumed = False
        self._body_done = False

    def __repr__(self) -> str:
        return (
            f"MultipartPart(field_name={self.field_name!r}, "
            f"filename={self.filename!r}, "
            f"content_type={self.content_type!r})"
        )

    @property
    def is_multipart(self) -> bool:
        """Whether this part is itself a multipart container."""
        return (
            self.content_type.startswith("multipart/")
            and self._boundary is not None
        )

    def open(self) -> MultipartReader:
        """Descend into this nested multipart container.

        The returned reader shares the underlying stream; the parent
        reader must not be advanced until the nested one is exhausted
        (advancing it drains the nested container automatically).
        """
        if not self.is_multipart:
            raise MultipartError(
                f"Part {self.field_name!r} is not a multipart container"
            )
        if self._consumed:
            raise MultipartError("Part body has already been consumed")
        depth = self._reader._depth + 1
        if depth > self._reader.max_depth:
            raise MultipartError(
                "Multipart nesting exceeds the maximum depth of "
                f"{self._reader.max_depth}"
            )
        self._consumed = True
        child = MultipartReader(
            None,
            self._boundary or "",
            max_depth=self._reader.max_depth,
            max_header_size=self._reader.max_header_size,
            _source=self._reader._source,
            _depth=depth,
            _prefix=self.field_name,
            _path=self.path,
        )
        self._child = child
        return child

    async def iter_chunks(self) -> AsyncIterator[bytes]:
        """Stream the part body chunk by chunk without buffering it."""
        if self._child is not None:
            raise MultipartError(
                "Part was opened as a nested multipart container; "
                "iterate its sub-parts instead"
            )
        if self._consumed:
            raise MultipartError("Part body has already been consumed")
        if self._reader._current is not self:
            raise MultipartError(
                "Part is no longer the active part of its reader"
            )
        self._consumed = True
        async for chunk in self._reader._iter_body():
            yield chunk
        self._body_done = True

    async def read(self) -> bytes:
        """Buffer and return the whole part body (small parts only)."""
        return b"".join([chunk async for chunk in self.iter_chunks()])

    async def text(self) -> str:
        """Buffer and decode the whole part body (small parts only)."""
        return (await self.read()).decode(self.charset)

    async def skip(self) -> None:
        """Drain any unread bytes of this part only.

        The reader is left positioned at the next part (or the end of
        the container); the rest of the request is left untouched.
        """
        if self._body_done:
            return
        self._consumed = True
        if self._child is not None:
            await self._child._drain()
        if self._body_done or self._reader._source.closed:
            return
        async for _ in self._reader._iter_body():
            pass
        self._body_done = True
