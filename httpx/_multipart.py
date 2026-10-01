from __future__ import annotations

import io
import mimetypes
import os
import re
import typing
from pathlib import Path

from ._types import (
    AsyncByteStream,
    AsyncIterable,
    FileContent,
    FileTypes,
    RequestData,
    RequestFiles,
    SyncByteStream,
)
from ._utils import (
    peek_filelike_length,
    primitive_value_to_str,
    to_bytes,
)

_HTML5_FORM_ENCODING_REPLACEMENTS = {'"': "%22", "\\": "\\\\"}
_HTML5_FORM_ENCODING_REPLACEMENTS.update(
    {chr(c): "%{:02X}".format(c) for c in range(0x1F + 1) if c != 0x1B}
)
_HTML5_FORM_ENCODING_RE = re.compile(
    r"|".join([re.escape(c) for c in _HTML5_FORM_ENCODING_REPLACEMENTS.keys()])
)


def _format_form_param(name: str, value: str) -> bytes:
    """
    Encode a name/value pair within a multipart form.
    """

    def replacer(match: typing.Match[str]) -> str:
        return _HTML5_FORM_ENCODING_REPLACEMENTS[match.group(0)]

    value = _HTML5_FORM_ENCODING_RE.sub(replacer, value)
    return f'{name}="{value}"'.encode()


def _guess_content_type(filename: str | None) -> str | None:
    """
    Guesses the mimetype based on a filename. Defaults to `application/octet-stream`.

    Returns `None` if `filename` is `None` or empty.
    """
    if filename:
        return mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return None


def get_multipart_boundary_from_content_type(
    content_type: bytes | None,
) -> bytes | None:
    if not content_type or not content_type.startswith(b"multipart/form-data"):
        return None
    # parse boundary according to
    # https://www.rfc-editor.org/rfc/rfc2046#section-5.1.1
    if b";" in content_type:
        for section in content_type.split(b";"):
            if section.strip().lower().startswith(b"boundary="):
                return section.strip()[len(b"boundary=") :].strip(b'"')
    return None


class DataField:
    """
    A single form field item, within a multipart form field.
    """

    def __init__(self, name: str, value: str | bytes | int | float | None) -> None:
        if not isinstance(name, str):
            raise TypeError(
                f"Invalid type for name. Expected str, got {type(name)}: {name!r}"
            )
        if value is not None and not isinstance(value, (str, bytes, int, float)):
            raise TypeError(
                "Invalid type for value. Expected primitive type,"
                f" got {type(value)}: {value!r}"
            )
        self.name = name
        self.value: str | bytes = (
            value if isinstance(value, bytes) else primitive_value_to_str(value)
        )

    def render_headers(self) -> bytes:
        if not hasattr(self, "_headers"):
            name = _format_form_param("name", self.name)
            self._headers = b"".join(
                [b"Content-Disposition: form-data; ", name, b"\r\n\r\n"]
            )

        return self._headers

    def render_data(self) -> bytes:
        if not hasattr(self, "_data"):
            self._data = to_bytes(self.value)

        return self._data

    def get_length(self) -> int:
        headers = self.render_headers()
        data = self.render_data()
        return len(headers) + len(data)

    def render(self) -> typing.Iterator[bytes]:
        yield self.render_headers()
        yield self.render_data()


class FileField:
    """
    A single file field item, within a multipart form field.
    """

    CHUNK_SIZE = 64 * 1024

    def __init__(self, name: str, value: FileTypes) -> None:
        self.name = name

        fileobj: FileContent

        headers: dict[str, str] = {}
        content_type: str | None = None

        # This large tuple based API largely mirror's requests' API
        # It would be good to think of better APIs for this that we could
        # include in httpx 2.0 since variable length tuples(especially of 4 elements)
        # are quite unwieldly
        if isinstance(value, tuple):
            if len(value) == 2:
                # neither the 3rd parameter (content_type) nor the 4th (headers)
                # was included
                filename, fileobj = value
            elif len(value) == 3:
                filename, fileobj, content_type = value
            else:
                # all 4 parameters included
                filename, fileobj, content_type, headers = value  # type: ignore
        else:
            filename = Path(str(getattr(value, "name", "upload"))).name
            fileobj = value

        if content_type is None:
            content_type = _guess_content_type(filename)

        has_content_type_header = any("content-type" in key.lower() for key in headers)
        if content_type is not None and not has_content_type_header:
            # note that unlike requests, we ignore the content_type provided in the 3rd
            # tuple element if it is also included in the headers requests does
            # the opposite (it overwrites the headerwith the 3rd tuple element)
            headers["Content-Type"] = content_type

        if isinstance(fileobj, io.StringIO):
            raise TypeError(
                "Multipart file uploads require 'io.BytesIO', not 'io.StringIO'."
            )
        if isinstance(fileobj, io.TextIOBase):
            raise TypeError(
                "Multipart file uploads must be opened in binary mode, not text mode."
            )

        self.filename = filename
        self.file = fileobj
        self.headers = headers
        self.is_async = self._is_async_file(fileobj)
        self._async_iterator: typing.AsyncIterator[bytes] | None = None

    def _is_async_file(self, fileobj: typing.Any) -> bool:
        return isinstance(fileobj, AsyncIterable) or hasattr(fileobj, "aread")

    def get_length(self) -> int | None:
        headers = self.render_headers()

        if isinstance(self.file, (str, bytes)):
            return len(headers) + len(to_bytes(self.file))

        if self.is_async:
            return None

        file_length = peek_filelike_length(self.file)

        # If we can't determine the filesize without reading it into memory,
        # then return `None` here, to indicate an unknown file length.
        if file_length is None:
            return None

        return len(headers) + file_length

    def render_headers(self) -> bytes:
        if not hasattr(self, "_headers"):
            parts = [
                b"Content-Disposition: form-data; ",
                _format_form_param("name", self.name),
            ]
            if self.filename:
                filename = _format_form_param("filename", self.filename)
                parts.extend([b"; ", filename])
            for header_name, header_value in self.headers.items():
                key, val = f"\r\n{header_name}: ".encode(), header_value.encode()
                parts.extend([key, val])
            parts.append(b"\r\n\r\n")
            self._headers = b"".join(parts)

        return self._headers

    def render_data(self) -> typing.Iterator[bytes]:
        if self.is_async:
            raise TypeError(
                "Multipart file uploads with async content require an AsyncClient."
            )

        if isinstance(self.file, (str, bytes)):
            yield to_bytes(self.file)
            return

        if hasattr(self.file, "seek"):
            try:
                self.file.seek(0)
            except io.UnsupportedOperation:
                pass

        chunk = self.file.read(self.CHUNK_SIZE)
        while chunk:
            yield to_bytes(chunk)
            chunk = self.file.read(self.CHUNK_SIZE)

    def render(self) -> typing.Iterator[bytes]:
        yield self.render_headers()
        yield from self.render_data()

    async def _aclose_async_render(self) -> None:
        if self._async_iterator is not None:
            iterator = self._async_iterator
            self._async_iterator = None
            aclose = getattr(iterator, "aclose", None)
            if aclose is not None:
                await aclose()
        elif not isinstance(self.file, AsyncIterable):
            aclose = getattr(self.file, "aclose", None)
            if aclose is not None:
                await aclose()

    async def arender(self) -> typing.AsyncIterator[bytes]:
        yield self.render_headers()
        if not self.is_async:
            for chunk in self.render_data():
                yield chunk
            return

        fileobj = self.file
        try:
            if hasattr(fileobj, "aread") and not isinstance(fileobj, AsyncIterable):
                chunk = await fileobj.aread(self.CHUNK_SIZE)
                while chunk:
                    yield to_bytes(chunk)
                    chunk = await fileobj.aread(self.CHUNK_SIZE)
            else:
                self._async_iterator = fileobj.__aiter__()
                try:
                    while True:
                        chunk = await self._async_iterator.__anext__()
                        yield to_bytes(chunk)
                except StopAsyncIteration:
                    self._async_iterator = None
        except BaseException:
            await self._aclose_async_render()
            raise


class BaseMultipartStream:
    """
    Request content as streaming multipart encoded form data.
    """

    def __init__(
        self,
        data: RequestData,
        files: RequestFiles,
        boundary: bytes | None = None,
    ) -> None:
        if boundary is None:
            boundary = os.urandom(16).hex().encode("ascii")

        self.boundary = boundary
        self.content_type = "multipart/form-data; boundary=%s" % boundary.decode(
            "ascii"
        )
        self.fields = list(self._iter_fields(data, files))

    @classmethod
    def _iter_fields(
        cls, data: RequestData, files: RequestFiles
    ) -> typing.Iterator[FileField | DataField]:
        for name, value in data.items():
            if isinstance(value, (tuple, list)):
                for item in value:
                    yield DataField(name=name, value=item)
            else:
                yield DataField(name=name, value=value)

        file_items = files.items() if isinstance(files, typing.Mapping) else files
        for name, value in file_items:
            yield FileField(name=name, value=value)

    def iter_chunks(self) -> typing.Iterator[bytes]:
        for field in self.fields:
            yield b"--%s\r\n" % self.boundary
            yield from field.render()
            yield b"\r\n"
        yield b"--%s--\r\n" % self.boundary

    def get_content_length(self) -> int | None:
        """
        Return the length of the multipart encoded content, or `None` if
        any of the files have a length that cannot be determined upfront.
        """
        boundary_length = len(self.boundary)
        length = 0

        for field in self.fields:
            field_length = field.get_length()
            if field_length is None:
                return None

            length += 2 + boundary_length + 2  # b"--{boundary}\r\n"
            length += field_length
            length += 2  # b"\r\n"

        length += 2 + boundary_length + 4  # b"--{boundary}--\r\n"
        return length

    # Content stream interface.

    def get_headers(self) -> dict[str, str]:
        content_length = self.get_content_length()
        content_type = self.content_type
        if content_length is None:
            return {"Transfer-Encoding": "chunked", "Content-Type": content_type}
        return {"Content-Length": str(content_length), "Content-Type": content_type}

    def _initialize_stream_state(self) -> None:
        pass


class MultipartStream(BaseMultipartStream, SyncByteStream, AsyncByteStream):
    @classmethod
    def build(
        cls,
        data: RequestData,
        files: RequestFiles,
        boundary: bytes | None = None,
    ) -> "MultipartStream | AsyncMultipartStream":
        if boundary is None:
            boundary = os.urandom(16).hex().encode("ascii")

        fields = list(cls._iter_fields(data, files))
        stream_cls = (
            AsyncMultipartStream
            if any(isinstance(field, FileField) and field.is_async for field in fields)
            else MultipartStream
        )
        stream = stream_cls.__new__(stream_cls)
        stream.boundary = boundary
        stream.content_type = "multipart/form-data; boundary=%s" % boundary.decode(
            "ascii"
        )
        stream.fields = fields
        stream._initialize_stream_state()
        return stream

    def __iter__(self) -> typing.Iterator[bytes]:
        for chunk in self.iter_chunks():
            yield chunk

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        for chunk in self.iter_chunks():
            yield chunk


class AsyncMultipartStreamIterator:
    def __init__(self, stream: AsyncMultipartStream) -> None:
        self._stream = stream
        self._iterator = stream.iter_chunks().__aiter__()

    async def __anext__(self) -> bytes:
        try:
            chunk = await self._iterator.__anext__()
        except StopAsyncIteration:
            self._stream._active_iterator = None
            raise
        self._stream._is_stream_consumed = True
        return chunk

    def __aiter__(self) -> AsyncMultipartStreamIterator:
        return self

    async def aclose(self) -> None:
        await self._iterator.aclose()


class AsyncMultipartStream(BaseMultipartStream, AsyncByteStream):
    def __init__(
        self,
        data: RequestData,
        files: RequestFiles,
        boundary: bytes | None = None,
    ) -> None:
        super().__init__(data=data, files=files, boundary=boundary)
        self._initialize_stream_state()

    def _initialize_stream_state(self) -> None:
        self._is_stream_consumed = False
        self._is_non_replayable = any(
            isinstance(field, FileField) and field.is_async for field in self.fields
        )
        self._active_field: FileField | None = None
        self._field_render: typing.AsyncIterator[bytes] | None = None
        self._active_iterator: AsyncMultipartStreamIterator | None = None

    def get_content_length(self) -> int | None:
        return MultipartStream.get_content_length(self)

    def get_headers(self) -> dict[str, str]:
        return MultipartStream.get_headers(self)

    def __aiter__(self) -> AsyncMultipartStreamIterator:
        if self._is_stream_consumed and self._is_non_replayable:
            from ._exceptions import StreamConsumed

            raise StreamConsumed()

        iterator = AsyncMultipartStreamIterator(self)
        self._active_iterator = iterator
        return iterator

    async def iter_chunks(self) -> typing.AsyncIterator[bytes]:
        try:
            for field in self.fields:
                yield b"--%s\r\n" % self.boundary
                if isinstance(field, FileField):
                    self._active_field = field
                    self._field_render = field.arender()
                    async for chunk in self._field_render:
                        yield chunk
                else:
                    yield field.render_headers()
                    yield field.render_data()
                yield b"\r\n"
            yield b"--%s--\r\n" % self.boundary
        finally:
            await self._close_active_field()

    async def _close_active_field(self) -> None:
        field_render = self._field_render
        if field_render is not None:
            await field_render.aclose()
            self._field_render = None
        if self._active_field is not None:
            field = self._active_field
            self._active_field = None
            await field._aclose_async_render()

    async def aclose(self) -> None:
        iterator = self._active_iterator
        if iterator is not None:
            self._active_iterator = None
            await iterator.aclose()
        else:
            await self._close_active_field()
