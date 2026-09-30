from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from collections.abc import Awaitable
from collections.abc import Callable
from collections.abc import Generator
from typing import Any
from typing import Literal
from typing import NoReturn
from typing import overload

from hypercorn.typing import HTTPScope
from werkzeug.datastructures import CombinedMultiDict
from werkzeug.datastructures import Headers
from werkzeug.datastructures import iter_multi_items
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.exceptions import RequestTimeout

from ..datastructures import FileStorage
from ..formparser import FormDataParser
from ..globals import current_app
from .base import BaseRequestWebsocket
from .base import ClientDisconnectedError

SERVER_PUSH_HEADERS_TO_COPY = {
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "user-agent",
}


class Body:
    """A request body container.

    The request body can either be iterated over and consumed in parts
    (without building up memory usage) or awaited.

    .. code-block:: python

        async for data in body:
            ...
        # or simply
        complete = await body

    Note: It is not possible to iterate over the data and then await
    it.
    """

    def __init__(
        self, expected_content_length: int | None, max_content_length: int | None
    ) -> None:
        self._data: bytes | None = None
        self._complete: asyncio.Event = asyncio.Event()
        self._max_content_length = max_content_length
        self._queue = asyncio.Queue[bytes]()

        # Exceptions must be raised within application (not ASGI)
        # calls, this is achieved by having the ASGI methods set this
        # to an exception on error.
        self._must_raise: Exception | None = None
        if (
            expected_content_length is not None
            and max_content_length is not None
            and expected_content_length > max_content_length
        ):
            self._must_raise = RequestEntityTooLarge()

    def __aiter__(self) -> Body:
        return self

    async def __anext__(self) -> bytes:
        if self._must_raise is not None:
            raise self._must_raise

        if self._queue.empty() and self._complete.is_set():
            raise StopAsyncIteration()

        return await self.get()

    def __await__(self) -> Generator[Any, None, Any]:
        # Must check the _must_raise before and after waiting on the
        # completion event as it may change whilst waiting and the
        # event may not be set if there is already an issue.
        if self._must_raise is not None:
            raise self._must_raise

        if self._data is not None:
            return self._data

        yield from self._complete.wait().__await__()

        if self._must_raise is not None:
            raise self._must_raise

        data = bytearray()
        while not self._queue.empty():
            data.extend(self._queue.get_nowait())
            if (
                self._max_content_length is not None
                and len(data) > self._max_content_length
            ):
                raise RequestEntityTooLarge()
        self._data = bytes(data)
        return self._data

    async def put(self, data: bytes) -> None:
        await self._queue.put(data)

    async def get(self) -> bytes:
        try:
            return await self._queue.get()
        except asyncio.QueueShutDown:
            if self._complete.is_set():
                return b""
            else:
                raise ClientDisconnectedError() from None

    def disconnect(self) -> None:
        self._queue.shutdown()

    def set_complete(self) -> None:
        self._complete.set()
        self._queue.shutdown()

    def set_result(self, data: bytes) -> None:
        """Convenience method, mainly for testing."""
        self._queue.put_nowait(data)
        self.set_complete()

    def clear(self) -> None:
        self._data = b""


class JSONSeqError(BadRequest):
    """An error parsing a single record of a JSON text sequence.

    Attributes:
        offset: The byte offset within the request body at which the
            offending record (or data) starts. For records this is the
            offset of the leading record separator (``0x1E``).
    """

    def __init__(self, message: str, offset: int) -> None:
        super().__init__(message)
        self.offset = offset


class _JSONSeqParser:
    """Incrementally parse a JSON text sequence (RFC 7464) byte stream.

    Records are delimited by a leading record separator (``0x1E``); a
    record is emitted when the next record separator or the end of the
    stream is reached. Parsing is byte based, so UTF-8 sequences and
    JSON string escapes split across chunks are handled correctly, and
    records may themselves span multiple lines.

    The feed and finish methods return a list of events, each either a
    parsed record or a :class:`JSONSeqError`.
    """

    def __init__(
        self, loads: Callable[[str], Any], max_record_size: int | None
    ) -> None:
        self._loads = loads
        self._max_record_size = max_record_size
        self._absolute = 0  # Bytes consumed from the stream so far.
        self._record = bytearray()
        self._record_open = False
        self._record_offset = 0
        self._record_too_large = False
        self._garbage = bytearray()
        self._garbage_offset = 0

    def feed(self, data: bytes) -> list[Any]:
        """Feed a chunk, returning any parsed records and errors."""
        events: list[Any] = []
        start = 0
        while start < len(data):
            index = data.find(b"\x1e", start)
            end = len(data) if index == -1 else index
            if end > start:
                self._append(data[start:end], events)
            self._absolute += end - start
            if index == -1:
                break
            events.extend(self._close_record(final=False))
            self._record_open = True
            self._record_offset = self._absolute
            self._absolute += 1
            start = index + 1
        return events

    def finish(self) -> list[Any]:
        """Flush the final record at the end of the stream."""
        return self._close_record(final=True)

    def _append(self, data: bytes, events: list[Any]) -> None:
        if self._record_open:
            if self._record_too_large:
                return  # Discard the remainder of the poisoned record.
            self._record.extend(data)
            if (
                self._max_record_size is not None
                and len(self._record) > self._max_record_size
            ):
                self._record_too_large = True
                events.append(
                    JSONSeqError(
                        "Record exceeds the maximum size of "
                        f"{self._max_record_size} bytes",
                        self._record_offset,
                    )
                )
        else:
            if not self._garbage:
                self._garbage_offset = self._absolute
            self._garbage.extend(data)

    def _close_record(self, final: bool) -> list[Any]:
        events: list[Any] = []
        if self._garbage:
            events.append(
                JSONSeqError(
                    "Data received before the first record separator",
                    self._garbage_offset,
                )
            )
            self._garbage.clear()
        if self._record_open:
            self._record_open = False
            if not self._record_too_large:
                events.extend(self._parse_record(final))
            self._record.clear()
            self._record_too_large = False
        return events

    def _parse_record(self, final: bool) -> list[Any]:
        data = bytes(self._record).strip()
        if not data:
            return []  # Empty records are valid and ignored (RFC 7464).
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return [JSONSeqError("Record is not valid UTF-8", self._record_offset)]
        try:
            return [self._loads(text)]
        except ValueError:
            if final:
                message = "Final record is truncated or not valid JSON"
            else:
                message = "Record is not valid JSON"
            return [JSONSeqError(message, self._record_offset)]


class Request(BaseRequestWebsocket):
    """This class represents a request.

    It can be subclassed and the subclassed used in preference by
    replacing the :attr:`~quart.Quart.request_class` with your
    subclass.

    Attributes:
        body_class: The class to store the body data within.
        form_data_parser_class: Can be overridden to implement a
            different form data parsing.
    """

    body_class = Body
    form_data_parser_class = FormDataParser
    lock_class = asyncio.Lock
    _max_content_length: int | None = None
    _max_form_memory_size: int | None = None
    _max_form_parts: int | None = None

    def __init__(
        self,
        method: str,
        scheme: str,
        path: str,
        query_string: bytes,
        headers: Headers,
        root_path: str,
        http_version: str,
        scope: HTTPScope,
        *,
        max_content_length: int | None = None,
        body_timeout: int | None = None,
        send_push_promise: Callable[[str, Headers], Awaitable[None]],
    ) -> None:
        """Create a request object.

        Arguments:
            method: The HTTP verb.
            scheme: The scheme used for the request.
            path: The full unquoted path of the request.
            query_string: The raw bytes for the query string part.
            headers: The request headers.
            root_path: The root path that should be prepended to all
                routes.
            http_version: The HTTP version of the request.
            body: An awaitable future for the body data i.e.
                ``data = await body``
            max_content_length: The maximum length in bytes of the
                body (None implies no limit in Quart).
            body_timeout: The maximum time (seconds) to wait for the
                body before timing out.
            send_push_promise: An awaitable to send a push promise based
                off of this request (HTTP/2 feature).
            scope: Underlying ASGI scope dictionary.
        """
        super().__init__(
            method, scheme, path, query_string, headers, root_path, http_version, scope
        )
        self.body_timeout = body_timeout
        self.body = self.body_class(self.content_length, max_content_length)
        self._cached_json: dict[bool, Any] = {False: Ellipsis, True: Ellipsis}
        self._body_consumed = False
        self._form: MultiDict | None = None
        self._files: MultiDict | None = None
        self._parsing_lock = self.lock_class()
        self._send_push_promise = send_push_promise
        self.json_seq_errors: list[JSONSeqError] = []

    @property
    def max_content_length(self) -> int | None:
        if self._max_content_length is not None:
            return self._max_content_length

        if current_app:
            return current_app.config["MAX_CONTENT_LENGTH"]

        return None

    @max_content_length.setter
    def max_content_length(self, value: int | None) -> None:
        self._max_content_length = value

    @property
    def max_form_memory_size(self) -> int | None:
        if self._max_form_memory_size is not None:
            return self._max_form_memory_size

        if current_app:
            return current_app.config["MAX_FORM_MEMORY_SIZE"]

        return None

    @max_form_memory_size.setter
    def max_form_memory_size(self, value: int | None) -> None:
        self._max_form_memory_size = value

    @property
    def max_form_parts(self) -> int | None:
        if self._max_form_parts is not None:
            return self._max_form_parts

        if current_app:
            return current_app.config["MAX_FORM_PARTS"]

        return None

    @max_form_parts.setter
    def max_form_parts(self, value: int | None) -> None:
        self._max_form_parts = value

    @property
    async def stream(self) -> NoReturn:
        raise NotImplementedError("Use body instead")

    @property
    async def data(self) -> bytes:
        return await self.get_data(as_text=False, parse_form_data=True)  # type: ignore

    @overload
    async def get_data(
        self, cache: bool, as_text: Literal[False], parse_form_data: bool
    ) -> bytes: ...

    @overload
    async def get_data(
        self, cache: bool, as_text: Literal[True], parse_form_data: bool
    ) -> str: ...

    @overload
    async def get_data(
        self, cache: bool = True, as_text: bool = False, parse_form_data: bool = False
    ) -> str | bytes: ...

    async def get_data(
        self, cache: bool = True, as_text: bool = False, parse_form_data: bool = False
    ) -> str | bytes:
        """Get the request body data.

        Arguments:
            cache: If False the body data will be cleared, resulting in any
                subsequent calls returning an empty str | bytes and reducing
                memory usage.
            as_text: If True the data is returned as a decoded string,
                otherwise raw bytes are returned.
            parse_form_data: Parse the data as form data first, return any
                remaining data.
        """
        if parse_form_data:
            await self._load_form_data()

        try:
            raw_data = await asyncio.wait_for(self.body, timeout=self.body_timeout)
        except TimeoutError as e:
            raise RequestTimeout() from e
        else:
            self._body_consumed = True
            if not cache:
                self.body.clear()

            if as_text:
                return raw_data.decode()
            else:
                return raw_data

    @property
    async def values(self) -> CombinedMultiDict:
        sources = [self.args]
        if self.method != "GET":
            # Whilst GET requests are allowed to have a body, most
            # implementations do not allow this hence this
            # inconsistency may result in confusing values.
            form = await self.form
            sources.append(form)

        multidict_sources: list[MultiDict] = []
        for source in sources:
            if not isinstance(source, MultiDict):
                multidict_sources.append(MultiDict(source))
            else:
                multidict_sources.append(source)

        return CombinedMultiDict(multidict_sources)

    @property
    async def form(self) -> MultiDict:
        """The parsed form encoded data.

        Note file data is present in the :attr:`files`.
        """
        await self._load_form_data()
        return self._form

    @property
    async def files(self) -> MultiDict[str, FileStorage]:
        """The parsed files.

        This will return an empty multidict unless the request
        mimetype was ``enctype="multipart/form-data"`` and the method
        POST, PUT, or PATCH.
        """
        await self._load_form_data()
        return self._files

    def make_form_data_parser(self) -> FormDataParser:
        return self.form_data_parser_class(
            max_content_length=self.max_content_length,
            max_form_memory_size=self.max_form_memory_size,
            max_form_parts=self.max_form_parts,
            cls=self.parameter_storage_class,
        )

    async def _load_form_data(self) -> None:
        async with self._parsing_lock:
            if self._form is None:
                parser = self.make_form_data_parser()
                try:
                    self._form, self._files = await asyncio.wait_for(
                        parser.parse(
                            self.body,
                            self.mimetype,
                            self.content_length,
                            self.mimetype_params,
                        ),
                        timeout=self.body_timeout,
                    )
                except TimeoutError as e:
                    raise RequestTimeout() from e
                else:
                    self._body_consumed = True

    @property
    async def json(self) -> Any:
        return await self.get_json()

    async def get_json(
        self, force: bool = False, silent: bool = False, cache: bool = True
    ) -> Any:
        """Parses the body data as JSON and returns it.

        Arguments:
            force: Force JSON parsing even if the mimetype is not JSON.
            silent: Do not trigger error handling if parsing fails, without
                this the :meth:`on_json_loading_failed` will be called on
                error.
            cache: Cache the parsed JSON on this request object.
        """
        if cache and self._cached_json[silent] is not Ellipsis:
            return self._cached_json[silent]

        if not (force or self.is_json):
            return None

        data = await self.get_data(cache=cache, as_text=True)

        try:
            result = self.json_module.loads(data)
        except ValueError as error:
            if silent:
                result = None
            else:
                result = self.on_json_loading_failed(error)

        if cache:
            self._cached_json[silent] = result

        return result

    def iter_json_seq(
        self,
        *,
        max_record_size: int | None = None,
        on_error: Literal["raise", "skip"] = "raise",
    ) -> AsyncIterator[Any]:
        """Iterate over the records of a JSON text sequence body.

        Parses an ``application/json-seq`` (RFC 7464) body record by
        record as the data arrives, without loading the whole body into
        memory. Records are delimited by a record separator
        (``0x1E``) and may span multiple lines; each record is
        yielded (as parsed JSON) once the next record separator or the
        end of the body is received. Only a single record is buffered
        at a time, and no further data is read once the caller stops
        iterating.

        Empty records are ignored, as allowed by RFC 7464. A final
        record that is not valid JSON (for example because the
        connection was lost mid-record) is reported as truncated.

        Arguments:
            max_record_size: The maximum size in bytes of a single
                record, or None for no limit. Larger records are
                reported as errors.
            on_error: If ``"raise"`` (the default) the first invalid
                record raises a :class:`JSONSeqError` and ends the
                iteration. If ``"skip"`` invalid records are appended
                to :attr:`json_seq_errors` (with their byte offset) and
                iteration resumes at the next record separator.

        Raises:
            ClientDisconnectedError: If the client disconnects whilst
                iterating.
            JSONSeqError: If ``on_error="raise"`` and a record is
                invalid.
            RuntimeError: If the body has already been consumed, for
                example by :meth:`get_data` or :meth:`get_json`.

        Note: This consumes the body stream, so it must be used before
        :meth:`get_data`, :meth:`get_json` or form parsing.
        Afterwards :meth:`get_data` returns any remaining (unread)
        data, ``b""`` if the iteration completed, and
        :meth:`get_json` will fail to parse it.
        """
        if on_error not in ("raise", "skip"):
            raise ValueError("on_error must be 'raise' or 'skip'")
        if self._body_consumed:
            raise RuntimeError(
                "The request body has already been consumed, iter_json_seq() "
                "must be used before get_data(), get_json() or form parsing"
            )
        return self._iter_json_seq(max_record_size, on_error)

    async def _iter_json_seq(
        self, max_record_size: int | None, on_error: Literal["raise", "skip"]
    ) -> AsyncIterator[Any]:
        self.json_seq_errors = []
        parser = _JSONSeqParser(self.json_module.loads, max_record_size)
        async for chunk in self.body:
            for event in parser.feed(chunk):
                if isinstance(event, JSONSeqError):
                    if on_error == "raise":
                        raise event
                    self.json_seq_errors.append(event)
                else:
                    yield event
        for event in parser.finish():
            if isinstance(event, JSONSeqError):
                if on_error == "raise":
                    raise event
                self.json_seq_errors.append(event)
            else:
                yield event
        self._body_consumed = True

    def on_json_loading_failed(self, error: Exception) -> Any:
        """Handle a JSON parsing error.

        Arguments:
            error: The exception raised during parsing.
        Returns:
            Any value returned (if overridden) will be used as the
            default for any get_json calls.
        """
        if current_app and current_app.debug:
            raise BadRequest(f"Failed to decode JSON: {error}")

        raise BadRequest()

    async def send_push_promise(self, path: str) -> None:
        headers = Headers()
        for name in SERVER_PUSH_HEADERS_TO_COPY:
            for value in self.headers.getlist(name):
                headers.add(name, value)
        await self._send_push_promise(path, headers)

    async def close(self) -> None:
        for _key, value in iter_multi_items(self._files or ()):
            value.close()
