from __future__ import annotations

import math
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from litestar.datastructures import MutableScopeHeaders
from litestar.enums import ScopeType
from litestar.exceptions import HTTPException
from litestar.exceptions.http_exceptions import RequestEntityTooLarge
from litestar.middleware.base import AbstractMiddleware
from litestar.status_codes import HTTP_400_BAD_REQUEST, HTTP_415_UNSUPPORTED_MEDIA_TYPE
from litestar.types import Empty
from litestar.utils.scope.state import ScopeState

__all__ = (
    "REQUEST_DECOMPRESSION_SCOPE_KEY",
    "GzipDecompressionError",
    "RequestDecompressionInfo",
    "RequestDecompressionMiddleware",
    "UnsupportedContentEncodingException",
)


if TYPE_CHECKING:
    from collections.abc import Iterable

    from litestar.types import ASGIApp, Receive, Scope, Send


REQUEST_DECOMPRESSION_SCOPE_KEY: Final = "litestar.request_decompression"
GZIP_MAGIC: Final = b"\x1f\x8b"
DECOMPRESSED_CHUNK_SIZE: Final = 64 * 1024


class UnsupportedContentEncodingException(HTTPException):
    """The request used a content encoding unsupported by the middleware."""

    status_code = HTTP_415_UNSUPPORTED_MEDIA_TYPE
    detail = "Unsupported Content-Encoding"


class GzipDecompressionError(HTTPException):
    """The request contained an invalid gzip payload."""

    status_code = HTTP_400_BAD_REQUEST


@dataclass(slots=True)
class RequestDecompressionInfo:
    """Information about a request decoded by ``RequestDecompressionMiddleware``."""

    content_encoding: str | None
    compressed_content_length: int | None
    compressed_bytes_received: int = 0
    decompressed_content_length: int | None = None


class _GzipDecoder:
    __slots__ = ("_awaiting_member", "_buffer", "_decompressor", "info")

    def __init__(self, info: RequestDecompressionInfo) -> None:
        self._decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._buffer = b""
        self._awaiting_member = False
        self.info = info

    @property
    def has_pending_input(self) -> bool:
        return bool(self._buffer)

    @property
    def awaits_more_input(self) -> bool:
        return self._awaiting_member and len(self._buffer) < 2

    def feed(self, data: bytes, max_length: int) -> bytes:
        self.info.compressed_bytes_received += len(data)
        data = self._buffer + data
        self._buffer = b""
        decompressed = bytearray()

        while data and len(decompressed) < max_length:
            if self._awaiting_member:
                if len(data) < 2:
                    self._buffer = data
                    break
                if data[:2] != GZIP_MAGIC:
                    raise GzipDecompressionError(
                        "Trailing data after gzip stream",
                        status_code=HTTP_400_BAD_REQUEST,
                    )
                self._decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                self._awaiting_member = False

            try:
                chunk = self._decompressor.decompress(
                    data, max_length - len(decompressed)
                )
            except zlib.error as exc:
                raise GzipDecompressionError(
                    self._error_message(exc), status_code=HTTP_400_BAD_REQUEST
                ) from exc
            decompressed.extend(chunk)

            if self._decompressor.unconsumed_tail:
                self._buffer = self._decompressor.unconsumed_tail
                data = b""
                break

            data = self._decompressor.unused_data
            if not self._decompressor.eof:
                data = b""
                continue

            self._awaiting_member = True
            if not data:
                break
        else:
            if data:
                self._buffer = data

        self.info.decompressed_content_length = (
            self.info.decompressed_content_length or 0
        ) + len(decompressed)

        return bytes(decompressed)

    def finish(self) -> None:
        if self._buffer:
            if self._awaiting_member and self._buffer[:2] == GZIP_MAGIC:
                raise GzipDecompressionError(
                    "gzip stream ended prematurely",
                    status_code=HTTP_400_BAD_REQUEST,
                )
            raise GzipDecompressionError(
                "Trailing data after gzip stream",
                status_code=HTTP_400_BAD_REQUEST,
            )
        if not self._awaiting_member:
            raise GzipDecompressionError(
                "gzip stream ended prematurely",
                status_code=HTTP_400_BAD_REQUEST,
            )

    @staticmethod
    def _error_message(exc: zlib.error) -> str:
        message = str(exc)
        if "incorrect data check" in message:
            return "gzip stream has an incorrect data checksum"
        if "incorrect length check" in message:
            return "gzip stream has an incorrect length checksum"
        if "header check" in message:
            return "gzip stream has an invalid header"
        return "gzip stream is invalid"


class RequestDecompressionMiddleware(AbstractMiddleware):
    """Decompress request bodies before they are passed to the next ASGI application."""

    def __init__(
        self,
        app: ASGIApp,
        exclude: str | Iterable[str] | None = None,
        exclude_opt_key: str | None = None,
    ) -> None:
        super().__init__(
            app=app,
            exclude=exclude,
            exclude_opt_key=exclude_opt_key,
            scopes={ScopeType.HTTP},
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = MutableScopeHeaders(scope=scope)
        content_encoding_header = headers.get("content-encoding")
        if content_encoding_header is None:
            await self.app(scope, receive, send)
            return

        content_encoding = content_encoding_header.strip().lower()
        if content_encoding not in {"gzip", "identity"}:
            raise UnsupportedContentEncodingException(
                f"Unsupported Content-Encoding: {content_encoding_header!r}",
                status_code=HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )

        original_content_length = self._parse_content_length(
            headers.get("content-length")
        )
        info = RequestDecompressionInfo(
            content_encoding=content_encoding,
            compressed_content_length=original_content_length,
        )
        scope.setdefault("state", {})[REQUEST_DECOMPRESSION_SCOPE_KEY] = info
        ScopeState.from_scope(scope).headers = Empty

        del headers["content-encoding"]
        if content_encoding == "gzip":
            del headers["content-length"]
            max_body_size = scope["route_handler"].request_max_body_size or math.inf
            decoder = _GzipDecoder(info)
            receive = self._create_gzip_receive(receive, decoder, max_body_size)
        else:
            max_body_size = scope["route_handler"].request_max_body_size or math.inf
            receive = self._create_identity_receive(receive, info, max_body_size)

        await self.app(scope, receive, send)

    @staticmethod
    def _parse_content_length(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            content_length = int(value)
        except ValueError as exc:
            raise GzipDecompressionError(
                f"Invalid content-length: {value!r}", status_code=HTTP_400_BAD_REQUEST
            ) from exc
        if content_length < 0:
            raise GzipDecompressionError(
                f"Invalid content-length: {value!r}", status_code=HTTP_400_BAD_REQUEST
            )
        return content_length

    @staticmethod
    def _create_gzip_receive(
        receive: Receive, decoder: _GzipDecoder, max_body_size: float
    ) -> Receive:
        buffer = b""
        finished = False

        async def receive_wrapper():
            nonlocal buffer, finished

            if finished:
                return {"type": "http.request", "body": b"", "more_body": False}

            while True:
                if decoder.has_pending_input and not decoder.awaits_more_input:
                    event = {"type": "http.request", "body": b"", "more_body": True}
                else:
                    event = await receive()
                if event["type"] == "http.disconnect":
                    return event

                compressed = event.get("body", b"")
                decompressed_total = decoder.info.decompressed_content_length or 0
                max_output = DECOMPRESSED_CHUNK_SIZE
                if math.isfinite(max_body_size):
                    max_output = min(
                        max_output,
                        int(max_body_size) - decompressed_total + 1,
                    )
                    if decompressed_total >= max_body_size and (
                        decoder.has_pending_input or event.get("more_body", False)
                    ):
                        raise RequestEntityTooLarge

                buffer += decoder.feed(compressed, max_output)
                decompressed_total = decoder.info.decompressed_content_length or 0
                if math.isfinite(max_body_size) and decompressed_total > max_body_size:
                    raise RequestEntityTooLarge

                if not event.get("more_body", False):
                    decoder.finish()
                    finished = True
                    return {"type": "http.request", "body": buffer, "more_body": False}

                if buffer:
                    body = buffer
                    buffer = b""
                    return {"type": "http.request", "body": body, "more_body": True}

        return receive_wrapper

    @staticmethod
    def _create_identity_receive(
        receive: Receive, info: RequestDecompressionInfo, max_body_size: float
    ) -> Receive:
        async def receive_wrapper():
            event = await receive()
            if event["type"] == "http.request":
                body = event.get("body", b"")
                info.compressed_bytes_received += len(body)
                info.decompressed_content_length = (
                    info.decompressed_content_length or 0
                ) + len(body)
                if (info.decompressed_content_length or 0) > max_body_size:
                    raise RequestEntityTooLarge
            return event

        return receive_wrapper
