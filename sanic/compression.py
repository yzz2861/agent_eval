from __future__ import annotations

import gzip
import re
import zlib

from collections.abc import Collection
from typing import TYPE_CHECKING, Any

from sanic.exceptions import BadRequest
from sanic.headers import parse_accept, parse_content_header
from sanic.helpers import has_message_body
from sanic.http.stream import Stream
from sanic.response import HTTPResponse


if TYPE_CHECKING:
    from sanic import Request, Sanic
    from sanic.response import BaseHTTPResponse


DEFAULT_COMPRESSIBLE_MEDIA_TYPES = (
    "application/javascript",
    "application/json",
    "application/manifest+json",
    "application/wasm",
    "application/xml",
    "font/ttf",
    "image/svg+xml",
    "text/css",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
)

_CODING = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class _GzipStream(Stream):
    __slots__ = (
        "_buffer",
        "_compresslevel",
        "_compressor",
        "_finished",
        "_force",
        "_minimum_size",
        "_response",
        "_stream",
    )

    def __init__(
        self,
        response: BaseHTTPResponse,
        stream: Stream,
        *,
        minimum_size: int,
        compresslevel: int,
        force: bool,
    ) -> None:
        response.body = None
        self._response = response
        self._stream = stream
        self._minimum_size = minimum_size
        self._compresslevel = compresslevel
        self._force = force
        self._buffer = bytearray()
        self._compressor: Any = None
        self._finished = False

    async def send(
        self,
        data: Any = None,
        end_stream: bool | None = None,
    ) -> None:
        if data is None:
            payload = b""
        elif hasattr(data, "encode"):
            payload = data.encode()
        else:
            payload = data

        if data is None and end_stream is None:
            end_stream = True

        if self._finished:
            return

        if self._compressor is not None:
            if end_stream and self._finished:
                return
            if payload:
                compressed = self._compressor.compress(payload)
                compressed += self._compressor.flush(zlib.Z_SYNC_FLUSH)
            elif end_stream:
                compressed = self._compressor.flush(zlib.Z_FINISH)
                self._finished = True
            else:
                compressed = b""

            if compressed or end_stream:
                await self._stream.send(
                    compressed,
                    end_stream=bool(end_stream),
                )
            return

        self._buffer.extend(payload)
        should_start = self._force or len(self._buffer) >= self._minimum_size

        if should_start and (self._buffer or self._force):
            payload = bytes(self._buffer)
            self._buffer.clear()
            compressor = self._start_gzip()
            if payload:
                compressed = compressor.compress(payload)
                if end_stream:
                    compressed += compressor.flush(zlib.Z_FINISH)
                    self._finished = True
                else:
                    compressed += compressor.flush(zlib.Z_SYNC_FLUSH)
            elif end_stream:
                compressed = compressor.flush(zlib.Z_FINISH)
                self._finished = True
            else:
                compressed = b""
            if compressed or end_stream:
                await self._stream.send(
                    compressed,
                    end_stream=bool(end_stream),
                )
        elif end_stream:
            payload = bytes(self._buffer)
            self._buffer.clear()
            self._finished = True
            await self._stream.send(payload, end_stream=True)

    def respond(self, response: BaseHTTPResponse) -> BaseHTTPResponse:
        return self._stream.respond(response)

    def _start_gzip(self) -> Any:
        compressor = zlib.compressobj(
            self._compresslevel,
            zlib.DEFLATED,
            zlib.MAX_WBITS | 16,
        )
        self._compressor = compressor
        headers = self._response.headers
        headers["content-encoding"] = "gzip"
        headers.pop("content-length", None)
        etag = headers.get("etag")
        if etag and not etag.lstrip().startswith("W/"):
            headers["etag"] = f"W/{etag}"
        return compressor


class _PreparedBodyStream(Stream):
    __slots__ = ("_body", "_sent", "_stream")

    def __init__(self, stream: Stream, body: bytes) -> None:
        self._stream = stream
        self._body = body
        self._sent = False

    async def send(
        self,
        data: Any = None,
        end_stream: bool | None = None,
    ) -> None:
        if self._sent:
            return
        self._sent = True
        await self._stream.send(
            self._body,
            end_stream=bool(end_stream),
        )

    def respond(self, response: BaseHTTPResponse) -> BaseHTTPResponse:
        return self._stream.respond(response)


class Compression:
    """Response compression middleware using gzip from the standard library."""

    def __init__(
        self,
        app: Sanic,
        *,
        minimum_size: int = 1024,
        media_types: Collection[str] = DEFAULT_COMPRESSIBLE_MEDIA_TYPES,
        compresslevel: int = 6,
    ) -> None:
        if minimum_size < 0:
            raise ValueError("minimum_size must be greater than or equal to 0")
        if not 1 <= compresslevel <= 9:
            raise ValueError("compresslevel must be between 1 and 9")

        self.minimum_size = minimum_size
        self.compresslevel = compresslevel
        self.media_types = tuple(media_types)
        self._accepted_media_types = parse_accept(",".join(self.media_types))
        app.register_middleware(self, "response")

    async def __call__(
        self,
        request: Request,
        response: BaseHTTPResponse,
    ) -> HTTPResponse | None:
        if not self._is_eligible(response):
            return None

        encodings = self._parse_accept_encoding(
            request.headers.get("accept-encoding")
        )
        self._add_vary(response)

        media_type_allowed = self._media_type_allowed(response)
        if not media_type_allowed and response.content_type:
            media_type, _ = parse_content_header(response.content_type)
            media_type_allowed = bool(
                self._accepted_media_types.match(media_type)
            )
            if media_type_allowed:
                response.headers["content-type"] = response.content_type

        if not media_type_allowed:
            if encodings.get("identity", 0.0) <= 0:
                return self._not_acceptable()
            return None

        gzip_quality = encodings.get("gzip", 0.0)
        identity_quality = encodings.get("identity", 0.0)
        if gzip_quality <= 0 and identity_quality <= 0:
            return self._not_acceptable()

        if identity_quality > gzip_quality:
            return None

        force_gzip = gzip_quality > identity_quality
        if response.body is not None and not response._manual_stream:
            return self._compress_body(response, force=force_gzip)

        assert response.stream is not None
        stream = response.stream
        response.body = None
        response.stream = _GzipStream(
            response,
            stream,
            minimum_size=self.minimum_size,
            compresslevel=self.compresslevel,
            force=force_gzip,
        )
        return None

    def _is_eligible(self, response: BaseHTTPResponse) -> bool:
        return (
            has_message_body(response.status)
            and "content-encoding" not in response.headers
            and "content-range" not in response.headers
        )

    def _media_type_allowed(self, response: BaseHTTPResponse) -> bool:
        content_type = response.headers.get(
            "content-type",
            response.content_type or "",
        )
        if not content_type:
            return False
        media_type, _ = parse_content_header(content_type)
        return bool(self._accepted_media_types.match(media_type))

    def _compress_body(
        self,
        response: BaseHTTPResponse,
        *,
        force: bool,
    ) -> HTTPResponse | None:
        body = response.body or b""
        if not body and not force:
            return None
        if not force and len(body) < self.minimum_size:
            return None

        compressed = gzip.compress(
            body,
            compresslevel=self.compresslevel,
            mtime=0,
        )
        response.body = compressed
        if response.stream is not None:
            response.stream = _PreparedBodyStream(
                response.stream,
                compressed,
            )
            response.body = None
        headers = response.headers
        headers["content-encoding"] = "gzip"
        headers["content-length"] = str(len(compressed))
        etag = headers.get("etag")
        if etag and not etag.lstrip().startswith("W/"):
            headers["etag"] = f"W/{etag}"
        return None

    @staticmethod
    def _add_vary(response: BaseHTTPResponse) -> None:
        existing: list[str] = []
        for value in response.headers.getall("vary", []):
            existing.extend(part.strip() for part in value.split(","))

        if any(value == "*" for value in existing):
            return
        if any(value.lower() == "accept-encoding" for value in existing):
            return

        existing.append("Accept-Encoding")
        response.headers["vary"] = ", ".join(
            value for value in existing if value
        )

    @staticmethod
    def _not_acceptable() -> HTTPResponse:
        return HTTPResponse(
            b"",
            status=406,
            headers={"Vary": "Accept-Encoding"},
            content_type="text/plain; charset=utf-8",
        )

    @staticmethod
    def _parse_accept_encoding(value: str | None) -> dict[str, float]:
        if value is None:
            return {"gzip": 1.0, "identity": 1.0}
        if not value.strip():
            return {"gzip": 0.0, "identity": 0.0}

        encodings: dict[str, float] = {}
        wildcard: float | None = None
        for part in value.split(","):
            coding, _, parameters = part.partition(";")
            coding = coding.strip().lower()
            if not coding or not _CODING.fullmatch(coding):
                raise BadRequest("Invalid Accept-Encoding header")

            quality = 1.0
            for parameter in parameters.split(";"):
                parameter = parameter.strip()
                if not parameter:
                    continue
                name, separator, raw_quality = parameter.partition("=")
                if name.strip().lower() != "q" or not separator:
                    continue
                try:
                    quality = float(raw_quality)
                except ValueError as error:
                    raise BadRequest(
                        "Invalid Accept-Encoding header"
                    ) from error
                if not 0.0 <= quality <= 1.0:
                    raise BadRequest("Invalid Accept-Encoding header")

            if coding == "x-gzip":
                coding = "gzip"
            if coding == "*":
                wildcard = quality
            else:
                encodings[coding] = quality

        if wildcard is not None:
            encodings.setdefault("gzip", wildcard)
            encodings.setdefault("identity", wildcard)
        else:
            encodings.setdefault("identity", 1.0)
            encodings.setdefault("gzip", 0.0)
        return encodings
