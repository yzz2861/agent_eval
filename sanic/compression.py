from __future__ import annotations

import zlib

from collections.abc import Collection
from typing import Any

from sanic.exceptions import InvalidHeader
from sanic.helpers import has_message_body


GZIP = "gzip"
IDENTITY = "identity"


class CompressedStream:
    __slots__ = (
        "_active",
        "_compressor",
        "_force",
        "_inner",
        "_level",
        "_minimum_size",
        "_pending",
        "_response",
        "_total",
    )

    def __init__(
        self,
        response: Any,
        inner: Any,
        *,
        level: int,
        minimum_size: int,
        force: bool,
    ) -> None:
        self._response = response
        self._inner = inner
        self._level = level
        self._minimum_size = minimum_size
        self._force = force
        self._pending = bytes(response.body or b"")
        self._total = len(self._pending)
        self._compressor: Any | None = None
        self._active = False
        response.body = b""

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def send(self, data: bytes, end_stream: bool) -> None:
        if not self._active:
            if self._total == 0 and not data and not end_stream:
                self._start()
                await self._inner.send(b"", False)
                return

            self._total += len(data)
            self._pending += data

            if self._force or self._total >= self._minimum_size:
                self._start()
                data = self._pending
                self._pending = b""
            elif end_stream:
                await self._inner.send(self._pending, True)
                return
            else:
                return

        if self._compressor is not None:
            if data:
                compressed = self._compressor.compress(data)
                compressed += self._compressor.flush(zlib.Z_SYNC_FLUSH)
                await self._inner.send(compressed, False)

            if end_stream:
                compressed = self._compressor.flush(zlib.Z_FINISH)
                await self._inner.send(compressed, True)
                self._compressor = None
        elif end_stream or data:
            await self._inner.send(data, end_stream)

    def _start(self) -> None:
        self._compressor = zlib.compressobj(
            self._level,
            zlib.DEFLATED,
            31,
        )
        self._active = True
        apply_gzip_headers(self._response)


def prepare_response_compression(
    response: Any,
    data: bytes,
    end_stream: bool,
) -> None:
    stream = response.stream
    request = getattr(stream, "request", None)
    if request is None:
        return

    config = request.app.config
    if not config.get("COMPRESS", False):
        return

    headers = response.headers
    if (
        not has_message_body(response.status)
        or response.status >= 400
        or "content-encoding" in headers
    ):
        return

    accept_encoding = (
        ",".join(request.headers.getall("accept-encoding", [])) or None
    )
    gzip_quality, identity_quality = select_encoding(accept_encoding)
    range_response = response.status == 206 or "content-range" in headers
    media_type_allowed = is_media_type_allowed(
        _response_media_type(response),
        config.get("COMPRESS_MIMETYPES", ()),
    )

    if range_response:
        if identity_quality <= 0:
            _not_acceptable()
        add_vary(headers)
        return

    if not media_type_allowed:
        if identity_quality <= 0:
            _not_acceptable()
        add_vary(headers)
        return

    if gzip_quality <= 0 and identity_quality <= 0:
        _not_acceptable()

    add_vary(headers)

    if gzip_quality <= 0:
        return

    minimum_size = max(0, int(config.get("COMPRESS_MIN_SIZE", 512)))
    level = int(config.get("COMPRESS_LEVEL", 6))
    force = identity_quality <= 0
    complete_response = end_stream and not data and response.body

    if complete_response:
        if force or len(response.body) >= minimum_size:
            response.body = gzip_compress(response.body, level)
            apply_gzip_headers(response)
            response.headers["content-length"] = len(response.body)
        return

    response.stream = CompressedStream(
        response,
        stream,
        level=level,
        minimum_size=minimum_size,
        force=force,
    )


def select_encoding(accept_encoding: str | None) -> tuple[float, float]:
    explicit: dict[str, float] = {}
    wildcard: float | None = None

    if accept_encoding is not None:
        for item in accept_encoding.split(","):
            coding, _, raw_params = item.partition(";")
            coding = coding.strip().lower()
            if not coding:
                continue

            quality = 1.0
            for param in raw_params.split(";"):
                param = param.strip()
                if not param:
                    continue
                key, separator, value = param.partition("=")
                if key.strip().lower() != "q" or not separator:
                    continue
                try:
                    quality = float(value)
                except ValueError:
                    raise InvalidHeader(
                        f"Invalid Accept-Encoding quality: {value}"
                    )
                if not 0 <= quality <= 1:
                    raise InvalidHeader(
                        f"Invalid Accept-Encoding quality: {value}"
                    )

            if coding == "*":
                wildcard = quality
            else:
                if coding == "x-gzip":
                    coding = GZIP
                explicit[coding] = quality

    gzip_quality = explicit.get(GZIP)
    if gzip_quality is None and wildcard is not None:
        gzip_quality = wildcard
    if gzip_quality is None:
        gzip_quality = 0.0

    identity_quality = explicit.get(IDENTITY)
    if identity_quality is None and wildcard is not None:
        identity_quality = wildcard
    if identity_quality is None:
        identity_quality = 1.0

    return gzip_quality, identity_quality


def is_media_type_allowed(
    media_type: str | None,
    allowed: str | Collection[str],
) -> bool:
    if not media_type:
        return False

    if isinstance(allowed, str):
        allowed_types = [item.strip().lower() for item in allowed.split(",")]
    else:
        allowed_types = [str(item).strip().lower() for item in allowed]

    media_type = media_type.split(";", 1)[0].strip().lower()
    main_type, _, subtype = media_type.partition("/")

    for allowed_type in allowed_types:
        allowed_type = allowed_type.split(";", 1)[0].strip()
        allowed_main, _, allowed_subtype = allowed_type.partition("/")
        if (allowed_main == main_type or allowed_main == "*") and (
            allowed_subtype == subtype or allowed_subtype == "*"
        ):
            return True
    return False


def gzip_compress(data: bytes, level: int) -> bytes:
    compressor = zlib.compressobj(level, zlib.DEFLATED, 31)
    return compressor.compress(data) + compressor.flush(zlib.Z_FINISH)


def apply_gzip_headers(response: Any) -> None:
    headers = response.headers
    headers["content-encoding"] = GZIP
    headers.pop("content-length", None)
    headers.pop("content-md5", None)

    etag = headers.get("etag")
    if etag and etag.startswith('"'):
        headers["etag"] = f"W/{etag}"

    add_vary(headers)


def add_vary(headers: Any) -> None:
    values: list[str] = []
    for value in headers.getall("vary", ()):
        values.extend(
            item.strip() for item in value.split(",") if item.strip()
        )

    if "*" in values:
        return
    if any(item.lower() == "accept-encoding" for item in values):
        return

    values.append("Accept-Encoding")
    headers.pop("vary", None)
    headers["vary"] = ", ".join(values)


def _response_media_type(response: Any) -> str | None:
    return (
        response.headers.get("content-type") or response.content_type or None
    )


def _not_acceptable() -> None:
    from sanic.exceptions import SanicException

    raise SanicException("Not Acceptable", status_code=406, quiet=True)
