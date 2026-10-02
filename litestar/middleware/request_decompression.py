from __future__ import annotations

import zlib
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from litestar.enums import ScopeType
from litestar.exceptions import ClientException
from litestar.exceptions.http_exceptions import RequestEntityTooLarge
from litestar.middleware.base import ASGIMiddleware
from litestar.status_codes import HTTP_415_UNSUPPORTED_MEDIA_TYPE
from litestar.types import Empty
from litestar.utils.scope.state import ScopeState

if TYPE_CHECKING:
    from litestar.types import ASGIApp, Receive, Scope, Send
    from litestar.types.asgi_types import ReceiveMessage

__all__ = ("RequestDecompressionMiddleware", "RequestDecompressionState")

# 16 + MAX_WBITS configures zlib to expect a gzip header and to validate the
# CRC32 checksum and size stored in the gzip trailer
GZIP_WBITS: int = zlib.MAX_WBITS | 16

SUPPORTED_CONTENT_ENCODINGS: tuple[str, str] = ("gzip", "identity")


@dataclass
class RequestDecompressionState:
    """Per-request state tracked by :class:`RequestDecompressionMiddleware`.

    An instance of this class is available on
    :attr:`Request.decompression_state <litestar.connection.Request.decompression_state>`
    for requests that carried a supported ``Content-Encoding`` header.
    """

    content_encoding: str
    """The value of the request's original ``Content-Encoding`` header."""
    compressed_content_length: int | None
    """The value of the request's original ``Content-Length`` header, i.e. the size of the
    compressed (wire-format) body, if the header was present.
    """
    compressed_bytes_received: int = 0
    """Number of compressed body bytes received so far."""
    decompressed_bytes_emitted: int = 0
    """Number of decompressed body bytes produced so far."""


class RequestDecompressionMiddleware(ASGIMiddleware):
    """Transparently decompress request bodies sent with a ``Content-Encoding`` header.

    Currently, the ``gzip`` and ``identity`` content encodings are supported. Requests
    carrying any other content encoding are rejected with a ``415 Unsupported Media Type``
    response.

    Downstream consumers (route handlers, other middleware) read the request body as usual
    via :meth:`Request.body <litestar.connection.Request.body>`,
    :meth:`Request.form <litestar.connection.Request.form>`,
    :meth:`Request.stream <litestar.connection.Request.stream>` etc. and receive the
    decompressed bytes. The original ``Content-Encoding`` and ``Content-Length`` headers
    are removed from the scope, since they describe the compressed representation and
    would otherwise mislead downstream consumers. Information about the compressed and
    decompressed representations is exposed via
    :attr:`Request.decompression_state <litestar.connection.Request.decompression_state>`.

    Body size limits are enforced on the *decompressed* size: both the route handler's
    ``request_max_body_size`` and the middleware's own ``max_decompressed_size`` are
    applied to the decompressed byte stream, so a small compressed payload cannot be used
    to bypass request size limits ("decompression bomb").

    Decompression happens lazily: request body bytes are only pulled from the client when
    the application asks for them. If the application stops reading the body, or the
    client disconnects, no further bytes are consumed and no resources are retained.

    Malformed payloads are rejected with a ``400 Bad Request`` response. This includes
    truncated gzip streams, checksum mismatches and trailing garbage after the end of the
    gzip stream.

    .. code-block:: python

        from litestar import Litestar
        from litestar.middleware.request_decompression import RequestDecompressionMiddleware

        app = Litestar(
            route_handlers=[...],
            middleware=[RequestDecompressionMiddleware(max_decompressed_size=10_000_000)],
        )
    """

    scopes = (ScopeType.HTTP,)

    def __init__(self, max_decompressed_size: int | None = None) -> None:
        """Initialize ``RequestDecompressionMiddleware``.

        Args:
            max_decompressed_size: Maximum allowed size of the *decompressed* request body
                in bytes. If the decompressed body exceeds this size, the request is
                rejected with a ``413 Request Entity Too Large`` response. If the route
                handler's ``request_max_body_size`` is set, the lower of the two limits
                applies. :obj:`None` disables the middleware-level limit.
        """
        self.max_decompressed_size = max_decompressed_size

    async def handle(self, scope: Scope, receive: Receive, send: Send, next_app: ASGIApp) -> None:
        """Handle an ASGI call, wrapping ``receive`` to decompress the request body.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive function.
            send: The ASGI send function.
            next_app: The next ASGI application in the middleware stack to call.

        Raises:
            ClientException: If the request carries an unsupported ``Content-Encoding``.
        """
        # read the headers directly from the scope instead of via 'Headers.from_scope':
        # the scope headers are mutated below, and 'Headers.from_scope' would cache the
        # original headers in the connection state
        raw_headers = dict(scope["headers"])
        content_encoding_bytes = raw_headers.get(b"content-encoding")
        content_encoding = content_encoding_bytes.decode("latin-1") if content_encoding_bytes is not None else None

        if content_encoding is None or content_encoding.strip().lower() == "identity":
            await next_app(scope, receive, send)
            return

        if content_encoding.strip().lower() != "gzip":
            raise ClientException(
                status_code=HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=(
                    f"Unsupported request content encoding {content_encoding!r}. "
                    f"Supported encodings: {', '.join(SUPPORTED_CONTENT_ENCODINGS)}"
                ),
            )

        compressed_content_length: int | None = None
        if (raw_content_length_bytes := raw_headers.get(b"content-length")) is not None:
            # on failure, leave 'compressed_content_length' as 'None'; validation of the
            # content-length header is left to the ASGI server
            with suppress(ValueError):
                compressed_content_length = int(raw_content_length_bytes)

        state = RequestDecompressionState(
            content_encoding=content_encoding,
            compressed_content_length=compressed_content_length,
        )
        connection_state = ScopeState.from_scope(scope)
        connection_state.request_decompression = state

        # the original headers describe the compressed representation; remove them so
        # downstream consumers are not misled into decompressing the body again or
        # trusting a length that refers to the compressed bytes
        scope["headers"] = [
            (name, value) for name, value in scope["headers"] if name not in (b"content-encoding", b"content-length")
        ]
        # invalidate any headers cached in the connection state before the mutation
        connection_state.headers = Empty

        await next_app(scope, self._create_decompressing_receive(receive=receive, scope=scope, state=state), send)

    def _create_decompressing_receive(
        self, receive: Receive, scope: Scope, state: RequestDecompressionState
    ) -> Receive:
        """Create a ``receive`` wrapper that lazily decompresses the request body.

        Args:
            receive: The ASGI receive function to wrap.
            scope: The ASGI connection scope.
            state: The decompression state for the current request.

        Returns:
            An ASGI receive function.
        """
        max_decompressed_size = self._resolve_max_decompressed_size(scope)
        decompressor = zlib.decompressobj(GZIP_WBITS)

        async def receive_wrapper() -> ReceiveMessage:
            message = await receive()

            # pass through non-body events (e.g. 'http.disconnect') untouched so
            # downstream consumers can react to them as usual
            if message["type"] != "http.request":
                return message

            body = message.get("body", b"")
            more_body = message.get("more_body", False)
            state.compressed_bytes_received += len(body)

            if decompressor.eof:
                if body:
                    raise ClientException(detail="Trailing data after end of gzip-encoded request body")
                decompressed = b""
            else:
                decompressed = self._decompress(
                    decompressor=decompressor,
                    data=body,
                    state=state,
                    max_decompressed_size=max_decompressed_size,
                )
                if decompressor.unused_data:
                    raise ClientException(detail="Trailing data after end of gzip-encoded request body")

            if not more_body:
                decompressed += self._finalize(
                    decompressor=decompressor,
                    state=state,
                    max_decompressed_size=max_decompressed_size,
                )

            request_event: ReceiveMessage = {"type": "http.request", "body": decompressed, "more_body": more_body}
            return request_event

        return receive_wrapper

    def _resolve_max_decompressed_size(self, scope: Scope) -> int | None:
        """Resolve the effective decompressed size limit for the current request.

        The limit is the lower of the middleware's ``max_decompressed_size`` and the
        route handler's ``request_max_body_size``, if both are set.

        Args:
            scope: The ASGI connection scope.

        Returns:
            The effective limit in bytes, or :obj:`None` if no limit applies.
        """
        limits = []
        if self.max_decompressed_size is not None:
            limits.append(self.max_decompressed_size)
        route_handler = scope.get("route_handler")
        handler_limit = getattr(route_handler, "request_max_body_size", None)
        if handler_limit is not None:
            limits.append(handler_limit)
        return min(limits) if limits else None

    @staticmethod
    def _decompress(
        decompressor: zlib.Decompress,
        data: bytes,
        state: RequestDecompressionState,
        max_decompressed_size: int | None,
    ) -> bytes:
        """Decompress a single chunk of compressed data, enforcing the size limit.

        When a limit applies, decompression is bounded by the remaining budget, so a
        maliciously crafted payload cannot allocate more than ``max_decompressed_size``
        bytes of decompressed data before the request is rejected.

        Args:
            decompressor: The zlib decompressor for the current request.
            data: A chunk of compressed data.
            state: The decompression state for the current request.
            max_decompressed_size: The size limit to enforce, or :obj:`None`.

        Raises:
            ClientException: If the data is not a valid gzip stream.
            RequestEntityTooLarge: If the decompressed size exceeds the limit.

        Returns:
            The decompressed bytes.
        """
        if not data:
            return b""

        if max_decompressed_size is None:
            try:
                decompressed = decompressor.decompress(data)
            except zlib.error as exc:
                raise ClientException(detail=f"Malformed gzip-encoded request body: {exc}") from exc
            state.decompressed_bytes_emitted += len(decompressed)
            return decompressed

        parts = []
        while data:
            # allow one byte past the limit so an oversized body is detected
            budget = max_decompressed_size - state.decompressed_bytes_emitted + 1
            try:
                part = decompressor.decompress(data, budget)
            except zlib.error as exc:
                raise ClientException(detail=f"Malformed gzip-encoded request body: {exc}") from exc
            parts.append(part)
            state.decompressed_bytes_emitted += len(part)
            if state.decompressed_bytes_emitted > max_decompressed_size:
                raise RequestEntityTooLarge(
                    detail=f"Decompressed request body exceeds the maximum allowed size of {max_decompressed_size} bytes"
                )
            data = decompressor.unconsumed_tail
            if data and not part:
                # guard against a pathological no-progress loop
                break
        return b"".join(parts)

    @staticmethod
    def _finalize(
        decompressor: zlib.Decompress,
        state: RequestDecompressionState,
        max_decompressed_size: int | None,
    ) -> bytes:
        """Finalize the gzip stream once the request body has been fully received.

        Args:
            decompressor: The zlib decompressor for the current request.
            state: The decompression state for the current request.
            max_decompressed_size: The size limit to enforce, or :obj:`None`.

        Raises:
            ClientException: If the gzip stream is truncated, i.e. the request body ended
                before the gzip stream was complete.
            RequestEntityTooLarge: If the decompressed size exceeds the limit.

        Returns:
            Any remaining decompressed bytes.
        """
        try:
            tail = decompressor.flush()
        except zlib.error as exc:
            raise ClientException(detail=f"Malformed gzip-encoded request body: {exc}") from exc
        state.decompressed_bytes_emitted += len(tail)
        if max_decompressed_size is not None and state.decompressed_bytes_emitted > max_decompressed_size:
            raise RequestEntityTooLarge(
                detail=f"Decompressed request body exceeds the maximum allowed size of {max_decompressed_size} bytes"
            )
        if not decompressor.eof:
            raise ClientException(detail="Truncated gzip-encoded request body")
        return tail
