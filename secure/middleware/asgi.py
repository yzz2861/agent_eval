from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, MutableMapping
import logging
from typing import Protocol, TypeAlias, cast

from ..secure import MULTI_OK, Secure

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ASGI typing aliases
# ---------------------------------------------------------------------------

Scope: TypeAlias = object
Message: TypeAlias = object

Receive: TypeAlias = Callable[[], Awaitable[Message]]
Send: TypeAlias = Callable[[Message], Awaitable[None]]


class ASGIApp(Protocol):
    def __call__(self, scope: Scope, receive: Receive, send: Send) -> Awaitable[None]: ...


# ``http.response.start`` stores headers as a list of (name: bytes, value: bytes).
HeaderList: TypeAlias = list[tuple[bytes, bytes]]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_header_name(name: str) -> str:
    """Normalize a header field-name for case-insensitive comparison."""
    return name.strip().lower()


def _normalize_header_name_bytes(name: bytes) -> bytes:
    """Normalize a header field-name (bytes) for case-insensitive comparison."""
    return name.strip().lower()


def _encode_header_name(name: str) -> bytes:
    """
    Encode an HTTP header field-name as ASCII bytes.

    ASGI requires header field-names to be ``bytes``. Per RFC 9110, header
    field-names are ASCII.
    """
    return name.encode("ascii")


def _encode_header_value(value: str) -> bytes:
    """
    Encode an HTTP header field-value as latin-1 bytes.

    ASGI transports header values as ``bytes``. The de-facto convention for ASGI
    servers is latin-1 encoding, matching common implementations and avoiding
    accidental Unicode transformations.
    """
    return value.encode("latin-1")


def _configured_header_items(secure: Secure) -> tuple[tuple[str, str], ...]:
    """
    Return configured header items, including intentionally repeated headers.

    ``Secure.headers`` is a single-valued mapping and raises for repeated
    configured names. In that case, fall back to the ordered item stream so
    ``multi_ok`` behavior remains available.
    """
    try:
        return tuple(secure.headers.items())
    except ValueError:
        return secure.header_items()


def _inject_headers(
    headers: Iterable[tuple[bytes, bytes]],
    configured_items: Iterable[tuple[str, str]],
    multi_ok: frozenset[bytes],
) -> HeaderList:
    """
    Merge configured security headers into an existing ASGI header list.

    Single-valued headers replace all existing occurrences. Headers listed in
    ``multi_ok`` are preserved and the configured value is appended.
    """
    out: HeaderList = list(headers)

    positions: dict[bytes, list[int]] = {}
    for i, (k, _v) in enumerate(out):
        positions.setdefault(_normalize_header_name_bytes(k), []).append(i)

    for name_str, value_str in configured_items:
        name_b = _encode_header_name(name_str)
        norm_name_b = _normalize_header_name_bytes(name_b)
        value_b = _encode_header_value(value_str)

        if norm_name_b in multi_ok:
            out.append((name_b, value_b))
            continue

        if norm_name_b in positions:
            for idx in reversed(positions[norm_name_b]):
                out.pop(idx)
            positions.pop(norm_name_b, None)

        out.append((name_b, value_b))
        positions[norm_name_b] = [len(out) - 1]

    return out


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class SecureASGIMiddleware:
    """
    Apply Secure's configured HTTP security headers to an ASGI application.

    This middleware wraps an ASGI app and injects headers by intercepting the
    ``http.response.start`` message for HTTP requests.

    Parameters
    ----------
    app:
        The ASGI application to wrap.
    secure:
        A configured :class:`~secure.Secure` instance. If omitted, uses
        :meth:`~secure.Secure.with_default_headers`.
    multi_ok:
        Header names allowed to appear multiple times in a response. For these,
        Secure's value is appended instead of overwriting. Defaults to
        :data:`secure.MULTI_OK`.

    Behavior
    --------
    - Only applies to HTTP scopes (``scope["type"] == "http"``).
    - For most headers, existing values are removed (case-insensitive) and
      Secure's value is added to avoid duplicates.
    - For headers listed in ``multi_ok``, existing values are preserved and
      Secure's value is appended.

    Notes
    -----
    This middleware is intentionally "response-object free": it does not require
    a framework's response type, so it can be used with any ASGI-compliant stack.
    """

    def __init__(
        self,
        app: object,
        *,
        secure: Secure | None = None,
        multi_ok: Iterable[str] | None = None,
    ) -> None:
        # Cast once: callers may pass function apps or callable objects.
        self.app: ASGIApp = cast("ASGIApp", app)
        self.secure = secure or Secure.with_default_headers()

        provided = MULTI_OK if multi_ok is None else multi_ok
        # Normalize once during init; comparisons during request handling are bytes-based.
        self._multi_ok: frozenset[bytes] = frozenset(
            _normalize_header_name_bytes(_encode_header_name(_normalize_header_name(name))) for name in provided
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_map = cast("MutableMapping[str, object]", scope)
        if scope_map.get("type") != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            msg = cast("MutableMapping[str, object]", message)

            if msg.get("type") == "http.response.start":
                if response_started:
                    logger.warning("Ignoring duplicate http.response.start")
                    return

                raw_headers = msg.get("headers") or []
                msg["headers"] = _inject_headers(
                    cast("Iterable[tuple[bytes, bytes]]", raw_headers),
                    _configured_header_items(self.secure),
                    self._multi_ok,
                )

                response_started = True

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            if response_started:
                raise

            logger.log(logging.ERROR, "ASGI application raised %s before http.response.start", type(exc).__name__)
            try:
                await send_wrapper(
                    {
                        "type": "http.response.start",
                        "status": 500,
                        "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                    }
                )
                await send_wrapper(
                    {
                        "type": "http.response.body",
                        "body": b"",
                        "more_body": False,
                    }
                )
            except Exception as fallback_error:
                raise exc from fallback_error

            raise
