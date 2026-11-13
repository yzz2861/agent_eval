from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Protocol, TypeAlias, cast

from .._internal.cache_policy import CachePolicy
from .._internal.cache_response import (
    apply_cache_policy,
    asgi_request_headers,
    parse_status_code,
    split_secure_headers,
)
from ..headers.cache_control import CacheControl
from ..headers.vary import Vary
from ..secure import MULTI_OK, Secure

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
    cache_policy:
        Optional :class:`~secure.CachePolicy` that decides which responses are
        sensitive. When omitted, a content-type/authentication-aware default
        policy is used.
    sensitive:
        Convenience alias for ``cache_policy``. A callable is treated as a
        predicate; a boolean marks every response (or no response) sensitive.
    cache:
        Convenience override for the sensitive Cache-Control overlay.
    vary:
        Convenience override for the Vary builder merged into responses.
    **cache_options:
        Additional :class:`~secure.CachePolicy` options such as
        ``sensitive_statuses`` or ``sensitive_content_types``.

    Behavior
    --------
    - Only applies to HTTP scopes (``scope["type"] == "http"``).
    - For most headers, existing values are removed (case-insensitive) and
      Secure's value is added to avoid duplicates.
    - For headers listed in ``multi_ok``, existing values are preserved and
      Secure's value is appended.
    - ``Cache-Control`` is merged for sensitive responses so directives written
      by the application are kept.
    - Public static responses keep their existing ``Cache-Control`` value.
    - ``Vary`` is merged with existing field names rather than replaced.
    - Headers are applied in ``http.response.start``, before any body message,
      so streaming responses are covered.

    Notes
    -----
    This middleware is intentionally "response-object free": it does not require
    a framework's response type, so it can be used with any ASGI-compliant stack.
    """

    def __init__(  # noqa: PLR0913
        self,
        app: object,
        *,
        secure: Secure | None = None,
        multi_ok: Iterable[str] | None = None,
        cache_policy: CachePolicy | None = None,
        sensitive: CachePolicy | bool | object | None = None,
        cache: CacheControl | str | None = None,
        vary: Vary | str | None = None,
        **cache_options: object,
    ) -> None:
        # Cast once: callers may pass function apps or callable objects.
        self.app: ASGIApp = cast("ASGIApp", app)
        self.secure = secure or Secure.with_default_headers()

        provided = MULTI_OK if multi_ok is None else multi_ok
        # Normalize once during init; comparisons during request handling are bytes-based.
        self._multi_ok: frozenset[bytes] = frozenset(
            _normalize_header_name_bytes(_encode_header_name(_normalize_header_name(name))) for name in provided
        )
        self.cache_policy = _resolve_cache_policy(
            secure=self.secure,
            cache_policy=cache_policy,
            sensitive=sensitive,
            cache_options=cache_options,
        )
        self.cache_control_override = _header_override(cache)
        self.vary_override = _header_override(vary)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_map = cast("MutableMapping[str, object]", scope)
        if scope_map.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            msg = cast("MutableMapping[str, object]", message)

            if msg.get("type") == "http.response.start":
                raw_headers = msg.get("headers") or []
                encoded_headers: HeaderList = list(cast("Iterable[tuple[bytes, bytes]]", raw_headers))
                headers: list[tuple[str, str]] = [
                    (name.decode("latin-1"), value.decode("latin-1")) for name, value in encoded_headers
                ]

                # Track existing occurrences by normalized key.
                positions: dict[str, list[int]] = {}
                for i, (k, _v) in enumerate(headers):
                    positions.setdefault(_normalize_header_name(k), []).append(i)

                other_headers, secure_cache_control, secure_vary = split_secure_headers(self.secure.headers.items())

                # Apply Secure headers.
                for name_str, value_str in other_headers:
                    norm_name = _normalize_header_name(name_str)

                    if _normalize_header_name_bytes(_encode_header_name(name_str)) in self._multi_ok:
                        headers.append((name_str, value_str))
                        continue

                    # Remove all existing values for this header (if present).
                    if norm_name in positions:
                        for idx in reversed(positions[norm_name]):
                            headers.pop(idx)
                        positions.pop(norm_name, None)

                    headers.append((name_str, value_str))
                    positions[norm_name] = [len(headers) - 1]

                status_code = parse_status_code(cast("int", msg.get("status", 0)))
                cache_control = self.cache_control_override or secure_cache_control
                vary = self.vary_override or secure_vary
                headers = apply_cache_policy(
                    headers,
                    status=status_code,
                    method=str(scope_map.get("method", "")),
                    path=str(scope_map.get("path", "")),
                    request_headers=asgi_request_headers(scope_map),
                    metadata=scope_map,
                    policy=self.cache_policy,
                    configured_cache_control=cache_control,
                    configured_vary=vary,
                )

                msg["headers"] = [(_encode_header_name(name), _encode_header_value(value)) for name, value in headers]

            await send(message)

        await self.app(scope, receive, send_wrapper)


def _header_override(value: CacheControl | Vary | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, (CacheControl, Vary)):
        return value.header_value
    return str(value)


def _resolve_cache_policy(  # noqa: PLR0911
    *,
    secure: Secure,
    cache_policy: CachePolicy | None,
    sensitive: CachePolicy | bool | object | None,
    cache_options: dict[str, object],
) -> CachePolicy | None:
    if cache_policy is not None:
        if isinstance(cache_policy, CachePolicy):
            return cache_policy
        if isinstance(cache_policy, dict):
            return CachePolicy(**cache_policy)
        if callable(cache_policy):
            return CachePolicy(predicate=cache_policy, **cache_options)
        return cache_policy
    if isinstance(sensitive, CachePolicy):
        return sensitive
    if isinstance(sensitive, dict):
        return CachePolicy(**sensitive, **cache_options)
    if isinstance(sensitive, (set, frozenset, list, tuple)):
        return CachePolicy(statuses=sensitive, **cache_options)
    if sensitive is not None and callable(sensitive):
        return CachePolicy(predicate=sensitive, **cache_options)
    if isinstance(sensitive, bool):
        if sensitive:
            return CachePolicy(default_sensitive=True, **cache_options)
        return CachePolicy(enabled=False, **cache_options)
    if cache_options:
        return CachePolicy(**cache_options)
    return secure.cache_policy
