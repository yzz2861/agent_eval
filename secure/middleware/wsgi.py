from __future__ import annotations

from collections.abc import Iterable
from types import TracebackType
from typing import Any, TypeAlias, cast

from .._internal.cache_policy import CachePolicy
from .._internal.cache_response import apply_cache_policy, parse_status_code, split_secure_headers, wsgi_request_headers
from ..headers.cache_control import CacheControl
from ..headers.vary import Vary
from ..secure import MULTI_OK, Secure

# ---------------------------------------------------------------------------
# WSGI typing aliases
# ---------------------------------------------------------------------------

HeaderList: TypeAlias = list[tuple[str, str]]

# PEP 3333: exc_info may be a 3-tuple, or None. In practice (and in wsgiref types),
# it's also allowed to be (None, None, None) as a sentinel.
ExcInfo: TypeAlias = tuple[type[BaseException], BaseException, TracebackType] | tuple[None, None, None] | None

# PEP 3333: start_response(status, headers[, exc_info]) -> write(body_bytes)
WriteCallable: TypeAlias = Any  # write callable exists, but is rarely used in modern apps

try:
    # Python 3.11+ provides useful WSGI types in the stdlib.
    from wsgiref.types import StartResponse, WSGIApplication, WSGIEnvironment
except Exception:  # pragma: no cover
    from collections.abc import Callable

    WSGIEnvironment = dict[str, Any]
    StartResponse = Callable[[str, HeaderList, ExcInfo], WriteCallable]
    WSGIApplication = Callable[[WSGIEnvironment, StartResponse], Iterable[bytes]]

WSGIApp: TypeAlias = WSGIApplication

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_header_name(name: str) -> str:
    """Normalize a header field-name for case-insensitive comparison."""
    return name.strip().lower()


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class SecureWSGIMiddleware:
    """
    Apply Secure's configured HTTP security headers to a WSGI application.

    This middleware wraps a WSGI app and injects headers by wrapping the WSGI
    ``start_response`` callable. It does not require a framework-specific
    response object.

    Parameters
    ----------
    app:
        The WSGI application to wrap.
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
    - Overwrites existing headers by default (case-insensitive) to avoid duplicates
      for single-value headers (e.g., ``X-Frame-Options``).
    - For header names in ``multi_ok``, existing values are preserved and
      Secure's value is appended.
    - ``Cache-Control`` is merged for sensitive responses so directives written
      by the application (for example ``private`` or ``no-cache``) are kept.
    - Public static responses keep their existing ``Cache-Control`` value.
    - ``Vary`` is merged with existing field names rather than replaced.
    - Headers are written in ``start_response``, before the response body is
      iterated, so streaming responses are covered.

    Notes
    -----
    WSGI technically allows calling ``start_response`` multiple times in error
    scenarios (via ``exc_info``). This middleware preserves that behavior by
    forwarding ``exc_info`` unchanged.
    """

    def __init__(  # noqa: PLR0913
        self,
        app: WSGIApp,
        *,
        secure: Secure | None = None,
        multi_ok: Iterable[str] | None = None,
        cache_policy: CachePolicy | None = None,
        sensitive: CachePolicy | bool | object | None = None,
        cache: CacheControl | str | None = None,
        vary: Vary | str | None = None,
        **cache_options: object,
    ) -> None:
        self.app = app
        self.secure = secure or Secure.with_default_headers()

        provided = MULTI_OK if multi_ok is None else multi_ok
        self._multi_ok: frozenset[str] = frozenset(_normalize_header_name(h) for h in provided)
        self.cache_policy = _resolve_cache_policy(
            secure=self.secure,
            cache_policy=cache_policy,
            sensitive=sensitive,
            cache_options=cache_options,
        )
        self.cache_control_override = _header_override(cache)
        self.vary_override = _header_override(vary)

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
        """
        Invoke the wrapped WSGI app, injecting configured security headers.

        Parameters
        ----------
        environ:
            The WSGI environment for the request.
        start_response:
            The WSGI ``start_response`` callable provided by the server.

        Returns
        -------
        Iterable[bytes]
            The response body iterable returned by the wrapped application.
        """

        def custom_start_response(
            status: str,
            headers: HeaderList,
            exc_info: ExcInfo = None,
        ) -> WriteCallable:
            out: HeaderList = list(headers)
            status_code = parse_status_code(status)

            # Track existing occurrences by normalized key.
            positions: dict[str, list[int]] = {}
            for i, (k, _v) in enumerate(out):
                positions.setdefault(_normalize_header_name(k), []).append(i)

            secure_cache_control: str | None = None
            secure_vary: str | None = None
            other_headers, secure_cache_control, secure_vary = split_secure_headers(self.secure.headers.items())

            # Apply Secure headers.
            for k, v in other_headers:
                nk = _normalize_header_name(k)

                if nk in self._multi_ok:
                    out.append((k, v))
                    continue

                if nk in positions:
                    for idx in reversed(positions[nk]):
                        out.pop(idx)
                    positions.pop(nk, None)

                out.append((k, v))
                positions[nk] = [len(out) - 1]

            cache_control = self.cache_control_override or secure_cache_control
            vary = self.vary_override or secure_vary
            out = apply_cache_policy(
                out,
                status=status_code,
                method=str(environ.get("REQUEST_METHOD", "")),
                path=str(environ.get("PATH_INFO", "")),
                request_headers=wsgi_request_headers(environ),
                metadata=cast("dict[str, object]", environ),
                policy=self.cache_policy,
                configured_cache_control=cache_control,
                configured_vary=vary,
            )

            return start_response(status, out, exc_info)

        return self.app(environ, custom_start_response)


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
