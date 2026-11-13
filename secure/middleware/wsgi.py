from __future__ import annotations

from collections.abc import Iterable, Iterator
import logging
from types import TracebackType
from typing import Any, TypeAlias

from ..secure import MULTI_OK, Secure

logger = logging.getLogger(__name__)

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
    headers: Iterable[tuple[str, str]],
    configured_items: Iterable[tuple[str, str]],
    multi_ok: frozenset[str],
) -> HeaderList:
    """
    Merge configured security headers into an existing header list.

    Single-valued headers replace all existing occurrences. Headers listed in
    ``multi_ok`` are preserved and the configured value is appended.
    """
    out: HeaderList = list(headers)

    positions: dict[str, list[int]] = {}
    for i, (k, _v) in enumerate(out):
        positions.setdefault(_normalize_header_name(k), []).append(i)

    for k, v in configured_items:
        nk = _normalize_header_name(k)

        if nk in multi_ok:
            out.append((k, v))
            continue

        if nk in positions:
            for idx in reversed(positions[nk]):
                out.pop(idx)
            positions.pop(nk, None)

        out.append((k, v))
        positions[nk] = [len(out) - 1]

    return out


class _ResponseIterable(Iterator[bytes]):
    """
    Close the wrapped WSGI iterable exactly once.

    WSGI servers call ``close()`` after use. This wrapper also closes on
    exhaustion or iteration failure so a client disconnect cannot strand
    upstream resources.
    """

    def __init__(self, iterable: Iterable[bytes]) -> None:
        self._iterable = iterable
        self._iterator: Iterator[bytes] | None = None
        self._closed = False

    def __iter__(self) -> _ResponseIterable:
        return self

    def __next__(self) -> bytes:
        try:
            if self._iterator is None:
                self._iterator = iter(self._iterable)
            return next(self._iterator)
        except StopIteration:
            self.close()
            raise
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        close = getattr(self._iterable, "close", None)
        if callable(close):
            close()
            return

        if self._iterator is not None:
            close = getattr(self._iterator, "close", None)
            if callable(close):
                close()


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

    Behavior
    --------
    - Overwrites existing headers by default (case-insensitive) to avoid duplicates
      for single-value headers (e.g., ``X-Frame-Options``).
    - For header names in ``multi_ok``, existing values are preserved and
      Secure's value is appended.

    Notes
    -----
    WSGI technically allows calling ``start_response`` multiple times in error
    scenarios (via ``exc_info``). This middleware preserves that behavior by
    forwarding ``exc_info`` unchanged.
    """

    def __init__(
        self,
        app: WSGIApp,
        *,
        secure: Secure | None = None,
        multi_ok: Iterable[str] | None = None,
    ) -> None:
        self.app = app
        self.secure = secure or Secure.with_default_headers()

        provided = MULTI_OK if multi_ok is None else multi_ok
        self._multi_ok: frozenset[str] = frozenset(_normalize_header_name(h) for h in provided)

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
            out = _inject_headers(headers, _configured_header_items(self.secure), self._multi_ok)

            if exc_info is None:
                return start_response(status, out)
            return start_response(status, out, exc_info)

        try:
            app_iterable = self.app(environ, custom_start_response)
        except Exception as exc:
            logger.log(logging.ERROR, "WSGI application raised %s", type(exc).__name__)
            raise

        return _ResponseIterable(app_iterable)
