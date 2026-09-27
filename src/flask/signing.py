from __future__ import annotations

import functools
import hashlib
import time
import typing as t
from datetime import timedelta
from urllib.parse import parse_qsl
from urllib.parse import quote
from urllib.parse import unquote
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from itsdangerous import Signer
from werkzeug.exceptions import abort as _wz_abort

from .globals import _cv_app
from .globals import current_app
from .globals import request

if t.TYPE_CHECKING:  # pragma: no cover
    from .app import Flask

#: The query parameter that carries the signature.
SIGNATURE_PARAM = "_sig"

#: The query parameter that carries the expiration timestamp.
EXPIRES_PARAM = "_sig_exp"

_RESERVED_PARAMS = {SIGNATURE_PARAM, EXPIRES_PARAM}

#: Characters that are left unencoded in canonicalized paths. This is the
#: RFC 3986 unreserved set plus sub-delims and the path separators, which
#: matches what Werkzeug produces when building URLs.
_PATH_SAFE = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:`/"
)


class SignedLinkError(Exception):
    """Base class for errors raised when verifying a signed URL."""


class InvalidSignedLink(SignedLinkError):
    """The signed URL is malformed, was tampered with, or does not match
    the current request.
    """


class ExpiredSignedLink(SignedLinkError):
    """The signed URL has a valid signature but its validity period has
    elapsed.
    """


def _get_signer(app: Flask) -> Signer:
    if not app.secret_key:
        raise RuntimeError(
            "The secret key is required to generate and verify signed URLs."
            " Set the 'SECRET_KEY' config to a random value."
        )

    keys: list[str | bytes] = []

    if fallbacks := app.config["SECRET_KEY_FALLBACKS"]:
        keys.extend(fallbacks)

    keys.append(app.secret_key)  # itsdangerous expects the current key last
    return Signer(keys, salt=b"flask-signed-url", digest_method=hashlib.sha256)


def _canonical_query(pairs: list[tuple[str, str]]) -> str:
    """Encode query key-value pairs in a canonical form. Pairs are sorted
    by key then value, so the order of parameters in the URL does not
    matter, while repeated keys and empty values are preserved.
    """
    return urlencode(sorted(pairs), quote_via=quote, safe="")


def _canonical_string(
    method: str,
    purpose: str,
    endpoint: str,
    host: str,
    path: str,
    query: str,
    expires: int | None,
) -> str:
    return "\n".join(
        [
            "v1",
            method,
            purpose,
            endpoint,
            host,
            path,
            query,
            "" if expires is None else str(expires),
        ]
    )


def _request_host(app: Flask) -> str:
    """The host to bind the signature to, or an empty string if the
    :data:`SIGNED_URL_INCLUDE_HOST` config is disabled.
    """
    if not app.config["SIGNED_URL_INCLUDE_HOST"]:
        return ""

    ctx = _cv_app.get(None)

    if ctx is not None and ctx.has_request:
        return ctx.request.host

    if (server_name := app.config["SERVER_NAME"]) is not None:
        return server_name

    raise RuntimeError(
        "'SIGNED_URL_INCLUDE_HOST' is enabled, but the host is not known"
        " outside a request. Set the 'SERVER_NAME' config."
    )


def signed_url_for(
    endpoint: str,
    *,
    purpose: str,
    method: str = "GET",
    max_age: int | float | timedelta | None = None,
    _anchor: str | None = None,
    _scheme: str | None = None,
    _external: bool | None = None,
    **values: t.Any,
) -> str:
    """Generate a URL for `endpoint` signed with the app's secret key,
    like :func:`flask.url_for` with an added signature. The URL can be
    verified with :func:`verify_signed_url` or :func:`signed_url_required`
    when the route is requested.

    The signature covers the HTTP `method`, the `purpose` string, the
    endpoint, the path, and the full set of query parameters. Reordering
    query parameters does not affect the signature, but changing, adding,
    or removing any value does. If the :data:`SIGNED_URL_INCLUDE_HOST`
    config is enabled, the host is covered as well.

    The link is signed with the current :data:`SECRET_KEY`. Keys in
    :data:`SECRET_KEY_FALLBACKS` are only used to verify old links.

    :param endpoint: The endpoint name to generate a URL for, same as
        :func:`flask.url_for`.
    :param purpose: A string identifying what the link is for, such as
        ``"unsubscribe"``. The same purpose must be passed when
        verifying. This prevents a link generated for one action from
        being used for another.
    :param method: The HTTP method the link is valid for. Other methods
        are rejected during verification.
    :param max_age: How long the link is valid, in seconds or as a
        ``timedelta``. If not given, the link does not expire.
    :param values: Values for the URL rule, same as
        :func:`flask.url_for`. The reserved parameters ``_sig`` and
        ``_sig_exp`` must not be used.

    .. versionadded:: 3.2
    """
    if _RESERVED_PARAMS.intersection(values):
        raise ValueError(
            f"The query parameters {SIGNATURE_PARAM!r} and {EXPIRES_PARAM!r}"
            " are reserved for the signature and must not be passed."
        )

    app = current_app._get_current_object()
    ctx = _cv_app.get(None)
    method = method.upper()

    # Resolve a blueprint-relative endpoint the same way url_for does, so
    # the signed endpoint name matches request.endpoint when verifying.
    if endpoint[:1] == ".":
        if (
            ctx is not None
            and ctx.has_request
            and (blueprint_name := ctx.request.blueprint) is not None
        ):
            endpoint = f"{blueprint_name}{endpoint}"
        else:
            endpoint = endpoint[1:]

    if max_age is None:
        expires = None
    else:
        if isinstance(max_age, timedelta):
            max_age = max_age.total_seconds()

        expires = int(time.time() + max_age)

    url = current_app.url_for(
        endpoint,
        _anchor=_anchor,
        _method=method,
        _scheme=_scheme,
        _external=_external,
        **values,
    )
    parts = urlsplit(url)

    # Normalize the path so that equivalent encodings, such as different
    # hex case or encoded unreserved characters, compare equal. Decode
    # once, then re-encode with a fixed safe set.
    path = quote(unquote(parts.path), safe=_PATH_SAFE)

    # The URL adapter prepends the script root, but request.path does not
    # include it when verifying. Strip it to make both sides consistent.
    if ctx is not None and ctx.has_request:
        script_root = ctx.request.script_root
    else:
        script_root = app.config["APPLICATION_ROOT"].rstrip("/")

    script_root = quote(script_root, safe=_PATH_SAFE)

    if script_root and (path == script_root or path.startswith(f"{script_root}/")):
        path = path[len(script_root) :]

    query = _canonical_query(parse_qsl(parts.query, keep_blank_values=True))
    canonical = _canonical_string(
        method,
        purpose,
        endpoint,
        _request_host(app),
        path,
        query,
        expires,
    )
    signature = _get_signer(app).get_signature(canonical.encode()).decode()

    extra = [(SIGNATURE_PARAM, signature)]

    if expires is not None:
        extra.insert(0, (EXPIRES_PARAM, str(expires)))

    query_string = parts.query

    if query_string:
        query_string = f"{query_string}&{urlencode(extra)}"
    else:
        query_string = urlencode(extra)

    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, query_string, parts.fragment)
    )


def verify_signed_url(
    *,
    purpose: str,
    method: str | None = None,
) -> bool:
    """Verify that the current request was made to a URL generated by
    :func:`signed_url_for` for the given `purpose`.

    The request's HTTP method must match the method the link was signed
    for, and the request's endpoint, path, and query parameters must be
    unchanged. A link is rejected if it is expired, was tampered with, or
    is used for a different route, method, or purpose than it was
    generated for.

    :param purpose: The same purpose string passed to
        :func:`signed_url_for`.
    :param method: The HTTP method to verify against. By default, the
        current request's method is used.
    :raises InvalidSignedLink: If the signature is missing, malformed,
        duplicated, or does not match the request.
    :raises ExpiredSignedLink: If the link's validity period has elapsed.
    :return: ``True`` if the link is valid.

    .. versionadded:: 3.2
    """
    app = current_app._get_current_object()
    req = request._get_current_object()

    if req.endpoint is None:
        raise InvalidSignedLink("The request did not match an endpoint.")

    if method is None:
        method = req.method

    method = method.upper()
    pairs = parse_qsl(
        req.query_string.decode("utf-8", "replace"), keep_blank_values=True
    )
    signatures = [value for key, value in pairs if key == SIGNATURE_PARAM]
    expirations = [value for key, value in pairs if key == EXPIRES_PARAM]

    if len(signatures) != 1 or len(expirations) > 1:
        raise InvalidSignedLink(
            f"The URL must contain exactly one {SIGNATURE_PARAM!r} parameter"
            f" and at most one {EXPIRES_PARAM!r} parameter."
        )

    if expirations:
        try:
            expires: int | None = int(expirations[0])
        except ValueError:
            raise InvalidSignedLink(
                f"The {EXPIRES_PARAM!r} parameter is not a valid timestamp."
            ) from None

        if time.time() > expires:
            raise ExpiredSignedLink("The signed link has expired.")
    else:
        expires = None

    remaining = [(key, value) for key, value in pairs if key not in _RESERVED_PARAMS]
    canonical = _canonical_string(
        method,
        purpose,
        req.endpoint,
        _request_host(app),
        quote(req.path, safe=_PATH_SAFE),
        _canonical_query(remaining),
        expires,
    )

    if not _get_signer(app).verify_signature(
        canonical.encode(), signatures[0].encode()
    ):
        raise InvalidSignedLink("The signature does not match the request.")

    return True


def signed_url_required(
    purpose: str, *, method: str | None = None
) -> t.Callable[[t.Callable[..., t.Any]], t.Callable[..., t.Any]]:
    """Decorate a view to require that the current request was made to a
    valid signed URL for the given `purpose`. Aborts with a ``403``
    error if :func:`verify_signed_url` fails.

    .. code-block:: python

        @app.get("/unsubscribe/<int:user_id>")
        @signed_url_required("unsubscribe")
        def unsubscribe(user_id):
            ...

    :param purpose: The same purpose string passed to
        :func:`signed_url_for`.
    :param method: The HTTP method to verify against. By default, the
        current request's method is used.

    .. versionadded:: 3.2
    """

    def decorator(
        view_func: t.Callable[..., t.Any],
    ) -> t.Callable[..., t.Any]:
        @functools.wraps(view_func)
        def wrapped(*args: t.Any, **kwargs: t.Any) -> t.Any:
            try:
                verify_signed_url(purpose=purpose, method=method)
            except SignedLinkError:
                _wz_abort(403)

            return view_func(*args, **kwargs)

        return wrapped

    return decorator
