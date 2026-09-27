from __future__ import annotations

import time
import typing as t
from datetime import timedelta
from functools import wraps
from urllib.parse import parse_qsl
from urllib.parse import quote
from urllib.parse import unquote
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from itsdangerous import BadSignature
from itsdangerous import URLSafeSerializer

from .globals import _cv_app
from .globals import current_app
from .globals import request
from .helpers import abort
from .helpers import url_for

#: The query parameter that carries the signature token. It is reserved:
#: any user-supplied value is stripped when generating a signed URL, and
#: a request is rejected if the parameter appears more than once.
SIGNATURE_PARAM = "_sig"

#: Characters that do not need percent-encoding in a URL path. This is
#: the union of RFC 3986 unreserved characters and the reserved
#: characters that are meaningful (and equivalent) across path segments.
_PATH_SAFE = "/:@!$&'()*+,;=-._~"


def _normalize_path(path: str) -> str:
    """Return a canonical form of a URL path.

    All percent-encoding is decoded, then re-encoded using uppercase hex
    and UTF-8, leaving only unreserved and path-safe reserved characters
    unencoded. This makes ``/a%20b`` and ``/a b`` compare equal,
    while Unicode and already-encoded paths get one consistent
    representation.
    """
    decoded = unquote(path, encoding="utf-8", errors="replace")
    return quote(decoded, safe=_PATH_SAFE)


def _canonical_query(pairs: t.Iterable[tuple[str, str]]) -> str:
    """Return a canonical query string from key/value pairs.

    Pairs are sorted so that parameter order does not matter, while
    repeated keys keep one entry per value. Empty values are kept as
    ``key=``. Keys and values are percent-encoded with UTF-8 and
    uppercase hex, so Unicode and already-encoded input normalize to
    the same representation.
    """
    items = sorted((str(key), str(value)) for key, value in pairs)
    return "&".join(
        f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in items
    )


def _canonical_string(
    method: str,
    purpose: str,
    endpoint: str,
    path: str,
    query_pairs: t.Iterable[tuple[str, str]],
    host: str | None,
    exp: int | None,
) -> str:
    """Build the canonical string that is signed and later compared."""
    return "\n".join(
        [
            "v1",
            method.upper(),
            purpose,
            endpoint,
            _normalize_path(path),
            _canonical_query(query_pairs),
            host if host is not None else "-",
            str(exp) if exp is not None else "-",
        ]
    )


def _resolve_endpoint(endpoint: str) -> str:
    """Resolve a relative ``.name`` endpoint against the current
    blueprint, mirroring :func:`url_for`.
    """
    if endpoint[:1] == ".":
        if (ctx := _cv_app.get(None)) is not None and ctx.has_request:
            blueprint_name = ctx.request.blueprint

            if blueprint_name is not None:
                return f"{blueprint_name}{endpoint}"

        return endpoint[1:]

    return endpoint


def _signed_host() -> str:
    """Return the host value that participates in the signature.

    ``SERVER_NAME`` always wins when configured, so the signature never
    depends on the client-supplied ``Host`` header. Otherwise the
    current request's host is used, which Flask has already validated
    against ``TRUSTED_HOSTS`` when that is configured.
    """
    server_name = current_app.config["SERVER_NAME"]

    if server_name is not None:
        return server_name

    if (ctx := _cv_app.get(None)) is not None and ctx.has_request:
        return request.host

    raise RuntimeError(
        "SIGNED_URL_INCLUDE_HOST is enabled, but no request is active and"
        " SERVER_NAME is not configured, so no trusted host is available."
    )


def _get_serializer() -> URLSafeSerializer:
    """Build the serializer used to sign and verify URL tokens.

    The current ``SECRET_KEY`` is always used to sign new URLs. Keys in
    ``SIGNED_URL_SECRET_KEY_FALLBACKS`` are only tried when verifying,
    which allows rotating keys without invalidating existing links.
    """
    app = current_app._get_current_object()

    if app.secret_key is None:
        raise RuntimeError("SECRET_KEY must be set to generate signed URLs.")

    keys: list[str | bytes] = []

    if fallbacks := app.config["SIGNED_URL_SECRET_KEY_FALLBACKS"]:
        keys.extend(fallbacks)

    keys.append(app.secret_key)  # itsdangerous signs with the last key
    return URLSafeSerializer(keys, salt=app.config["SIGNED_URL_SALT"])


def generate_signed_url(
    endpoint: str,
    *,
    purpose: str,
    max_age: int | float | timedelta | None = None,
    method: str = "GET",
    _external: bool | None = None,
    **values: t.Any,
) -> str:
    """Generate a signed URL for ``endpoint``.

    The URL is only valid for the given HTTP ``method`` and
    ``purpose``, for the exact set of route and query ``values``,
    and until ``max_age`` seconds have passed. Verification happens in
    the target view with :func:`verify_signed_url` or
    :func:`signed_url_required`.

    Query parameters are canonicalized before signing: order does not
    matter, repeated keys keep each of their values, and empty, Unicode,
    and already percent-encoded values have one consistent
    representation. The reserved ``_sig`` parameter is stripped from
    ``values`` so a signature can never be injected or duplicated.

    :param endpoint: The endpoint name, as accepted by :func:`url_for`.
    :param purpose: A short string identifying what the link is for, such
        as ``"download"``. The same purpose must be given when verifying.
    :param max_age: Seconds until the link expires, or a
        :class:`~datetime.timedelta`. ``None`` means the link does
        not expire.
    :param method: The HTTP method the link is valid for.
    :param _external: Passed to :func:`url_for`. Forced to ``True``
        when :data:`SIGNED_URL_INCLUDE_HOST` is enabled.
    :param values: Values for the URL rule and extra query parameters,
        as accepted by :func:`url_for`. Lists produce repeated query
        parameters.

    .. versionadded:: 3.2
    """
    if "\n" in purpose:
        raise ValueError("purpose must not contain a newline")

    values.pop(SIGNATURE_PARAM, None)
    include_host = current_app.config["SIGNED_URL_INCLUDE_HOST"]

    if include_host:
        _external = True

    raw_url = url_for(endpoint, _method=method, _external=_external, **values)
    parts = urlsplit(raw_url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)

    if max_age is None:
        exp = None
    else:
        if isinstance(max_age, timedelta):
            max_age = max_age.total_seconds()

        exp = int(time.time()) + int(max_age)

    payload = _canonical_string(
        method,
        purpose,
        _resolve_endpoint(endpoint),
        parts.path,
        query_pairs,
        _signed_host() if include_host else None,
        exp,
    )
    token = _get_serializer().dumps(payload)
    separator = "&" if parts.query else ""
    query = f"{parts.query}{separator}{SIGNATURE_PARAM}={token}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def verify_signed_url(purpose: str) -> bool:
    """Verify that the current request is a valid signed URL.

    The request is only valid if its signature was created with
    :func:`generate_signed_url` for the same ``purpose``, the
    same HTTP method, the same endpoint, and an equivalent set of query
    parameters, and it has not expired. Query parameter order may
    differ; any change to a parameter value, including one value of a
    repeated parameter, invalidates the link. A request with more than
    one ``_sig`` parameter is always rejected.

    :param purpose: The purpose the link was generated with.

    .. versionadded:: 3.2
    """
    signature_values = request.args.getlist(SIGNATURE_PARAM)

    if len(signature_values) != 1:
        return False

    try:
        payload = _get_serializer().loads(signature_values[0])
    except BadSignature:
        return False

    lines = payload.split("\n")

    if len(lines) != 8 or lines[0] != "v1":
        return False

    exp: int | None = None

    if lines[7] != "-":
        try:
            exp = int(lines[7])
        except ValueError:
            return False

        if int(time.time()) > exp:
            return False

    query_pairs = [
        (key, value)
        for key, values in request.args.to_dict(flat=False).items()
        if key != SIGNATURE_PARAM
        for value in values
    ]
    include_host = current_app.config["SIGNED_URL_INCLUDE_HOST"]
    expected = _canonical_string(
        request.method,
        purpose,
        request.endpoint or "",
        request.path,
        query_pairs,
        _signed_host() if include_host else None,
        exp,
    )
    return expected == payload


def signed_url_required(purpose: str) -> t.Callable[[t.Callable], t.Callable]:
    """Decorate a view to require a valid signed URL for ``purpose``.

    Aborts with 403 if :func:`verify_signed_url` fails::

        @app.route("/download/<name>")
        @signed_url_required("download")
        def download(name):
            ...

    .. versionadded:: 3.2
    """

    def decorator(f: t.Callable) -> t.Callable:
        @wraps(f)
        def wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
            if not verify_signed_url(purpose):
                abort(403)

            return f(*args, **kwargs)

        return wrapper

    return decorator
