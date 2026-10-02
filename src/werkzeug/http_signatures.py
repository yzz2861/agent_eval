"""Build RFC 9421 HTTP message signature base strings.

This module only builds the *signature base* described in :rfc:`9421`
section 2.5. It does not select keys, and it does not perform any
cryptographic operation. The caller is responsible for choosing the
key and algorithm, and for signing or verifying the bytes returned by
:func:`build_signature_base`.

The message context (method, target URI, status, headers) must be
provided explicitly through :class:`RequestContext` and
:class:`ResponseContext`. The target URI is used exactly as given, in
its raw percent-encoded form. Forwarding headers such as ``Forwarded``
or ``X-Forwarded-Host`` are never consulted; if a proxy rewrites the
request, the original target must be captured by the application.

.. versionadded:: 3.2
"""

from __future__ import annotations

import collections.abc as cabc
import dataclasses
import re
import typing as t
from urllib.parse import urlsplit

from .datastructures.headers import Headers


class SignatureComponentError(ValueError):
    """A covered component cannot be resolved for the given message.

    Raised when a component is unknown or unsupported, when a header
    field or query parameter is missing, or when the required request
    or response context was not provided. Components are never skipped
    silently.

    .. versionadded:: 3.2
    """


_header_name_re = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")
_derived_name_re = re.compile(r"^@[a-z-]+$")

#: Derived component identifiers supported by this module.
_supported_derived = {
    "@method",
    "@target-uri",
    "@authority",
    "@path",
    "@query",
    "@query-param",
    "@status",
}


def _serialize_string(value: str) -> str:
    """Serialize a value as an RFC 8941 string."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclasses.dataclass(frozen=True)
class Component:
    """A covered component identifier, such as ``"date"``,
    ``"@method"``, or ``"@query-param"`` with a ``name`` parameter.

    :param name: The component name. Header field names are matched
        case-insensitively and serialized in lowercase. Derived
        component names start with ``@``.
    :param params: Component parameters. ``"req"`` (boolean) derives
        the component from the related request when signing a
        response. ``"name"`` (string) is required for
        ``"@query-param"`` and invalid for anything else.

    .. versionadded:: 3.2
    """

    name: str
    params: t.Mapping[str, str | bool] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        name = self.name.lower()
        params = {k.lower(): v for k, v in self.params.items()}

        if params.get("req") is False:
            del params["req"]

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "params", params)

        if name.startswith("@"):
            if not _derived_name_re.match(name):
                raise SignatureComponentError(
                    f"Invalid derived component name {self.name!r}."
                )

            if name not in _supported_derived:
                raise SignatureComponentError(
                    f"Derived component {name!r} is not supported."
                )
        elif not _header_name_re.match(name):
            raise SignatureComponentError(
                f"Invalid header field name {self.name!r}."
            )

        for key, value in params.items():
            if key == "req":
                if not isinstance(value, bool):
                    raise SignatureComponentError(
                        "The 'req' parameter must be a boolean."
                    )
            elif key == "name":
                if name != "@query-param":
                    raise SignatureComponentError(
                        "The 'name' parameter is only valid for '@query-param'."
                    )

                if not isinstance(value, str):
                    raise SignatureComponentError(
                        "The 'name' parameter must be a string."
                    )
            else:
                raise SignatureComponentError(
                    f"Component parameter {key!r} is not supported."
                )

    def to_string(self) -> str:
        """Serialize as an RFC 8941 string with parameters, such as
        ``"@query-param";name="Pet"``.
        """
        out = [_serialize_string(self.name)]

        for key, value in self.params.items():
            if value is True:
                out.append(f";{key}")
            else:
                out.append(f";{key}={_serialize_string(t.cast(str, value))}")

        return "".join(out)


def _normalize_headers(
    value: Headers | cabc.Mapping[str, str] | cabc.Iterable[tuple[str, str]] | None,
) -> Headers:
    if value is None:
        return Headers()

    if isinstance(value, Headers):
        return value

    return Headers(value)


@dataclasses.dataclass(frozen=True)
class RequestContext:
    """The explicit request message context used to resolve components.

    :param method: The HTTP method, used as-is for ``@method``.
    :param target_uri: The raw target URI, exactly as received or sent,
        with percent-encoding preserved. It is never decoded and
        rebuilt. Derived URI components require an absolute URI, except
        ``@path``, ``@query``, and ``@query-param``, which also work
        with an origin-form target such as ``/path?query``.
    :param headers: The request headers. Multiple fields with the same
        name are combined with ``", "`` in order.

    .. versionadded:: 3.2
    """

    method: str
    target_uri: str
    headers: Headers = dataclasses.field(default_factory=Headers)

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", _normalize_headers(self.headers))


@dataclasses.dataclass(frozen=True)
class ResponseContext:
    """The explicit response message context used to resolve components.

    :param status: The HTTP status code, used for ``@status``.
    :param headers: The response headers.
    :param request: The original request this response is associated
        with. Required to resolve components carrying the ``req``
        parameter. It must be provided explicitly; it is never guessed
        from the environment.

    .. versionadded:: 3.2
    """

    status: int
    headers: Headers = dataclasses.field(default_factory=Headers)
    request: RequestContext | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", _normalize_headers(self.headers))


def _split_target(target_uri: str) -> tuple[str, str, str, str]:
    """Split a raw target URI into ``(scheme, authority, path, query)``
    without decoding or normalizing any percent-encoding.
    """
    try:
        parts = urlsplit(target_uri)
    except ValueError as e:
        raise SignatureComponentError(f"Invalid target URI: {e}") from e

    return parts.scheme, parts.netloc, parts.path, parts.query


def _authority(target_uri: str) -> str:
    """The ``@authority`` value: lowercase host, optional port, no
    userinfo.
    """
    try:
        parts = urlsplit(target_uri)
    except ValueError as e:
        raise SignatureComponentError(f"Invalid target URI: {e}") from e

    if parts.username is not None or parts.password is not None:
        raise SignatureComponentError(
            "The target URI must not contain a userinfo component."
        )

    host = parts.hostname

    if not host:
        raise SignatureComponentError(
            "'@authority' requires an absolute target URI with a host."
        )

    try:
        port = parts.port
    except ValueError as e:
        raise SignatureComponentError(f"Invalid target URI: {e}") from e

    if ":" in host:
        host = f"[{host}]"

    if port is not None:
        return f"{host}:{port}"

    return host


def _query_param(query: str, name: str) -> str:
    """The raw value of the query parameter ``name``, without decoding
    percent-encoding. The name is matched exactly.
    """
    matches = []

    for pair in query.split("&"):
        if not pair:
            continue

        key, _, value = pair.partition("=")

        if key == name:
            matches.append(value)

    if not matches:
        raise SignatureComponentError(
            f"Query parameter {name!r} is not present in the target URI."
        )

    if len(matches) > 1:
        raise SignatureComponentError(
            f"Query parameter {name!r} occurs multiple times in the target URI."
        )

    return matches[0]


def _resolve_request_component(component: Component, request: RequestContext) -> str:
    name = component.name

    if name == "@method":
        return request.method

    if name == "@target-uri":
        scheme, netloc, _, _ = _split_target(request.target_uri)

        if not scheme or not netloc:
            raise SignatureComponentError(
                "'@target-uri' requires an absolute target URI."
            )

        return request.target_uri

    if name == "@authority":
        return _authority(request.target_uri)

    _, _, path, query = _split_target(request.target_uri)

    if name == "@path":
        return path or "/"

    if name == "@query":
        return query

    # "@query-param"
    wanted = component.params.get("name")

    if wanted is None:
        raise SignatureComponentError(
            "'@query-param' requires a 'name' parameter."
        )

    return _query_param(query, t.cast(str, wanted))


def _resolve_component(
    component: Component,
    request: RequestContext | None,
    response: ResponseContext | None,
) -> str:
    from_request = bool(component.params.get("req", False))

    if from_request:
        if request is None:
            raise SignatureComponentError(
                f"Component {component.to_string()} requires the related"
                " request, but no request context was provided."
            )

        message: RequestContext | ResponseContext = request
    elif response is not None:
        message = response
    elif request is not None:
        message = request
    else:
        raise SignatureComponentError(
            "A request or response context is required to resolve components."
        )

    name = component.name

    if name == "@status":
        if from_request or isinstance(message, RequestContext):
            raise SignatureComponentError(
                "'@status' is only valid for the response being signed."
            )

        return str(message.status)

    if name.startswith("@"):
        if not isinstance(message, RequestContext):
            raise SignatureComponentError(
                f"Component {name!r} is only valid for requests."
            )

        return _resolve_request_component(component, message)

    values = message.headers.getlist(name)

    if not values:
        raise SignatureComponentError(
            f"Header field {name!r} is not present in the message."
        )

    return ", ".join(value.strip(" \t") for value in values)


def _serialize_signature_params(params: t.Mapping[str, str | int | bool]) -> str:
    out = []

    for key, value in params.items():
        if not _header_name_re.match(key):
            raise SignatureComponentError(
                f"Invalid signature parameter name {key!r}."
            )

        if isinstance(value, bool):
            if value:
                out.append(f";{key}")
        elif isinstance(value, int):
            out.append(f";{key}={value}")
        elif isinstance(value, str):
            out.append(f";{key}={_serialize_string(value)}")
        else:
            raise TypeError(
                f"Signature parameter {key!r} must be a string, integer, or"
                f" boolean, got {type(value).__name__!r}."
            )

    return "".join(out)


def build_signature_base(
    components: cabc.Sequence[Component | str],
    *,
    request: RequestContext | None = None,
    response: ResponseContext | None = None,
    signature_params: t.Mapping[str, str | int | bool] | None = None,
) -> bytes:
    """Build the RFC 9421 signature base for the covered components.

    Each component is resolved against the explicit message context and
    emitted as one ``"component-id": value`` line, in the order given.
    The final line is ``"@signature-params"``, which attests the exact
    component and parameter order, so it cannot be reordered without
    invalidating the signature. The result is UTF-8 encoded.

    Components are resolved against the response if one is provided,
    otherwise against the request. A component with the ``req``
    parameter is resolved against the related request, which must be
    passed as ``request`` or as :attr:`ResponseContext.request`.

    :param components: The covered components, in order. Plain strings
        are treated as component names without parameters.
    :param request: The request message context.
    :param response: The response message context.
    :param signature_params: Parameters appended to the
        ``"@signature-params"`` line, such as ``created``, ``keyid``,
        ``alg``, ``nonce``, ``expires``, and ``tag``. They are
        serialized in the order given. This does not select a key or
        algorithm; it only records what the caller chose.
    :return: The signature base, ready to be signed or verified.
    :raise SignatureComponentError: If a component is missing,
        unsupported, or cannot be resolved.

    .. versionadded:: 3.2
    """
    normalized = [
        item if isinstance(item, Component) else Component(item) for item in components
    ]

    if request is None and response is not None:
        request = response.request

    lines = []

    for component in normalized:
        value = _resolve_component(component, request, response)
        lines.append(f"{component.to_string()}: {value}")

    inner_list = " ".join(item.to_string() for item in normalized)
    params = _serialize_signature_params(signature_params or {})
    lines.append(f'"@signature-params": ({inner_list}){params}')
    return "\n".join(lines).encode("utf-8")
