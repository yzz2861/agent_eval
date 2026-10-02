"""Build RFC 9421 HTTP message signature base strings.

This module implements only the *signature base* construction defined in
RFC 9421. It deliberately does **not** select keys, choose algorithms,
or perform any cryptography. The caller provides explicit request and
response contexts plus the signature parameters (keyid, alg, created,
...) and is responsible for signing the returned bytes.

Values are derived from the raw request target exactly as it appeared on
the wire. Nothing is percent-decoded and re-encoded, and forwarded
headers (Forwarded, X-Forwarded-*) are never consulted.

.. versionadded:: 3.2
"""

from __future__ import annotations

import re
import typing as t
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

__all__ = [
    "Component",
    "RequestContext",
    "ResponseContext",
    "SignatureBaseError",
    "build_signature_base",
]

# RFC 9110 tchar; \x60 is the backtick character.
_token_re = re.compile(r"^[!#$%&'*+\-.0-9A-Za-z^_\x60|~]+$")
_sf_key_re = re.compile(r"^[a-z*][a-z0-9_.*-]*$")

_request_derived = frozenset(
    {"@method", "@target-uri", "@authority", "@path", "@query", "@query-param"}
)
_supported_derived = _request_derived | {"@status"}


class SignatureBaseError(ValueError):
    """A covered component is missing, unsupported, or malformed.

    Raised instead of silently skipping anything, so both signing peers
    always agree on the exact bytes that were covered.
    """


@dataclass(frozen=True)
class Component:
    """A covered component identifier: a lowercased name plus parameters.

    'params' preserves order and maps each parameter name to a string
    value, or to True for a bare flag such as 'req'.
    """

    name: str
    params: tuple[tuple[str, str | bool], ...] = ()


@dataclass(frozen=True)
class RequestContext:
    """Explicit request data to derive component values from.

    'target' is the raw request target (origin-form or absolute-form) as
    sent on the wire, without any decoding or normalization. 'scheme' is
    used together with the Host header to form @target-uri when 'target'
    is in origin-form; it is never taken from forwarded headers.
    'headers' may be a Headers instance, a mapping, or an iterable of
    (name, value) pairs, and may contain repeated names.
    """

    method: str
    target: str
    headers: t.Any = ()
    scheme: str = "http"


@dataclass(frozen=True)
class ResponseContext:
    """Explicit response data to derive component values from.

    'headers' accepts the same types as RequestContext.headers.
    """

    status: int
    headers: t.Any = ()


def _normalize_headers(headers: t.Any) -> list[tuple[str, str]]:
    if headers is None:
        return []

    if hasattr(headers, "items"):
        pairs = list(headers.items())
    else:
        pairs = list(headers)

    return [(str(name).lower(), str(value)) for name, value in pairs]


def _coerce_component(item: t.Any) -> Component:
    if isinstance(item, Component):
        comp = item
    elif isinstance(item, str):
        comp = Component(item)
    elif isinstance(item, tuple) and len(item) == 2:
        name, params = item

        if hasattr(params, "items"):
            params = tuple(params.items())

        comp = Component(name, tuple((k, v) for k, v in params))
    else:
        raise SignatureBaseError(f"invalid component specifier: {item!r}")

    if not isinstance(comp.name, str) or not comp.name:
        raise SignatureBaseError(f"invalid component name: {comp.name!r}")

    if comp.name.startswith("@"):
        if comp.name not in _supported_derived:
            raise SignatureBaseError(f"unsupported derived component: {comp.name!r}")
    else:
        # Field names are case-insensitive and serialized lowercase.
        comp = Component(comp.name.lower(), comp.params)

        if not _token_re.match(comp.name):
            raise SignatureBaseError(f"invalid field name: {comp.name!r}")

    name_count = 0

    for key, value in comp.params:
        if not isinstance(key, str) or not _sf_key_re.match(key):
            raise SignatureBaseError(f"invalid component parameter: {key!r}")

        if key == "req":
            if value is not True:
                raise SignatureBaseError("the 'req' parameter must be a bare flag")
        elif key == "name" and comp.name == "@query-param":
            if not isinstance(value, str):
                raise SignatureBaseError("the 'name' parameter must be a string")

            name_count += 1
        else:
            raise SignatureBaseError(
                f"unsupported parameter {key!r} for component {comp.name!r}"
            )

    if comp.name == "@query-param" and name_count != 1:
        raise SignatureBaseError("@query-param requires exactly one 'name' parameter")

    return comp


def _split_target(target: str) -> tuple[str, str, str, str | None]:
    """Split a raw request target without decoding anything.

    Returns (scheme, authority, path, query). query is None when no
    question mark is present, distinguishing it from an empty query.
    """
    scheme = ""
    authority = ""
    rest = target
    i = target.find("://")

    if i > 0 and not any(c in "/?#" for c in target[:i]):
        scheme = target[:i]
        rest = target[i + 3 :]
        j = len(rest)

        for c in "/?":
            k = rest.find(c)

            if k != -1:
                j = min(j, k)

        authority = rest[:j]
        rest = rest[j:]

    q = rest.find("?")

    if q == -1:
        return scheme, authority, rest, None

    return scheme, authority, rest[:q], rest[q + 1 :]


def _host_header(headers: list[tuple[str, str]]) -> str:
    for name, value in headers:
        if name == "host":
            return value.strip(" \t")

    raise SignatureBaseError(
        "an origin-form target requires a Host header for this component"
    )


def _pct_decode(value: str) -> str:
    try:
        return unquote_to_bytes(value).decode("utf-8")
    except UnicodeDecodeError as e:
        raise SignatureBaseError(
            f"query parameter is not valid UTF-8: {value!r}"
        ) from e


def _resolve_request_derived(
    comp: Component, ctx: RequestContext, headers: list[tuple[str, str]]
) -> str:
    name = comp.name

    if name == "@method":
        return ctx.method.upper()

    scheme, authority, path, query = _split_target(ctx.target)

    if name == "@target-uri":
        if scheme:
            return ctx.target

        if not path.startswith("/"):
            raise SignatureBaseError(
                f"cannot derive @target-uri from target {ctx.target!r}"
            )

        return f"{ctx.scheme}://{authority or _host_header(headers)}{ctx.target}"

    if name == "@authority":
        return (authority or _host_header(headers)).lower()

    if not scheme and not path.startswith("/"):
        raise SignatureBaseError(f"cannot derive {name} from target {ctx.target!r}")

    if name == "@path":
        return path or "/"

    if name == "@query":
        return query or ""

    # @query-param
    param_name = next(v for k, v in comp.params if k == "name")

    if query is None:
        raise SignatureBaseError(f"query parameter {param_name!r} is not present")

    for pair in query.split("&"):
        raw_name, _, raw_value = pair.partition("=")

        if _pct_decode(raw_name) == param_name:
            return _pct_decode(raw_value)

    raise SignatureBaseError(f"query parameter {param_name!r} is not present")


def _resolve(
    comp: Component,
    request: RequestContext | None,
    response: ResponseContext | None,
    request_headers: list[tuple[str, str]],
    response_headers: list[tuple[str, str]],
) -> str:
    use_req = any(key == "req" for key, _ in comp.params)
    current_is_response = response is not None

    if use_req and not current_is_response:
        raise SignatureBaseError(
            f"component {comp.name!r} uses ;req but no response is being signed"
        )

    if use_req and request is None:
        raise SignatureBaseError(
            f"component {comp.name!r} uses ;req but no request context was provided"
        )

    if comp.name == "@status":
        if use_req or not current_is_response:
            raise SignatureBaseError("@status requires a response context")

        return str(response.status)  # type: ignore[union-attr]

    if comp.name in _request_derived:
        if current_is_response and not use_req:
            raise SignatureBaseError(
                f"component {comp.name!r} requires the ;req parameter"
                " when signing a response"
            )

        if request is None:
            raise SignatureBaseError(
                f"component {comp.name!r} requires a request context"
            )

        return _resolve_request_derived(comp, request, request_headers)

    # Plain header field.
    if current_is_response and not use_req:
        headers = response_headers
    else:
        if request is None:
            raise SignatureBaseError(
                f"component {comp.name!r} requires a request context"
            )

        headers = request_headers

    values = [value.strip(" \t") for name, value in headers if name == comp.name]

    if not values:
        raise SignatureBaseError(f"header field {comp.name!r} is not present")

    return ", ".join(values)


def _serialize_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _serialize_value(value: t.Any) -> str:
    if value is False:
        return "?0"

    if isinstance(value, bool):
        raise SignatureBaseError("only the true flag may be serialized bare")

    if isinstance(value, int):
        return str(value)

    if isinstance(value, str):
        return _serialize_string(value)

    raise SignatureBaseError(f"cannot serialize parameter value: {value!r}")


def _component_id(comp: Component) -> str:
    out = _serialize_string(comp.name)

    for key, value in comp.params:
        out += f";{key}"

        if value is not True:
            out += f"={_serialize_value(value)}"

    return out


def build_signature_base(
    components: t.Iterable[str | Component | tuple[str, t.Any]],
    *,
    request: RequestContext | None = None,
    response: ResponseContext | None = None,
    params: t.Mapping[str, t.Any] | t.Iterable[tuple[str, t.Any]] = (),
) -> bytes:
    """Build the RFC 9421 signature base for an ordered component list.

    'components' items are field names or derived component names,
    optionally with parameters, for example "date", "@method",
    ("@query-param", {"name": "Pet"}), or
    Component("@method", (("req", True),)).

    When 'response' is given, the base is for a response signature:
    request-derived components and request headers must carry the 'req'
    parameter and are resolved from the explicitly provided 'request'
    context.

    'params' are the signature parameters (created, keyid, alg, nonce,
    tag, ...) serialized after the component list in the final
    @signature-params line, in the exact order given. Returns the
    signature base as UTF-8 bytes, ready to be fed to a signature
    algorithm chosen by the caller.
    """
    if request is None and response is None:
        raise SignatureBaseError("a request or response context is required")

    if isinstance(components, (str, bytes)):
        raise SignatureBaseError("components must be an iterable of specifiers")

    comps = [_coerce_component(item) for item in components]
    request_headers = _normalize_headers(request.headers) if request else []
    response_headers = _normalize_headers(response.headers) if response else []

    lines = []

    for comp in comps:
        value = _resolve(comp, request, response, request_headers, response_headers)
        lines.append(f"{_component_id(comp)}: {value}")

    sig_params = f"({' '.join(_component_id(comp) for comp in comps)})"

    if hasattr(params, "items"):
        param_items = list(params.items())
    else:
        param_items = list(params)

    for key, value in param_items:
        if not isinstance(key, str) or not _sf_key_re.match(key):
            raise SignatureBaseError(f"invalid signature parameter: {key!r}")

        sig_params += f";{key}"

        if value is not True:
            sig_params += f"={_serialize_value(value)}"

    lines.append(f'"@signature-params": {sig_params}')
    return "\n".join(lines).encode("utf-8")
