from __future__ import annotations

from collections.abc import Iterable, Mapping

from ..headers.cache_control import CacheControl
from ..headers.vary import merge_vary_values
from .cache_policy import CachePolicy, merge_cache_control_values

HeaderPair = tuple[str, str]


def parse_status_code(status: int | str) -> int:
    """Extract an integer status code from a WSGI status line or ASGI status."""
    if isinstance(status, int):
        return status
    token = str(status).strip().split(" ", 1)[0]
    try:
        return int(token)
    except ValueError:
        return 0


def header_values(headers: Iterable[HeaderPair], name: str) -> list[str]:
    """Return all values for a header name, case-insensitively."""
    lowered = name.lower()
    return [value for key, value in headers if key.lower() == lowered]


def response_headers_mapping(headers: Iterable[HeaderPair]) -> dict[str, str]:
    """Build a lowercase header mapping, joining repeated field values."""
    mapping: dict[str, str] = {}
    for key, value in headers:
        lowered = key.lower()
        if lowered in mapping:
            mapping[lowered] = f"{mapping[lowered]}, {value}"
        else:
            mapping[lowered] = value
    return mapping


def wsgi_request_headers(environ: Mapping[str, object]) -> dict[str, str]:
    """Extract request headers from a WSGI environ."""
    request_headers: dict[str, str] = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").lower()
            request_headers[name] = str(value)
    for key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
        if key in environ:
            request_headers[key.replace("_", "-").lower()] = str(environ[key])
    return request_headers


def asgi_request_headers(scope: Mapping[str, object]) -> dict[str, str]:
    """Extract request headers from an ASGI scope."""
    request_headers: dict[str, str] = {}
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, Iterable):
        return request_headers

    for pair in raw_headers:
        try:
            raw_name, raw_value = pair  # type: ignore[misc]
        except (TypeError, ValueError):
            continue
        name = raw_name.decode("latin-1").strip().lower() if isinstance(raw_name, bytes) else str(raw_name).lower()
        value = raw_value.decode("latin-1") if isinstance(raw_value, bytes) else str(raw_value)
        if name in request_headers:
            request_headers[name] = f"{request_headers[name]}, {value}"
        else:
            request_headers[name] = value
    return request_headers


def _replace_header(headers: list[HeaderPair], name: str, value: str | None) -> None:
    lowered = name.lower()
    headers[:] = [(key, val) for key, val in headers if key.lower() != lowered]
    if value:
        headers.append((name, value))


def apply_cache_policy(  # noqa: PLR0913
    headers: list[HeaderPair],
    *,
    status: int,
    method: str,
    path: str,
    request_headers: Mapping[str, str],
    metadata: Mapping[str, object],
    policy: CachePolicy | None,
    configured_cache_control: str | None,
    configured_vary: str | None,
) -> list[HeaderPair]:
    """
    Apply cache-sensitivity rules to a response header list in place.

    This is deliberately protocol-neutral: WSGI and ASGI middleware both
    convert their header containers into this ``(name, value)`` representation
    before calling it, so they produce identical results.
    """
    effective_policy = policy or CachePolicy()
    response_map = response_headers_mapping(headers)
    sensitive = effective_policy.is_sensitive(
        status=status,
        method=method,
        path=path,
        request_headers=request_headers,
        response_headers=response_map,
        metadata=metadata,
    )

    existing_cache_control = header_values(headers, "cache-control")
    existing_vary = header_values(headers, "vary")

    if sensitive:
        overlay = effective_policy.sensitive_cache_control(configured_cache_control)
        merged_cache_control = merge_cache_control_values(existing_cache_control, overlay)
        _replace_header(headers, "Cache-Control", merged_cache_control.header_value)
    elif configured_cache_control is not None and effective_policy.apply_cache_to_public:
        overlay = CacheControl.parse(configured_cache_control)
        merged_cache_control = merge_cache_control_values(existing_cache_control, overlay)
        _replace_header(headers, "Cache-Control", merged_cache_control.header_value)

    vary_additions: list[str] = []
    if configured_vary:
        vary_additions.append(configured_vary)
    if sensitive:
        vary_additions.extend(effective_policy.vary_additions())

    if vary_additions:
        merged_vary = merge_vary_values(existing_vary, vary_additions)
        if merged_vary:
            _replace_header(headers, "Vary", merged_vary)

    return headers


def split_secure_headers(
    items: Iterable[HeaderPair],
) -> tuple[list[HeaderPair], str | None, str | None]:
    """Separate Cache-Control and Vary from the remaining configured headers."""
    others: list[HeaderPair] = []
    cache_control: str | None = None
    vary: str | None = None
    for name, value in items:
        lowered = name.lower()
        if lowered == "cache-control":
            cache_control = value
        elif lowered == "vary":
            vary = value
        else:
            others.append((name, value))
    return others, cache_control, vary
