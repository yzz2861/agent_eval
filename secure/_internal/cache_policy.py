from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch
import inspect
from typing import Protocol

from ..headers.cache_control import CacheControl, _split_cache_control_value
from ..headers.vary import Vary, split_vary_value

HeaderMap = Mapping[str, str]
Metadata = Mapping[str, object]

_STATUS_CLASS_TOKEN_LENGTH = 3
_STATUS_RANGE_LENGTH = 2

# Content types that are normally safe to cache in shared caches.
DEFAULT_PUBLIC_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/font-woff",
        "application/javascript",
        "application/vnd.ms-fontobject",
        "application/wasm",
        "font/otf",
        "font/ttf",
        "font/woff",
        "font/woff2",
        "image/avif",
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/svg+xml",
        "image/vnd.microsoft.icon",
        "image/webp",
        "text/css",
        "text/javascript",
        "video/mp4",
        "video/webm",
        "audio/mpeg",
        "audio/ogg",
    }
)

# Content types that commonly contain user-specific data.
DEFAULT_SENSITIVE_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/json",
        "application/ld+json",
        "application/xhtml+xml",
        "application/xml",
        "text/html",
        "text/plain",
        "text/xml",
    }
)

DEFAULT_STATIC_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".avif",
        ".css",
        ".eot",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".mjs",
        ".cjs",
        ".map",
        ".mp3",
        ".mp4",
        ".ogg",
        ".otf",
        ".png",
        ".svg",
        ".ttf",
        ".wasm",
        ".webm",
        ".webp",
        ".woff",
        ".woff2",
    }
)

DEFAULT_SENSITIVE_MARKER_KEYS: tuple[str, ...] = (
    "secure.sensitive",
    "secure.cache.sensitive",
    "cache.sensitive",
    "cache_control.sensitive",
    "sensitive",
    "no_store",
    "no-store",
)

DEFAULT_PUBLIC_MARKER_KEYS: tuple[str, ...] = (
    "secure.public",
    "secure.cache.public",
    "cache.public",
    "cache_public",
    "cache-public",
    "public",
)

DEFAULT_ROUTE_TAGS: frozenset[str] = frozenset(
    {
        "cache-sensitive",
        "no-store",
        "private",
        "sensitive",
        "secure",
    }
)

DEFAULT_PUBLIC_ROUTE_TAGS: frozenset[str] = frozenset({"cache-public", "public", "static"})


class CachePredicate(Protocol):
    def __call__(self, **context: object) -> bool: ...


def _normalize_content_type(value: str | None) -> str:
    if not value:
        return ""
    normalized = value.split(";", 1)[0].strip().lower()
    aliases = {
        "css": "text/css",
        "html": "text/html",
        "javascript": "application/javascript",
        "js": "application/javascript",
        "json": "application/json",
        "text": "text/plain",
        "xml": "application/xml",
    }
    return aliases.get(normalized, normalized)


def _matches_pattern(candidate: str, pattern: str) -> bool:
    if candidate == pattern or fnmatch(candidate, pattern):
        return True
    if any(char in pattern for char in "*?[]"):
        return False
    prefix = pattern.rstrip("/")
    return bool(prefix) and candidate.startswith(f"{prefix}/")


def _normalize_content_types(values: object) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, str):
        items: Iterable[object] = (values,)
    else:
        items = values  # type: ignore[assignment]
    return frozenset(_normalize_content_type(str(item)) for item in items if str(item).strip())


def _normalize_statuses(values: object) -> frozenset[int] | None:
    if values is None:
        return None
    if isinstance(values, (int, str)):
        items: Iterable[object] = (values,)
    else:
        items = values  # type: ignore[assignment]

    statuses: set[int] = set()
    for item in items:
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            statuses.add(item)
            continue
        if isinstance(item, str):
            token = item.strip().lower()
            if len(token) == _STATUS_CLASS_TOKEN_LENGTH and token.endswith("xx") and token[0].isdigit():
                start = int(token[0]) * 100
                statuses.update(range(start, start + 100))
                continue
            if token.isdigit():
                statuses.add(int(token))
                continue
        if isinstance(item, (tuple, list)) and len(item) == _STATUS_RANGE_LENGTH:
            first, last = item
            if isinstance(first, int) and isinstance(last, int):
                statuses.update(range(first, last + 1))
    return frozenset(statuses)


def _normalize_strings(values: object) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        return (values.strip().lower(),) if values.strip() else ()
    if isinstance(values, Mapping):
        return tuple(str(key).strip().lower() for key in values if str(key).strip())
    return tuple(str(item).strip().lower() for item in values if str(item).strip())


def _normalize_extensions(values: object) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, str):
        items: Iterable[object] = (values,)
    else:
        items = values  # type: ignore[assignment]
    result: set[str] = set()
    for item in items:
        token = str(item).strip().lower()
        if not token:
            continue
        result.add(token if token.startswith(".") else f".{token}")
    return frozenset(result)


def _normalize_tags(values: object) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, str):
        items: Iterable[object] = (values,)
    else:
        items = values  # type: ignore[assignment]
    return frozenset(str(item).strip().lower() for item in items if str(item).strip())


def _route_truthiness(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "sensitive", "private", "no-store"}:
            return True
        if lowered in {"0", "false", "no", "off", "public"}:
            return False
    if value is None:
        return None
    return True


def _is_sensitive_route_object(  # noqa: PLR0911, PLR0912
    route: object,
    route_tags: frozenset[str],
    public_route_tags: frozenset[str] = DEFAULT_PUBLIC_ROUTE_TAGS,
) -> bool | None:
    if isinstance(route, Mapping):
        for key in DEFAULT_SENSITIVE_MARKER_KEYS:
            if key in route:
                marker = _route_truthiness(route.get(key))
                if marker is not None:
                    return marker
        for key in DEFAULT_PUBLIC_MARKER_KEYS:
            if key in route:
                marker = _route_truthiness(route.get(key))
                if marker is not None:
                    return not marker
        tags = route.get("tags")
        if tags and any(str(tag).strip().lower() in public_route_tags for tag in tags):
            return False
        if tags and any(str(tag).strip().lower() in route_tags for tag in tags):
            return True
        endpoint = route.get("endpoint")
        if endpoint is not None and endpoint is not route:
            return _is_sensitive_route_object(endpoint, route_tags, public_route_tags)
        return None

    for attr in ("cache_sensitive", "cache_control_sensitive", "sensitive", "no_store", "private"):
        marker = _route_truthiness(getattr(route, attr, None))
        if marker is not None:
            return marker

    for attr in ("cache_public", "public", "static"):
        public_marker = _route_truthiness(getattr(route, attr, None))
        if public_marker is not None:
            return not public_marker

    tags = getattr(route, "tags", None)
    if tags and any(str(tag).strip().lower() in public_route_tags for tag in tags):
        return False
    if tags and any(str(tag).strip().lower() in route_tags for tag in tags):
        return True

    endpoint = getattr(route, "endpoint", None)
    if endpoint is not None and endpoint is not route:
        return _is_sensitive_route_object(endpoint, route_tags, public_route_tags)
    return None


def _user_is_authenticated(metadata: Metadata, request_headers: HeaderMap) -> bool:  # noqa: PLR0911, PLR0912
    for key in ("secure.authenticated", "authenticated", "auth.authenticated"):
        if key in metadata:
            marker = _route_truthiness(metadata.get(key))
            if marker is not None:
                return marker

    if request_headers.get("authorization"):
        return True
    if metadata.get("REMOTE_USER"):
        return True
    if metadata.get("remote_user"):
        return True

    user = metadata.get("user")
    if user is not None:
        is_authenticated = getattr(user, "is_authenticated", None)
        if callable(is_authenticated):
            return bool(is_authenticated())
        if isinstance(is_authenticated, bool):
            return is_authenticated
        return bool(user)

    auth = metadata.get("auth")
    if auth is not None:
        return bool(auth)

    session = metadata.get("session")
    if session:
        return True

    state = metadata.get("state")
    if isinstance(state, Mapping) and state.get("user") is not None:
        user = state["user"]
        is_authenticated = getattr(user, "is_authenticated", None)
        if callable(is_authenticated):
            return bool(is_authenticated())
        if isinstance(is_authenticated, bool):
            return is_authenticated
        return bool(user)

    return False


def _invoke_predicate(  # noqa: PLR0913
    predicate: CachePredicate | None,
    *,
    status: int,
    method: str,
    path: str,
    request_headers: HeaderMap,
    response_headers: HeaderMap,
    metadata: Metadata,
) -> bool:
    if predicate is None:
        return False

    context: dict[str, object] = {
        "status": status,
        "status_code": status,
        "method": method,
        "path": path,
        "request_headers": request_headers,
        "response_headers": response_headers,
        "metadata": metadata,
        "headers": request_headers,
        "content_type": _normalize_content_type(response_headers.get("content-type")),
        "environ": metadata,
        "scope": metadata,
        "request": metadata,
        "response": response_headers,
    }
    try:
        signature = inspect.signature(predicate)
    except (TypeError, ValueError):
        return bool(predicate(**context))

    parameters = signature.parameters.values()
    if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters):
        return bool(predicate(**context))
    if any(
        parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.POSITIONAL_ONLY)
        for parameter in parameters
    ):
        return bool(predicate(status, method, path, request_headers, response_headers, metadata))  # type: ignore[call-arg]

    kwargs = {
        name: context[name]
        for name, parameter in signature.parameters.items()
        if name in context and parameter.kind is not inspect.Parameter.POSITIONAL_ONLY
    }
    return bool(predicate(**kwargs))  # type: ignore[call-arg]


@dataclass
class CachePolicy:
    """
    Decide which responses must not be stored by shared caches.

    A response is sensitive when any configured signal matches it:

    * a route marker (``scope["sensitive"] = True``, a route ``no_store``
      attribute, or a route tag such as ``"sensitive"``);
    * an explicit status-code rule;
    * an authenticated request;
    * a sensitive response content type;
    * a caller-supplied predicate.

    Public static content (JavaScript, CSS, images, fonts, and similar assets)
    keeps the application's existing caching headers. An explicit route marker
    can override that behavior.

    The default sensitive baseline is ``no-store, private, max-age=0``. An
    optional ``cache_control`` overlay is merged with that baseline, never
    replacing stricter directives already present on the response.
    """

    statuses: frozenset[int] | None = None
    sensitive_when_authenticated: bool = True
    content_types: frozenset[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_CONTENT_TYPES)
    public_content_types: frozenset[str] = field(default_factory=lambda: DEFAULT_PUBLIC_CONTENT_TYPES)
    routes: tuple[str, ...] = ()
    route_tags: frozenset[str] = field(default_factory=lambda: DEFAULT_ROUTE_TAGS)
    public_route_tags: frozenset[str] = field(default_factory=lambda: DEFAULT_PUBLIC_ROUTE_TAGS)
    static_extensions: frozenset[str] = field(default_factory=lambda: DEFAULT_STATIC_EXTENSIONS)
    predicate: CachePredicate | None = None
    default_sensitive: bool = False
    enabled: bool = True
    cache_control: CacheControl | str | None = None
    vary: Vary | str | Iterable[str] | None = None
    apply_cache_to_public: bool = False
    _route_rules: dict[str, bool] = field(default_factory=dict, repr=False)
    _unknown_options: dict[str, object] = field(default_factory=dict, repr=False)
    _status_matcher: frozenset[int] | None = field(default=None, repr=False)
    _status_predicate: CachePredicate | None = field(default=None, repr=False)

    def __init__(self, **kwargs: object) -> None:
        aliases = {
            "status": "statuses",
            "status_code": "statuses",
            "status_codes": "statuses",
            "sensitive_status": "statuses",
            "sensitive_statuses": "statuses",
            "sensitive_status_codes": "statuses",
            "authenticated": "sensitive_when_authenticated",
            "auth": "sensitive_when_authenticated",
            "auth_required": "sensitive_when_authenticated",
            "sensitive_on_auth": "sensitive_when_authenticated",
            "sensitive_if_authenticated": "sensitive_when_authenticated",
            "sensitive_auth": "sensitive_when_authenticated",
            "sensitive_when_authenticated": "sensitive_when_authenticated",
            "content_type": "content_types",
            "content_types": "content_types",
            "sensitive_content_types": "content_types",
            "sensitive_types": "content_types",
            "route": "routes",
            "routes": "routes",
            "sensitive_routes": "routes",
            "sensitive_route_names": "routes",
            "route_patterns": "routes",
            "route_names": "routes",
            "sensitive_paths": "routes",
            "tags": "route_tags",
            "route_tags": "route_tags",
            "sensitive_tags": "route_tags",
            "public_tags": "public_route_tags",
            "public_route_tags": "public_route_tags",
            "static_tags": "public_route_tags",
            "public_content_types": "public_content_types",
            "static_content_types": "public_content_types",
            "public_types": "public_content_types",
            "static_extensions": "static_extensions",
            "public_extensions": "static_extensions",
            "predicate": "predicate",
            "is_sensitive": "predicate",
            "classifier": "predicate",
            "default": "default_sensitive",
            "default_sensitive": "default_sensitive",
            "enabled": "enabled",
            "sensitive": "default_sensitive",
            "cache_control": "cache_control",
            "cache": "cache_control",
            "sensitive_cache_control": "cache_control",
            "sensitive_directives": "cache_control",
            "vary": "vary",
            "apply_cache_to_public": "apply_cache_to_public",
            "cache_to_public": "apply_cache_to_public",
        }

        values: dict[str, object] = {
            "statuses": None,
            "sensitive_when_authenticated": True,
            "content_types": DEFAULT_SENSITIVE_CONTENT_TYPES,
            "public_content_types": DEFAULT_PUBLIC_CONTENT_TYPES,
            "routes": (),
            "route_tags": DEFAULT_ROUTE_TAGS,
            "public_route_tags": DEFAULT_PUBLIC_ROUTE_TAGS,
            "static_extensions": DEFAULT_STATIC_EXTENSIONS,
            "predicate": None,
            "default_sensitive": False,
            "cache_control": None,
            "vary": None,
            "apply_cache_to_public": False,
            "enabled": True,
        }

        unknown: dict[str, object] = {}
        for key, value in kwargs.items():
            canonical = aliases.get(key)
            if canonical is None:
                unknown[key] = value
            else:
                values[canonical] = value

        route_rules: dict[str, bool] = {}
        raw_routes = values["routes"]
        if isinstance(raw_routes, Mapping):
            route_rules = {
                str(pattern).strip().lower(): bool(sensitive)
                for pattern, sensitive in raw_routes.items()
                if str(pattern).strip()
            }
            values["routes"] = tuple(route_rules)

        if callable(values["statuses"]):
            self.statuses = None
            self._status_matcher = None
            self._status_predicate = values["statuses"]  # type: ignore[assignment]
        else:
            self.statuses = _normalize_statuses(values["statuses"])
            self._status_matcher = self.statuses
            self._status_predicate = None
        self.sensitive_when_authenticated = bool(values["sensitive_when_authenticated"])
        self.content_types = _normalize_content_types(values["content_types"])
        self.public_content_types = _normalize_content_types(values["public_content_types"])
        self.routes = _normalize_strings(values["routes"])
        self.route_tags = _normalize_tags(values["route_tags"])
        self.public_route_tags = _normalize_tags(values["public_route_tags"])
        self.static_extensions = _normalize_extensions(values["static_extensions"])
        self.predicate = values["predicate"]  # type: ignore[assignment]
        self.default_sensitive = bool(values["default_sensitive"])
        self.enabled = bool(values["enabled"])
        self.cache_control = values["cache_control"]  # type: ignore[assignment]
        self.vary = values["vary"]  # type: ignore[assignment]
        self.apply_cache_to_public = bool(values["apply_cache_to_public"])
        self._route_rules = route_rules
        self._unknown_options = unknown

    # -------------------------------------------------------------------------
    # Classification
    # -------------------------------------------------------------------------

    def is_sensitive(  # noqa: PLR0911, PLR0912, PLR0913
        self,
        status: int,
        method: str = "",
        path: str = "",
        request_headers: HeaderMap | None = None,
        response_headers: HeaderMap | None = None,
        metadata: Metadata | None = None,
    ) -> bool:
        """Return ``True`` when the response must not be stored by shared caches."""
        if not self.enabled:
            return False
        request_headers = {str(key).lower(): str(value) for key, value in (request_headers or {}).items()}
        response_headers = {str(key).lower(): str(value) for key, value in (response_headers or {}).items()}
        metadata = metadata or {}
        path = path or ""
        lowered_path = path.split("?", 1)[0].lower()

        route = metadata.get("route") if isinstance(metadata, Mapping) else None
        if route is None and isinstance(metadata, Mapping):
            route = metadata.get("endpoint")
        route_marker = (
            _is_sensitive_route_object(route, self.route_tags, self.public_route_tags) if route is not None else None
        )

        for key in DEFAULT_SENSITIVE_MARKER_KEYS:
            if isinstance(metadata, Mapping) and key in metadata:
                marker = _route_truthiness(metadata.get(key))
                if marker is not None:
                    route_marker = True if marker else route_marker

        for key in DEFAULT_PUBLIC_MARKER_KEYS:
            if isinstance(metadata, Mapping) and key in metadata:
                marker = _route_truthiness(metadata.get(key))
                if marker is not None:
                    return not marker

        if route_marker is not None:
            return route_marker

        route_name = self._route_name(metadata, route)
        route_match = self._match_route(route_name, lowered_path)
        if route_match is not None:
            return route_match

        if self._is_static_path(lowered_path):
            return False

        content_type = _normalize_content_type(response_headers.get("content-type"))
        if content_type and content_type in self.public_content_types:
            return False

        status_is_configured = self._status_matcher is not None or self._status_predicate is not None
        if self._status_matcher is not None and status in self._status_matcher:
            return True
        if self._status_predicate is not None and bool(self._status_predicate(status)):
            return True

        if self.sensitive_when_authenticated and _user_is_authenticated(metadata, request_headers):
            return True

        if content_type and content_type in self.content_types and not status_is_configured:
            return True

        if _invoke_predicate(
            self.predicate,
            status=status,
            method=method,
            path=path,
            request_headers=request_headers,
            response_headers=response_headers,
            metadata=metadata,
        ):
            return True

        return self.default_sensitive

    def _route_name(self, metadata: Metadata, route: object) -> str:
        if isinstance(metadata, Mapping):
            for key in ("route_name", "endpoint_name", "view_name"):
                value = metadata.get(key)
                if isinstance(value, str) and value:
                    return value.lower()
        if route is not None:
            name = getattr(route, "name", None)
            if isinstance(name, str) and name:
                return name.lower()
            if isinstance(route, Mapping) and isinstance(route.get("name"), str):
                return str(route["name"]).lower()
        return ""

    def _match_route(self, route_name: str, path: str) -> bool | None:
        candidates = [route_name, path]
        for pattern, sensitive in self._route_rules.items():
            if any(_matches_pattern(candidate, pattern) for candidate in candidates if candidate):
                return sensitive
        if route_name:
            for pattern in self.routes:
                if _matches_pattern(route_name, pattern):
                    return True
        if path:
            for pattern in self.routes:
                if _matches_pattern(path, pattern):
                    return True
        return None

    def _is_static_path(self, path: str) -> bool:
        return any(path.endswith(extension) for extension in self.static_extensions)

    # -------------------------------------------------------------------------
    # Header construction
    # -------------------------------------------------------------------------

    def sensitive_cache_control(self, configured: CacheControl | str | None = None) -> CacheControl:
        """Build the merged sensitive Cache-Control value."""
        merged = CacheControl().sensitive()
        for overlay in (self.cache_control, configured):
            if overlay is None:
                continue
            merged.merge(overlay)
        return merged

    def vary_additions(self) -> list[str]:
        """Return the configured ``Vary`` field names for sensitive responses."""
        return _vary_values(self.vary)


def _vary_values(value: Vary | str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Vary):
        return [value.header_value] if value.header_value else []
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(item) for item in value if str(item).strip()]


# Friendly aliases for callers who describe the concept rather than the class.
SensitiveCachePolicy = CachePolicy
CacheSensitivity = CachePolicy
SensitiveResponsePolicy = CachePolicy


def merge_cache_control_values(existing_values: list[str], overlay: CacheControl) -> CacheControl:
    """Merge one or more existing header values into a sensitive overlay."""
    merged = CacheControl()
    merged._directives = dict(overlay._directives)
    merged._extras = list(overlay._extras)
    for value in existing_values:
        if value.strip():
            merged.merge(value)
    merged._discard_conflicting_relaxations()
    return merged


def split_header_values(value: str) -> list[str]:
    """Split a merged header value for callers that need individual directives."""
    return _split_cache_control_value(value)


def split_vary_fields(value: str) -> list[str]:
    """Split a ``Vary`` value into field names."""
    return split_vary_value(value)


__all__ = [
    "DEFAULT_PUBLIC_CONTENT_TYPES",
    "DEFAULT_ROUTE_TAGS",
    "DEFAULT_SENSITIVE_CONTENT_TYPES",
    "DEFAULT_STATIC_EXTENSIONS",
    "CachePolicy",
    "CachePredicate",
    "CacheSensitivity",
    "SensitiveCachePolicy",
    "SensitiveResponsePolicy",
    "merge_cache_control_values",
]
