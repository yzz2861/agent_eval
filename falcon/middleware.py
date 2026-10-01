from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Callable, cast, Literal, TYPE_CHECKING, TypeVar, Union

from ._typing import _AReqT
from ._typing import _ARespT
from ._typing import UniversalMiddlewareWithProcessResponse

if TYPE_CHECKING:
    from .asgi.request import Request as AsgiRequest
    from .asgi.response import Response as AsgiResponse
    from .request import Request
    from .response import Response


_T = TypeVar('_T', bound=Callable[..., Any])

_UNSET = object()
_ORIGIN_WILDCARD = '*'
_HEADER_WILDCARD = '*'
_DEFAULT_MAX_AGE = '86400'
_CORS_POLICY_ATTR = 'cors_policy'
_CORS_RESPONDER_POLICY_ATTR = '_falcon_cors_policy'
_DEFAULT_RESPONDER_ATTR = '_falcon_default_responder'
_SAFELISTED_REQUEST_HEADERS = frozenset(
    ('accept', 'accept-language', 'content-language', 'content-type')
)

OriginPolicy = Union[Literal['*'], frozenset[str]]
CredentialsPolicy = Union[Literal['*'], frozenset[str]]
PolicyValue = Union[
    OriginPolicy, CredentialsPolicy, frozenset[str], tuple[str, ...], bool
]
UnsetPolicyValue = Union[object, PolicyValue]


def _normalize_origins(value: str | Iterable[str]) -> OriginPolicy:
    """Normalize an origin allow-list."""
    if value == _ORIGIN_WILDCARD:
        return _ORIGIN_WILDCARD

    if isinstance(value, str):
        value = (value,)

    origins = frozenset(value)
    if _ORIGIN_WILDCARD in origins:
        raise ValueError(
            'The wildcard string "*" may only be passed to allow_origins as a '
            'string literal, not inside an iterable.'
        )
    return origins


def _normalize_credentials(value: str | Iterable[str] | None) -> CredentialsPolicy:
    """Normalize a credentials allow-list."""
    if value is None:
        return frozenset()

    if value == _ORIGIN_WILDCARD:
        return _ORIGIN_WILDCARD

    if isinstance(value, str):
        value = (value,)

    origins = frozenset(value)
    if _ORIGIN_WILDCARD in origins:
        raise ValueError(
            'The wildcard string "*" may only be passed to allow_credentials '
            'as a string literal, not inside an iterable.'
        )
    return origins


def _normalize_header_set(value: object, *, lowercase: bool = True) -> object:
    """Normalize a policy header list."""
    if value is _UNSET or value == _HEADER_WILDCARD:
        return value
    if value is None:
        return ()

    if isinstance(value, str):
        value = (value,)

    return tuple(
        _normalize_header_name(header) if lowercase else header.strip()
        for header in value
    )


def _normalize_method_set(value: object) -> object:
    """Normalize a policy HTTP method list."""
    if value is _UNSET or value is None:
        return value

    if isinstance(value, str):
        value = (value,)

    return frozenset(_normalize_token(method) for method in value)


def _normalize_header_name(value: str) -> str:
    """Normalize an HTTP header name for case-insensitive comparison."""
    return value.strip().lower()


def _normalize_token(value: str | None) -> str:
    """Normalize an HTTP method token."""
    return value.strip().upper() if value is not None else ''


def _parse_header_list(value: str | None) -> tuple[str, ...]:
    """Parse a comma-separated request header list."""
    if not value:
        return ()
    return tuple(
        normalized
        for header in value.split(',')
        if (normalized := _normalize_header_name(header))
    )


def _parse_raw_header_list(value: str | None) -> tuple[str, ...]:
    """Parse a header list while preserving the requested field names."""
    if not value:
        return ()
    return tuple(header.strip() for header in value.split(',') if header.strip())


def _parse_method_list(value: str | None) -> frozenset[str]:
    """Parse a comma-separated HTTP method list."""
    if not value:
        return frozenset()
    return frozenset(
        normalized
        for method in value.split(',')
        if (normalized := _normalize_token(method))
    )


def _origin_allowed(policy: CORSPolicy, origin: str) -> bool:
    """Return whether an origin is allowed by a resolved policy."""
    allowed_origins = cast(OriginPolicy, policy.allow_origins)
    return allowed_origins == _ORIGIN_WILDCARD or origin in allowed_origins


def _credentials_allowed(policy: CORSPolicy, origin: str) -> bool:
    """Return whether credentials are allowed for an origin."""
    allowed_credentials = cast(CredentialsPolicy, policy.allow_credentials)
    return allowed_credentials == _ORIGIN_WILDCARD or origin in allowed_credentials


def _headers_allowed(policy: CORSPolicy, headers: tuple[str, ...]) -> bool:
    """Return whether all requested headers are permitted."""
    allowed_headers = policy.allow_headers
    if allowed_headers == _HEADER_WILDCARD:
        return all(header.lower() != 'authorization' for header in headers)

    allowed = _SAFELISTED_REQUEST_HEADERS | set(cast(tuple[str, ...], allowed_headers))
    return all(header.lower() in allowed for header in headers)


def _allowed_header_names(
    policy: CORSPolicy, headers: tuple[str, ...], credentials_allowed: bool
) -> str | None:
    """Return the header list to publish for an accepted preflight."""
    allowed_headers = policy.allow_headers
    if not headers:
        if allowed_headers == _HEADER_WILDCARD and not credentials_allowed:
            return _HEADER_WILDCARD
        return None

    if allowed_headers == _HEADER_WILDCARD:
        if any(header.lower() == 'authorization' for header in headers):
            return None
        return ', '.join(headers)

    allowed = set(cast(tuple[str, ...], allowed_headers))
    published = tuple(header for header in headers if header.lower() in allowed)
    return ', '.join(published) if published else None


def _intersection_header_sets(
    raw_headers: tuple[str, ...], values: tuple[str | None, ...]
) -> str | None:
    """Return requested headers allowed by every published method policy."""
    if not values or any(value is None for value in values):
        return None

    header_sets = tuple(
        frozenset(_parse_header_list(value)) for value in values if value is not None
    )
    common = header_sets[0].intersection(*header_sets[1:])
    if _HEADER_WILDCARD in common:
        return ', '.join(raw_headers) if raw_headers else _HEADER_WILDCARD

    published = tuple(header for header in raw_headers if header.lower() in common)
    return ', '.join(published) if published else None


def _delete_cors_headers(resp: Response | AsgiResponse) -> None:
    """Remove all CORS response headers."""
    for header in (
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'Access-Control-Expose-Headers',
        'Access-Control-Allow-Methods',
        'Access-Control-Allow-Headers',
        'Access-Control-Max-Age',
        'Access-Control-Allow-Private-Network',
    ):
        resp.delete_header(header)


def _delete_cors_vary(resp: Response | AsgiResponse) -> None:
    """Remove request headers that vary only CORS policy decisions."""
    existing = resp.get_header('Vary')
    if existing is None:
        return

    cors_vary = frozenset(
        (
            'origin',
            'access-control-request-method',
            'access-control-request-headers',
        )
    )
    remaining = tuple(
        name for name in _parse_header_list(existing) if name not in cors_vary
    )
    if remaining:
        resp.set_header('Vary', ', '.join(remaining))
    else:
        resp.delete_header('Vary')


def _append_vary(resp: Response | AsgiResponse, names: tuple[str, ...]) -> None:
    """Merge Vary header names without replacing existing values."""
    existing = _parse_header_list(resp.get_header('Vary'))
    merged = tuple(names) + tuple(
        value
        for value in existing
        if value not in frozenset(_normalize_header_name(name) for name in names)
    )
    resp.set_header('Vary', ', '.join(merged))


def _route_methods(method_map: dict[str, Any]) -> frozenset[str]:
    """Return the methods actually implemented by a routed resource."""
    return frozenset(
        method
        for method, responder in method_map.items()
        if method not in ('OPTIONS', 'WEBSOCKET')
        and not getattr(responder, _DEFAULT_RESPONDER_ATTR, False)
    )


class CORSPolicy:
    """Resource and responder CORS policy.

    Unspecified options inherit from the policy configured on
    :class:`CORSMiddleware`. Attach an instance to a resource class or
    instance through its ``cors_policy`` attribute, or use it to decorate an
    individual responder.

    Keyword Arguments:
        allow_origins: Allowed origins, or ``'*'`` to allow any origin.
        allow_methods: HTTP methods permitted by the policy, or ``None`` to
            permit every method supported by the route.
        allow_headers: Headers permitted in a preflight request, or ``'*'``
            to allow any non-wildcard request header.
        expose_headers: Headers exposed to browser scripts.
        allow_credentials: Origins for which credentials are permitted,
            ``'*'`` for all allowed origins, or ``None`` to disallow them.
        allow_private_network: Whether private network access is permitted.
    """

    allow_origins: UnsetPolicyValue
    allow_methods: UnsetPolicyValue
    allow_headers: UnsetPolicyValue
    expose_headers: UnsetPolicyValue
    allow_credentials: UnsetPolicyValue
    allow_private_network: UnsetPolicyValue

    def __init__(
        self,
        *,
        allow_origins: UnsetPolicyValue = _UNSET,
        allow_methods: str | Iterable[str] | None = _UNSET,
        allow_headers: str | Iterable[str] | None = _UNSET,
        expose_headers: str | Iterable[str] | None = _UNSET,
        allow_credentials: str | Iterable[str] | None = _UNSET,
        allow_private_network: UnsetPolicyValue = _UNSET,
    ) -> None:
        self.allow_origins = allow_origins
        self.allow_methods = _normalize_method_set(allow_methods)
        self.allow_headers = _normalize_header_set(allow_headers)
        self.expose_headers = _normalize_header_set(expose_headers, lowercase=False)
        self.allow_credentials = allow_credentials
        self.allow_private_network = allow_private_network

    def __call__(self, target: _T) -> _T:
        """Attach this policy to a responder or resource class."""
        if isinstance(target, type):
            setattr(target, _CORS_POLICY_ATTR, self)
        else:
            setattr(target, _CORS_RESPONDER_POLICY_ATTR, self)
        return target

    def merged_with(self, default_policy: CORSPolicy) -> CORSPolicy:
        """Return a copy inheriting unset fields from another policy."""
        merged = CORSPolicy()
        for name in (
            'allow_origins',
            'allow_methods',
            'allow_headers',
            'expose_headers',
            'allow_credentials',
            'allow_private_network',
        ):
            value = getattr(self, name)
            if value is _UNSET:
                value = getattr(default_policy, name)
            elif name == 'allow_credentials' and value is None:
                value = _normalize_credentials(value)
            setattr(merged, name, value)
        return merged


class CORSMiddleware(UniversalMiddlewareWithProcessResponse[_AReqT, _ARespT]):
    """CORS Middleware.

    This middleware provides a simple out-of-the box CORS policy, including handling
    of preflighted requests from the browser.

    See also:

    * https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
    * https://www.w3.org/TR/cors/#resource-processing-model

    Note:
        Preflight requests are evaluated using the policy for the responder named by
        ``Access-Control-Request-Method``. The policy on ``on_options`` is not used
        as a substitute for that target policy. Resource preflight responses skip
        ``on_options`` and advertise only the methods supported by both the route
        and the resolved policy.

        Sinks and static routes retain their legacy contract: an OPTIONS responder
        must set ``Allow`` for the preflight request to be accepted.

    Keyword Arguments:
        allow_origins (Union[str, Iterable[str]]): List of origins to allow (case
            sensitive). The string ``'*'`` acts as a wildcard, matching every origin.
            (default ``'*'``).
        expose_headers (Optional[Union[str, Iterable[str]]]): List of additional
            response headers to expose via the ``Access-Control-Expose-Headers``
            header. These headers are in addition to the CORS-safelisted ones:
            ``Cache-Control``, ``Content-Language``, ``Content-Length``,
            ``Content-Type``, ``Expires``, ``Last-Modified``, ``Pragma``.
            (default ``None``).

            See also:
            https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
        allow_credentials (Optional[Union[str, Iterable[str]]]): List of origins
            (case sensitive) for which to allow credentials via the
            ``Access-Control-Allow-Credentials`` header.
            The string ``'*'`` acts as a wildcard, matching every allowed origin,
            while ``None`` disallows all origins. This parameter takes effect only
            if the origin is allowed by the ``allow_origins`` argument.
            (default ``None``).
        allow_private_network (bool):
            If ``True``, the server includes the
            ``Access-Control-Allow-Private-Network`` header in responses to
            CORS preflight (OPTIONS) requests. This indicates that the resource is
            willing to respond to requests from less-public IP address spaces
            (e.g., from public site to private device).
            (default ``False``).

            See also:
            https://wicg.github.io/private-network-access/#private-network-request-heading
        allow_headers (Optional[Union[str, Iterable[str]]]): Headers permitted in a
            preflight request. The string ``'*'`` permits any header other than
            ``Authorization`` when credentials are not allowed. Header names are
            compared case-insensitively (default ``'*'``).
        allow_methods (Optional[Union[str, Iterable[str]]]): HTTP methods permitted
            by the default policy. ``None`` permits every method supported by the
            route (default ``None``).
    """

    allow_origins: OriginPolicy
    allow_credentials: CredentialsPolicy
    default_policy: CORSPolicy

    def __init__(
        self,
        allow_origins: str | Iterable[str] = '*',
        expose_headers: str | Iterable[str] | None = None,
        allow_credentials: str | Iterable[str] | None = None,
        allow_private_network: bool = False,
        allow_headers: str | Iterable[str] | None = '*',
        allow_methods: str | Iterable[str] | None = None,
    ) -> None:
        self.default_policy = CORSPolicy(
            allow_origins=_normalize_origins(allow_origins),
            allow_methods=allow_methods,
            allow_headers=allow_headers,
            expose_headers=expose_headers,
            allow_credentials=_normalize_credentials(allow_credentials),
            allow_private_network=allow_private_network,
        )
        self.allow_origins = cast(OriginPolicy, self.default_policy.allow_origins)
        self.allow_credentials = cast(
            CredentialsPolicy, self.default_policy.allow_credentials
        )

    def process_preflight(
        self,
        req: Request | AsgiRequest,
        resp: Response | AsgiResponse,
        resource: object,
        method_map: dict[str, Any],
    ) -> bool:
        """Validate a preflight request against its target responder.

        Args:
            req: Incoming CORS preflight OPTIONS request.
            resp: Response that will be returned to the client.
            resource: Resource that would handle the target request.
            method_map: Responders mapped to the matched route.

        Returns:
            ``True`` when the OPTIONS responder must be skipped.
        """

        target_method = _normalize_token(
            req.get_header('Access-Control-Request-Method')
        )
        origin = req.get_header('Origin')
        requested_headers = _parse_header_list(
            req.get_header('Access-Control-Request-Headers')
        )
        raw_requested_headers = _parse_raw_header_list(
            req.get_header('Access-Control-Request-Headers')
        )
        route_methods = _route_methods(method_map)
        allowed_methods: list[str] = []
        allowed_policies: list[CORSPolicy] = []
        target_policy: CORSPolicy | None = None

        if origin and target_method in route_methods:
            for method in sorted(route_methods):
                policy = self._resolve_policy(resource, method_map[method])
                if policy.allow_methods is not None:
                    allowed_methods_for_policy = cast(
                        frozenset[str], policy.allow_methods
                    )
                    if method not in allowed_methods_for_policy:
                        continue

                if not _origin_allowed(policy, origin):
                    continue
                if not _headers_allowed(policy, requested_headers):
                    continue

                allowed_methods.append(method)
                allowed_policies.append(policy)
                if method == target_method:
                    target_policy = policy

        resp.status = '200 OK'
        resp.set_header('Content-Length', '0')

        if target_policy is None:
            setattr(req, '_cors_preflight_allowed', False)
            setattr(req, '_cors_preflight_methods', ())
            setattr(req, '_cors_preflight_headers', requested_headers)
            setattr(req, '_cors_preflight_policies', ())
            resp.complete = True
            return True

        setattr(req, '_cors_preflight_allowed', True)
        setattr(req, '_cors_preflight_policy', target_policy)
        setattr(req, '_cors_preflight_methods', tuple(allowed_methods))
        setattr(req, '_cors_preflight_headers', requested_headers)
        setattr(req, '_cors_preflight_raw_headers', raw_requested_headers)
        setattr(req, '_cors_preflight_policies', tuple(allowed_policies))

        resp.set_header('Allow', ', '.join(allowed_methods))
        return True

    def process_response(
        self, req: Request, resp: Response, resource: object, req_succeeded: bool
    ) -> None:
        """Implement the CORS policy for all routes.

        This middleware provides a simple out-of-the box CORS policy,
        including handling of preflighted requests from the browser.

        See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

        See also: https://www.w3.org/TR/cors/#resource-processing-model
        """

        origin = req.get_header('Origin')
        is_preflight = req.method == 'OPTIONS' and bool(
            req.get_header('Access-Control-Request-Method')
        )
        preflight_allowed = getattr(req, '_cors_preflight_allowed', None)
        method_map = getattr(req, '_cors_method_map', {})

        if origin is None:
            return

        if is_preflight and (not req_succeeded or preflight_allowed is False):
            _delete_cors_headers(resp)
            _delete_cors_vary(resp)
            return

        policy = getattr(req, '_cors_preflight_policy', None)
        if not isinstance(policy, CORSPolicy):
            policy = self._response_policy(req, resource, method_map)
        if not _origin_allowed(policy, origin):
            return

        credentials_allowed = _credentials_allowed(policy, origin)
        if resp.get_header('Access-Control-Allow-Origin') is None:
            origin_value = (
                origin
                if credentials_allowed or policy.allow_origins != _ORIGIN_WILDCARD
                else _ORIGIN_WILDCARD
            )
            resp.set_header('Access-Control-Allow-Origin', origin_value)
            if credentials_allowed:
                resp.set_header('Access-Control-Allow-Credentials', 'true')

        if is_preflight:
            if preflight_allowed is None:
                self._process_legacy_preflight_response(req, resp)
                vary_names = [
                    'Access-Control-Request-Method',
                    'Access-Control-Request-Headers',
                ]
                if resp.get_header('Access-Control-Allow-Origin') != _ORIGIN_WILDCARD:
                    vary_names.insert(0, 'Origin')
                _append_vary(resp, tuple(vary_names))
                return

            self._process_preflight_response(req, resp, policy, credentials_allowed)
            vary_names = [
                'Access-Control-Request-Method',
                'Access-Control-Request-Headers',
            ]
            if credentials_allowed or policy.allow_origins != _ORIGIN_WILDCARD:
                vary_names.insert(0, 'Origin')
            _append_vary(resp, tuple(vary_names))
            return

        exposed_headers = cast(tuple[str, ...], policy.expose_headers)
        if exposed_headers:
            resp.set_header('Access-Control-Expose-Headers', ', '.join(exposed_headers))
        if credentials_allowed or policy.allow_origins != _ORIGIN_WILDCARD:
            _append_vary(resp, ('Origin',))

    def _resolve_policy(self, resource: object, responder: object) -> CORSPolicy:
        """Resolve app, resource, and responder policies for a responder."""
        policy = self.default_policy
        resource_policy = getattr(resource, _CORS_POLICY_ATTR, None)
        if isinstance(resource_policy, CORSPolicy):
            policy = resource_policy.merged_with(policy)

        target = responder
        while True:
            target = getattr(target, '__func__', target)
            wrapped_target = getattr(target, '__wrapped__', None)
            if wrapped_target is None:
                break
            target = wrapped_target
        responder_policy = getattr(target, _CORS_RESPONDER_POLICY_ATTR, None)
        if isinstance(responder_policy, CORSPolicy):
            policy = responder_policy.merged_with(policy)

        return policy

    def _response_policy(
        self,
        req: Request | AsgiRequest,
        resource: object,
        method_map: dict[str, Any],
    ) -> CORSPolicy:
        """Resolve the policy for an actual response method."""
        responder = method_map.get(req.method)
        if responder is None:
            return self.default_policy
        return self._resolve_policy(resource, responder)

    def _process_preflight_response(
        self,
        req: Request | AsgiRequest,
        resp: Response | AsgiResponse,
        policy: CORSPolicy,
        credentials_allowed: bool,
    ) -> None:
        """Populate CORS headers on an accepted preflight response."""
        resp.delete_header('Allow')
        allowed_methods = set(getattr(req, '_cors_preflight_methods', ()))

        raw_headers = tuple(getattr(req, '_cors_preflight_raw_headers', ()))
        policies = tuple(
            resolved_policy
            for method, resolved_policy in zip(
                getattr(req, '_cors_preflight_methods', ()),
                getattr(req, '_cors_preflight_policies', ()),
            )
            if method in allowed_methods
        )

        resp.set_header(
            'Access-Control-Allow-Methods', ', '.join(sorted(allowed_methods))
        )
        published_header_sets = tuple(
            _allowed_header_names(resolved_policy, raw_headers, credentials_allowed)
            for resolved_policy in policies
        )
        allowed_headers = _intersection_header_sets(raw_headers, published_header_sets)
        if allowed_headers is not None:
            resp.set_header('Access-Control-Allow-Headers', allowed_headers)
        else:
            resp.delete_header('Access-Control-Allow-Headers')

        resp.set_header('Access-Control-Max-Age', _DEFAULT_MAX_AGE)

        if policy.allow_private_network is True and (
            req.get_header('Access-Control-Request-Private-Network') == 'true'
        ):
            resp.set_header('Access-Control-Allow-Private-Network', 'true')

    def _process_legacy_preflight_response(
        self, req: Request | AsgiRequest, resp: Response | AsgiResponse
    ) -> None:
        """Preserve the Allow-header contract for sinks and static routes."""
        allow = resp.get_header('Allow')
        resp.delete_header('Allow')

        if allow is None:
            _delete_cors_headers(resp)
            return

        resp.set_header('Access-Control-Allow-Methods', allow)
        requested_headers = req.get_header('Access-Control-Request-Headers')
        resp.set_header(
            'Access-Control-Allow-Headers',
            requested_headers if requested_headers is not None else _HEADER_WILDCARD,
        )
        resp.set_header('Access-Control-Max-Age', _DEFAULT_MAX_AGE)

    async def process_response_async(
        self,
        req: AsgiRequest,
        resp: AsgiResponse,
        resource: object,
        req_succeeded: bool,
    ) -> None:
        self.process_response(req, resp, resource, req_succeeded)
