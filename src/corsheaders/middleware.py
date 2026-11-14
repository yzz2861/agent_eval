from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseBase
from django.utils.cache import patch_vary_headers

from corsheaders.conf import conf
from corsheaders.signals import check_request_enabled

ACCESS_CONTROL_ALLOW_ORIGIN = "access-control-allow-origin"
ACCESS_CONTROL_EXPOSE_HEADERS = "access-control-expose-headers"
ACCESS_CONTROL_ALLOW_CREDENTIALS = "access-control-allow-credentials"
ACCESS_CONTROL_ALLOW_HEADERS = "access-control-allow-headers"
ACCESS_CONTROL_ALLOW_METHODS = "access-control-allow-methods"
ACCESS_CONTROL_MAX_AGE = "access-control-max-age"
ACCESS_CONTROL_REQUEST_METHOD = "access-control-request-method"
ACCESS_CONTROL_REQUEST_HEADERS = "access-control-request-headers"
ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK = "access-control-request-private-network"
ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK = "access-control-allow-private-network"

# Origins that are not scheme://authority URLs but may be explicitly allowed.
SPECIAL_ORIGINS = ("null", "file://")

_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}


def normalize_origin(origin: str) -> str | None:
    """
    Return the normalized form of a syntactically valid Origin header value,
    or None if the value is malformed.

    Only origins with an explicit scheme and authority are accepted; userinfo,
    paths, queries, fragments, whitespace, and control characters are
    rejected. The special values "null" and "file://" are returned as-is so
    they can be matched against explicit configuration only.
    """
    if origin in SPECIAL_ORIGINS:
        return origin
    if not origin or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in origin):
        return None
    try:
        parts = urlsplit(origin)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.path or parts.query or parts.fragment:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    hostname = parts.hostname
    if not hostname:
        return None
    if ":" in hostname:
        # IPv6 literal
        hostname = f"[{hostname}]"
    if port is None or _DEFAULT_PORTS.get(parts.scheme) == port:
        return f"{parts.scheme}://{hostname}"
    return f"{parts.scheme}://{hostname}:{port}"


class CorsMiddleware:
    sync_capable = True
    async_capable = True

    def __init__(
        self,
        get_response: (
            Callable[[HttpRequest], HttpResponseBase]
            | Callable[[HttpRequest], Awaitable[HttpResponseBase]]
        ),
    ) -> None:
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(self.get_response)

        if self.async_mode:
            # Mark the class as async-capable, but do the actual switch

            # inside __call__ to avoid swapping out dunder methods
            markcoroutinefunction(self)

    def __call__(
        self, request: HttpRequest
    ) -> HttpResponseBase | Awaitable[HttpResponseBase]:
        if self.async_mode:
            return self.__acall__(request)
        response: HttpResponseBase | None = self.check_preflight(request)
        if response is None:
            result = self.get_response(request)
            assert isinstance(result, HttpResponseBase)
            response = result
        self.add_response_headers(request, response)
        return response

    async def __acall__(self, request: HttpRequest) -> HttpResponseBase:
        response = self.check_preflight(request)
        if response is None:
            result = self.get_response(request)
            assert not isinstance(result, HttpResponseBase)
            response = await result
        self.add_response_headers(request, response)
        return response

    def check_preflight(self, request: HttpRequest) -> HttpResponseBase | None:
        """
        Generate a response for CORS preflight requests.
        """
        request._cors_enabled = self.is_enabled(request)  # type: ignore [attr-defined]
        if (
            request._cors_enabled  # type: ignore [attr-defined]
            and request.method == "OPTIONS"
            and ACCESS_CONTROL_REQUEST_METHOD in request.headers
        ):
            response = HttpResponse(headers={"content-length": "0"})
            # Preflight responses vary on the requested method and headers as
            # well as the origin, so shared caches cannot reuse one origin's
            # allowance for another.
            patch_vary_headers(
                response,
                (
                    "origin",
                    ACCESS_CONTROL_REQUEST_METHOD,
                    ACCESS_CONTROL_REQUEST_HEADERS,
                ),
            )
            return response
        return None

    def add_response_headers(
        self, request: HttpRequest, response: HttpResponseBase
    ) -> HttpResponseBase:
        """
        Add the respective CORS headers
        """
        enabled = getattr(request, "_cors_enabled", None)
        if enabled is None:
            enabled = self.is_enabled(request)

        if not enabled:
            return response

        patch_vary_headers(response, ("origin",))

        origin = request.headers.get("origin")
        if not origin:
            return response

        normalized_origin = normalize_origin(origin)
        if normalized_origin is None:
            return response

        if (
            not conf.CORS_ALLOW_ALL_ORIGINS
            and not self.origin_found_in_white_lists(normalized_origin)
            and not self.check_signal(request)
        ):
            return response

        if conf.CORS_ALLOW_ALL_ORIGINS and not conf.CORS_ALLOW_CREDENTIALS:
            response[ACCESS_CONTROL_ALLOW_ORIGIN] = "*"
        else:
            response[ACCESS_CONTROL_ALLOW_ORIGIN] = origin

        if conf.CORS_ALLOW_CREDENTIALS:
            response[ACCESS_CONTROL_ALLOW_CREDENTIALS] = "true"

        if len(conf.CORS_EXPOSE_HEADERS):
            response[ACCESS_CONTROL_EXPOSE_HEADERS] = ", ".join(
                conf.CORS_EXPOSE_HEADERS
            )

        if request.method == "OPTIONS":
            requested_method = request.headers.get(ACCESS_CONTROL_REQUEST_METHOD)
            if not requested_method or requested_method in conf.CORS_ALLOW_METHODS:
                response[ACCESS_CONTROL_ALLOW_METHODS] = ", ".join(
                    conf.CORS_ALLOW_METHODS
                )
            if self.requested_headers_allowed(request):
                response[ACCESS_CONTROL_ALLOW_HEADERS] = ", ".join(
                    conf.CORS_ALLOW_HEADERS
                )
            if conf.CORS_PREFLIGHT_MAX_AGE:
                response[ACCESS_CONTROL_MAX_AGE] = str(conf.CORS_PREFLIGHT_MAX_AGE)

        if (
            conf.CORS_ALLOW_PRIVATE_NETWORK
            and request.headers.get(ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK) == "true"
        ):
            response[ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK] = "true"

        return response

    def requested_headers_allowed(self, request: HttpRequest) -> bool:
        """
        Check the Access-Control-Request-Headers preflight header against
        CORS_ALLOW_HEADERS.
        """
        requested = request.headers.get(ACCESS_CONTROL_REQUEST_HEADERS)
        if not requested:
            return True
        allowed = {header.lower() for header in conf.CORS_ALLOW_HEADERS}
        return all(
            header.strip().lower() in allowed for header in requested.split(",")
        )

    def origin_found_in_white_lists(self, normalized_origin: str) -> bool:
        if normalized_origin in SPECIAL_ORIGINS:
            # "null" and "file://" are only allowed when explicitly configured.
            return normalized_origin in conf.CORS_ALLOWED_ORIGINS
        return (
            self._origin_in_exact_whitelist(normalized_origin)
            or self._origin_in_regex_whitelist(normalized_origin)
        )

    def _origin_in_exact_whitelist(self, normalized_origin: str) -> bool:
        return any(
            normalize_origin(allowed_origin) == normalized_origin
            for allowed_origin in conf.CORS_ALLOWED_ORIGINS
        )

    def _origin_in_regex_whitelist(self, normalized_origin: str) -> bool:
        return any(
            re.fullmatch(domain_pattern, normalized_origin)
            for domain_pattern in conf.CORS_ALLOWED_ORIGIN_REGEXES
        )

    def is_enabled(self, request: HttpRequest) -> bool:
        return bool(
            re.match(conf.CORS_URLS_REGEX, request.path_info)
        ) or self.check_signal(request)

    def check_signal(self, request: HttpRequest) -> bool:
        signal_responses = check_request_enabled.send(sender=None, request=request)
        return any(return_value for function, return_value in signal_responses)
