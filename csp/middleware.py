from __future__ import annotations

import base64
import hashlib
import http.client as http_client
import os
import warnings
from dataclasses import asdict, dataclass
from functools import partial
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.cache import caches
from django.utils.cache import patch_cache_control
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty
from django.utils.http import split_directive_names

from csp.constants import (
    CACHE_FINGERPRINT_CACHE_ALIAS,
    CACHE_FINGERPRINT_KEY_PREFIX,
    HEADER,
    HEADER_REPORT_ONLY,
)
from csp.exceptions import CSPNonceError
from csp.utils import DIRECTIVES_T, build_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


@dataclass
class PolicyParts:
    # A dataclass is used rather than a namedtuple so that the attributes are mutable
    config: DIRECTIVES_T | None = None
    update: DIRECTIVES_T | None = None
    replace: DIRECTIVES_T | None = None
    nonce: str | None = None


class CheckableLazyObject(SimpleLazyObject):
    """A SimpleLazyObject where bool(obj) returns True if no longer lazy"""

    def __bool__(self) -> bool:
        """
        If the wrapped function has been evaluated, return True.
        If the wrapped function has not been evalated, return False.
        """
        return getattr(self, "_wrapped") is not empty


def _policy_contains_nonce(policy_parts: PolicyParts, report_only: bool = False) -> bool:
    """
    Return True if the resolved policy embeds the request nonce.

    The check runs against the built policy string rather than the raw parts
    because the NONCE sentinel may come either from the global settings-backed
    policy or from a per-view decorator override. When no nonce was generated
    the sentinel is stripped from the string, so this is only True for
    responses whose header actually carries the per-request value.
    """
    return "'nonce-" in build_policy(**asdict(policy_parts), report_only=report_only)


def _has_cache_control_directive(response: HttpResponseBase, directive: str) -> bool:
    """Check a Cache-Control directive name, ignoring any qualified value."""
    return directive in split_directive_names(response.get("Cache-Control", ""))


class CSPMiddleware(MiddlewareMixin):
    """
    Implements the Content-Security-Policy response header, which
    conforming user-agents can use to restrict the permitted sources
    of various content.

    See http://www.w3.org/TR/CSP/

    Can be customised by subclassing and extending the get_policy_parts method.
    """

    def _make_nonce(self, request: HttpRequest) -> str:
        # Ensure that any subsequent calls to request.csp_nonce return the same value
        stored_nonce = getattr(request, "_csp_nonce", None)
        if isinstance(stored_nonce, str):
            return stored_nonce
        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        setattr(request, "_csp_nonce", nonce)
        return nonce

    @staticmethod
    def _csp_nonce_post_response() -> None:
        raise CSPNonceError(
            "The 'csp_nonce' attribute is not available after the CSP header has been written. Consider adjusting your MIDDLEWARE order."
        )

    def process_request(self, request: HttpRequest) -> HttpResponseBase | None:
        # The nonce stays lazy: it is only generated when the view or a
        # template reads `request.csp_nonce`.
        setattr(request, "csp_nonce", CheckableLazyObject(partial(self._make_nonce, request)))
        # A shared-cache hit short-circuits the view. Validate the stored
        # response against the current policy before it can be reused.
        cached_response = self.get_cached_response(request)
        if cached_response is not None:
            request._csp_cached_response = cached_response
            return cached_response
        return None

    def get_cached_response(self, request: HttpRequest) -> HttpResponseBase | None:
        """
        Return a shared-cache response only when the stored policy still matches.

        Responses cached before a CSP policy change carry the fingerprint of the
        policy they were built with. When the current policy fingerprint differs,
        the stale entry is discarded and the request is rebuilt.
        """
        cache = caches[CACHE_FINGERPRINT_CACHE_ALIAS]
        cached = cache.get(self._fingerprint_cache_key(request))
        if cached is None:
            return None
        cached_response, cached_fingerprint = cached
        if cached_fingerprint != self.get_policy_fingerprint(request):
            # The policy changed since this response was cached: treat the entry
            # as a miss and drop it so the rebuilt response is stored fresh.
            cache.delete(self._fingerprint_cache_key(request))
            return None
        return cached_response

    @staticmethod
    def _fingerprint_cache_key(request: HttpRequest) -> str:
        return f"{CACHE_FINGERPRINT_KEY_PREFIX}{request.build_absolute_uri()}"

    def get_policy_fingerprint(self, request: HttpRequest) -> str:
        """
        Return a stable fingerprint of the settings-backed CSP policies.

        Both the enforced and report-only settings take part because either one
        changing must invalidate a previously cached response. The fingerprint is
        computed from settings alone so it is identical before the view runs
        (cache lookup) and after the response is built (cache storage).
        Per-view decorator overrides do not affect the fingerprint; responses
        carrying a request-specific nonce are stored with ``no-store`` instead.
        """
        payload = repr(
            (
                getattr(settings, "CONTENT_SECURITY_POLICY", None),
                getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None),
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        # Check for debug view
        exempted_debug_codes = (
            http_client.INTERNAL_SERVER_ERROR,
            http_client.NOT_FOUND,
        )
        if response.status_code in exempted_debug_codes and settings.DEBUG:
            return response

        policy_parts = self.get_policy_parts(request=request, response=response)
        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)

        # The nonce is request-specific: it exists only if the view or a template
        # read the lazy `request.csp_nonce` while building the body.
        nonce_used = getattr(request, "_csp_nonce", None) is not None

        csp = build_policy(**asdict(policy_parts))
        if csp:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt", False) is False
            no_header = HEADER not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER] = csp
            # A response whose enforced policy embeds the nonce cannot be reused:
            # the body and its header are only valid together for this request.
            if nonce_used and _policy_contains_nonce(policy_parts):
                self._mark_non_cacheable(response)

        csp_ro = build_policy(**asdict(policy_parts_ro), report_only=True)
        if csp_ro:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt_ro", False) is False
            no_header = HEADER_REPORT_ONLY not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER_REPORT_ONLY] = csp_ro
            # The report-only header can embed the nonce independently of the
            # enforced header and is just as request-specific.
            if nonce_used and _policy_contains_nonce(policy_parts_ro, report_only=True):
                self._mark_non_cacheable(response)

        self.update_cached_response(request=request, response=response)

        # Once we have written the header, accessing `request.csp_nonce` can no
        # longer feed the nonce into the header. Reading an un-generated nonce at
        # this point is a programming error (headers were decided first, nonce
        # accessed afterwards), so raise rather than silently diverging.
        if getattr(request, "_csp_nonce", None) is None:
            setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        return response

    @staticmethod
    def _mark_non_cacheable(response: HttpResponseBase) -> None:
        # `no-store` keeps the response out of Django's UpdateCacheMiddleware and
        # any other conforming shared cache, so a nonce-bound body/header pair can
        # never be split and reassembled on another request.
        patch_cache_control(response, no_store=True)

    def update_cached_response(self, request: HttpRequest, response: HttpResponseBase) -> None:
        """
        Store the response in the shared cache only when it is safe to reuse.

        Nonced responses carry ``no-store`` and are skipped, together with any
        response already marked private/no-cache/no-store and responses exempted
        from CSP. Everything else is stored alongside the current policy
        fingerprint, so a later policy change invalidates it on the next lookup.
        """
        if _has_cache_control_directive(response, "no-store"):
            return
        if _has_cache_control_directive(response, "no-cache"):
            return
        if _has_cache_control_directive(response, "private"):
            return
        if getattr(response, "_csp_exempt", False) or getattr(response, "_csp_exempt_ro", False):
            return
        caches[CACHE_FINGERPRINT_CACHE_ALIAS].set(
            self._fingerprint_cache_key(request),
            (response, self.get_policy_fingerprint(request)),
        )

    def build_policy(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts = self.get_policy_parts(request=request, response=response, report_only=False)
        return build_policy(**asdict(policy_parts))

    def build_policy_ro(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        return build_policy(**asdict(policy_parts_ro), report_only=True)

    def get_policy_parts(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool = False,
    ) -> PolicyParts:
        if report_only:
            config = getattr(response, "_csp_config_ro", None)
            update = getattr(response, "_csp_update_ro", None)
            replace = getattr(response, "_csp_replace_ro", None)
        else:
            config = getattr(response, "_csp_config", None)
            update = getattr(response, "_csp_update", None)
            replace = getattr(response, "_csp_replace", None)

        nonce = getattr(request, "_csp_nonce", None)

        return PolicyParts(config, update, replace, nonce)
