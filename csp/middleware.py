from __future__ import annotations

import base64
import http.client as http_client
import logging
import os
import warnings
from dataclasses import asdict, dataclass
from functools import partial
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPNonceError
from csp.utils import DIRECTIVES_T, build_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

logger = logging.getLogger("csp.render_review")


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

    def process_request(self, request: HttpRequest) -> None:
        nonce = partial(self._make_nonce, request)
        setattr(request, "csp_nonce", CheckableLazyObject(nonce))

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        # Check for debug view
        exempted_debug_codes = (
            http_client.INTERNAL_SERVER_ERROR,
            http_client.NOT_FOUND,
        )
        if response.status_code in exempted_debug_codes and settings.DEBUG:
            return response

        policy_parts = self.get_policy_parts(request=request, response=response)
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

        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
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

        # Once we've written the header, accessing the `request.csp_nonce` will no longer trigger
        # the nonce to be added to the header. Instead we throw an error here to catch this since
        # this has security implications.
        if getattr(request, "_csp_nonce", None) is None:
            setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        return response

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


def _review_policy_scope(request: HttpRequest, response: HttpResponseBase, report_only: bool) -> dict[str, Any]:
    """
    Compare the policy header actually present on the final response with the
    policy dictated by that response's own scope (its ``_csp_*`` attributes and
    the relevant settings), for either the enforced or the report-only policy.
    """
    suffix = "_ro" if report_only else ""
    header_name = HEADER_REPORT_ONLY if report_only else HEADER
    actual = response.headers.get(header_name)

    config = getattr(response, f"_csp_config{suffix}", None)
    update = getattr(response, f"_csp_update{suffix}", None)
    replace = getattr(response, f"_csp_replace{suffix}", None)
    nonce = getattr(request, "_csp_nonce", None)
    scoped_policy = build_policy(config=config, update=update, replace=replace, nonce=nonce, report_only=report_only)

    exempted_debug_codes = (
        http_client.INTERNAL_SERVER_ERROR,
        http_client.NOT_FOUND,
    )
    debug_exempt = response.status_code in exempted_debug_codes and settings.DEBUG
    exempt = getattr(response, f"_csp_exempt{suffix}", False) is not False
    setting_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
    policy_settings = getattr(settings, setting_name, None) or {}
    prefixes = policy_settings.get("EXCLUDE_URL_PREFIXES", None) or ()
    excluded = request.path_info.startswith(tuple(prefixes))

    expected: str | None
    if debug_exempt:
        expected, origin = None, "debug-exempt"
    elif not scoped_policy:
        expected, origin = None, "no-policy"
    elif exempt:
        expected, origin = None, "exempt"
    elif excluded:
        expected, origin = None, "excluded-prefix"
    else:
        expected = scoped_policy
        if config is not None:
            origin = "config"
        elif replace is not None:
            origin = "replace"
        elif update is not None:
            origin = "update"
        else:
            origin = "settings"

    if actual is None:
        scope_valid = expected is None
        source = origin if expected is None else "missing"
    else:
        scope_valid = expected == actual
        source = origin if scope_valid else "foreign"

    return {"header": actual, "source": source, "scope_valid": scope_valid}


def review_final_response(request: HttpRequest, response: HttpResponseBase) -> dict[str, Any]:
    """
    Review the CSP headers on the final response of a request.

    Both the enforced and the report-only policy are validated against the
    scope of the last-generated response, so a policy carried over from an
    earlier response (e.g. an approval object that followed an internal
    dispatch onto a shared error page) is reported as ``foreign``.
    """
    is_redirect = 300 <= response.status_code < 400
    return {
        "path": request.path_info,
        "status": response.status_code,
        "enforced": _review_policy_scope(request, response, report_only=False),
        "report_only": _review_policy_scope(request, response, report_only=True),
        # A redirect only leaves this auditable decision behind. The record
        # lives on this request/response pair alone, so it can never
        # authorize a subsequent request.
        "decision_only": is_redirect,
        "authorizes_followup": False,
    }


class CSPRenderReviewMiddleware(MiddlewareMixin):
    """
    Optional render review for the policies written by ``CSPMiddleware``.

    Add it before ``csp.middleware.CSPMiddleware`` in ``MIDDLEWARE`` so that
    its ``process_response`` runs after the CSP headers have been written::

        MIDDLEWARE = [
            "csp.middleware.CSPRenderReviewMiddleware",
            "csp.middleware.CSPMiddleware",
            ...
        ]

    For every request it records, on ``response.csp_review`` and in the
    ``csp.render_review`` logger, which enforced and report-only policy the
    final response actually carries and where each policy came from
    (``settings``, ``config``, ``replace``, ``update``, ``exempt``,
    ``excluded-prefix``, ``debug-exempt``, ``no-policy``, ``missing`` or
    ``foreign``). Redirect responses only leave this auditable decision
    behind; nothing is persisted that could authorize subsequent requests.
    """

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        record = review_final_response(request, response)
        setattr(response, "csp_review", record)
        logger.info("CSP render review: %s", record)
        return response
