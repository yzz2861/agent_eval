from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from django.http import HttpRequest

from csp.exceptions import CSPReportEndpointError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

# Directives whose values name reporting endpoints and therefore need validation.
REPORT_DIRECTIVES = ("report-uri", "report-to")

# Policy-level setting holding origins that are explicitly allowed as
# reporting endpoints, e.g. ``REPORT_ALLOWLIST = ["https://reports.example.com"]``.
ALLOWLIST_SETTING = "REPORT_ALLOWLIST"


def _as_list(value: object) -> list[str]:
    """Normalise a directive value into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(item) for item in value]
    return [str(value)]


def _origin_of(url: str) -> str:
    """Return the ``scheme://host[:port]`` origin for an absolute URL."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def normalize_allowlist(allowlist: Iterable[str] | None) -> frozenset[str]:
    """Normalise configured allowlist entries into a set of https origins."""
    if not allowlist:
        return frozenset()
    origins: set[str] = set()
    for entry in allowlist:
        parsed = urlsplit(str(entry))
        if parsed.scheme != "https" or not parsed.netloc:
            continue
        origins.add(urlunsplit(("https", parsed.netloc, "", "", "")))
    return frozenset(origins)


def _is_relative_endpoint(endpoint: str) -> bool:
    """Relative references are same-origin by construction.

    A scheme-relative reference (//host/path) has no scheme, even though
    urlsplit populates its netloc, so it is treated as relative and
    validated against the request scheme separately.
    """
    return urlsplit(endpoint).scheme == ""


def _is_scheme_relative(endpoint: str) -> bool:
    """Scheme-relative references (``//host/path``) carry no scheme."""
    return endpoint.startswith("//")


def is_allowed_report_endpoint(
    endpoint: str,
    request: HttpRequest | None = None,
    allowed_origins: Sequence[str] | frozenset[str] | None = None,
) -> bool:
    """Return whether a reporting endpoint is safe to send reports to.

    Allowed endpoints are:

    * relative references, which always resolve to the current origin;
    * bare ``report-to`` group tokens, which are not URLs;
    * absolute ``https`` URLs that are same-origin with the request;
    * absolute ``https`` URLs whose origin is in ``allowed_origins``.

    Everything else (notably plain ``http`` URLs or cross-origin ``https``
    URLs that have not been allowlisted) is rejected.
    """
    if not endpoint:
        return True

    if _is_relative_endpoint(endpoint):
        # Scheme-relative URLs inherit the request scheme, so only allow them
        # when the request itself is secure (or there is no request, e.g. in
        # system checks, where deployment behind HTTPS is assumed).
        if _is_scheme_relative(endpoint) and request is not None and not request.is_secure():
            return False
        return True

    parsed = urlsplit(endpoint)

    # A bare token with no scheme/netloc (a Reporting API group name) is not
    # an exfiltration URL and is always valid.
    if not parsed.scheme and not parsed.netloc:
        return True

    if parsed.scheme != "https":
        return False

    origin = _origin_of(endpoint)
    if origin in normalize_allowlist(allowed_origins):
        return True

    if request is not None and request.is_secure():
        request_origin = urlunsplit(("https", request.get_host(), "", "", ""))
        if origin == request_origin:
            return True

    return False


def validate_report_endpoints(
    directives: dict[str, object],
    request: HttpRequest | None = None,
    allowed_origins: Sequence[str] | frozenset[str] | None = None,
) -> None:
    """Raise ``CSPReportEndpointError`` for any disallowed reporting endpoint.

    Both ``report-uri`` and ``report-to`` are checked. ``report-to`` may also
    name a bare Reporting API group (a non-URL token), which is permitted.
    """
    for directive in REPORT_DIRECTIVES:
        for endpoint in _as_list(directives.get(directive)):
            if not is_allowed_report_endpoint(endpoint, request=request, allowed_origins=allowed_origins):
                raise CSPReportEndpointError(
                    f"Invalid {directive} endpoint {endpoint!r}: reporting endpoints must be same-origin "
                    f"(relative or https matching the request origin) or an https origin listed in "
                    f"{ALLOWLIST_SETTING!r}."
                )
