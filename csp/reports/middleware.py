from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from csp.reports.views import DEFAULT_REPORT_PATH, get_report_config, report_uri

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


class ReportEndpointMiddleware:
    """Serve the report endpoint without adding a URLconf entry.

    Requests whose path matches ``CSP_REPORTS["PATH"]`` (default
    ``/csp/report/``) are handled directly by the report view.
    """

    def __init__(self, get_response: Callable[..., "HttpResponseBase"]) -> None:
        self.get_response = get_response

    def __call__(self, request: "HttpRequest") -> "HttpResponseBase":
        path = get_report_config().get("PATH", DEFAULT_REPORT_PATH)
        if request.path_info == path:
            return report_uri(request)
        return self.get_response(request)
