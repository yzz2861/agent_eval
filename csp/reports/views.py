from __future__ import annotations

import json
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.module_loading import import_string

from csp.reports.processor import ReportProcessor, ReportStatus
from csp.reports.rate_limiting import RateLimiter

DEFAULT_REPORT_PATH = "/csp/report/"

_processor: ReportProcessor | None = None


def get_report_config() -> dict[str, Any]:
    return getattr(settings, "CSP_REPORTS", None) or {}


def reset_report_processor() -> None:
    """Forget the cached processor. Mainly useful for tests."""
    global _processor
    _processor = None


def get_report_processor() -> ReportProcessor:
    """Return a processor built from the ``CSP_REPORTS`` setting.

    The processor is cached so the in-memory storage and rate-limiter state
    persist across requests.
    """
    global _processor
    if _processor is None:
        config = get_report_config()
        storage_path = config.get("STORAGE", "csp.reports.storage.InMemoryStorage")
        rate_limit = config.get("RATE_LIMIT", {}) or {}
        storage = import_string(storage_path)()
        rate_limiter = RateLimiter(
            max_events=int(rate_limit.get("MAX_EVENTS", 100)),
            window_seconds=float(rate_limit.get("WINDOW_SECONDS", 60.0)),
            key_func=lambda key: key[:2],
        )
        _processor = ReportProcessor(storage=storage, rate_limiter=rate_limiter)
    return _processor


def report_uri(request: HttpRequest) -> HttpResponse:
    """Django view that receives and processes CSP violation reports.

    Wire it up in your URLconf::

        from csp.reports.views import report_uri
        urlpatterns = [path("csp/report/", report_uri)]
    """
    if request.method != "POST":
        return HttpResponse(status=405, headers={"Allow": "POST"})

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"status": ReportStatus.INVALID.value}, status=400)

    status, _event = get_report_processor().process(payload)
    if status is ReportStatus.INVALID:
        http_status = 400
    else:
        # Duplicates and rate-limited reports are accepted silently so browsers
        # do not retry them.
        http_status = 202
    return JsonResponse({"status": status.value}, status=http_status)
