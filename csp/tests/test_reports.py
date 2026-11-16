from __future__ import annotations

import json

import pytest
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.reports import (
    CSPViolationEvent,
    InMemoryStorage,
    RateLimiter,
    ReportEndpointMiddleware,
    ReportProcessor,
    ReportStatus,
    report_uri,
)
from csp.reports.views import DEFAULT_REPORT_PATH, reset_report_processor

rf = RequestFactory()

LEGACY_REPORT = {
    "csp-report": {
        "document-uri": "http://example.com/page.html",
        "referrer": "",
        "violated-directive": "img-src https://cdn.example.com",
        "effective-directive": "img-src",
        "original-policy": "default-src 'self'",
        "disposition": "enforce",
        "blocked-uri": "http://evil.example.com/image.png",
        "line-number": 12,
        "column-number": 34,
        "source-file": "http://example.com/script.js",
        "status-code": 200,
        "script-sample": "",
    }
}


@pytest.fixture(autouse=True)
def _reset_cached_processor() -> None:
    reset_report_processor()
    yield
    reset_report_processor()


def _post(payload: object) -> object:
    request = rf.post(DEFAULT_REPORT_PATH, data=json.dumps(payload), content_type="application/csp-report")
    return report_uri(request)


# --------------------------------------------------------------------------- #
# Event normalization
# --------------------------------------------------------------------------- #


def test_event_from_legacy_report() -> None:
    event = CSPViolationEvent.from_report(LEGACY_REPORT)
    assert event.document_uri == "http://example.com/page.html"
    assert event.violated_directive == "img-src https://cdn.example.com"
    assert event.effective_directive == "img-src"
    assert event.blocked_uri == "http://evil.example.com/image.png"
    assert event.line_number == 12
    assert event.column_number == 34
    assert event.status_code == 200
    assert event.raw == LEGACY_REPORT


def test_event_deduplication_key_normalizes_directive() -> None:
    event = CSPViolationEvent.from_report(LEGACY_REPORT)
    assert event.deduplication_key == (
        "http://evil.example.com/image.png",
        "img-src",
        "http://example.com/page.html",
    )


def test_event_from_reporting_api_body() -> None:
    payload = {
        "type": "csp-violation",
        "body": {
            "documentURL": "http://example.com/app",
            "violatedDirective": "script-src",
            "effectiveDirective": "script-src",
            "blockedURL": "eval",
            "lineNumber": 3,
        },
    }
    event = CSPViolationEvent.from_report(payload)
    assert event.document_uri == "http://example.com/app"
    assert event.effective_directive == "script-src"
    assert event.blocked_uri == "eval"
    assert event.line_number == 3
    assert event.referrer == "unknown"
    assert event.column_number is None


def test_event_handles_missing_fields() -> None:
    event = CSPViolationEvent.from_report({"csp-report": {"violated-directive": "script-src"}})
    assert event.document_uri == "unknown"
    assert event.blocked_uri == "unknown"
    assert event.effective_directive == "script-src"
    assert event.line_number is None
    assert event.status_code is None
    assert event.source_file is None
    assert event.sample == ""
    assert event.deduplication_key == ("unknown", "script-src", "unknown")


def test_event_to_dict_includes_key() -> None:
    event = CSPViolationEvent.from_report(LEGACY_REPORT)
    data = event.to_dict()
    assert data["deduplication_key"] == list(event.deduplication_key)
    assert data["blocked_uri"] == event.blocked_uri


# --------------------------------------------------------------------------- #
# Storage and deduplication
# --------------------------------------------------------------------------- #


def test_in_memory_storage_stores_and_tracks_keys() -> None:
    storage = InMemoryStorage()
    event = CSPViolationEvent.from_report(LEGACY_REPORT)
    assert storage.seen(event.deduplication_key) is False

    storage.store(event)
    assert storage.seen(event.deduplication_key) is True
    assert len(storage) == 1
    assert storage.events == [event]

    storage.clear()
    assert len(storage) == 0
    assert storage.seen(event.deduplication_key) is False


def test_processor_deduplicates_repeated_reports() -> None:
    processor = ReportProcessor()
    status_one, event_one = processor.process(LEGACY_REPORT)
    status_two, event_two = processor.process(LEGACY_REPORT)

    assert status_one is ReportStatus.STORED
    assert status_two is ReportStatus.DUPLICATE
    assert event_one is not None
    assert event_two is not None
    assert event_one.deduplication_key == event_two.deduplication_key
    assert len(processor.storage) == 1


def test_processor_stores_distinct_reports() -> None:
    processor = ReportProcessor()
    assert processor.process(LEGACY_REPORT)[0] is ReportStatus.STORED

    other_body = dict(LEGACY_REPORT["csp-report"])
    other_body["blocked-uri"] = "http://other.example.com/x.png"
    other = {"csp-report": other_body}
    assert processor.process(other)[0] is ReportStatus.STORED
    assert len(processor.storage) == 2


def test_processor_rejects_unrecognized_payload() -> None:
    processor = ReportProcessor()
    status, event = processor.process({"nope": "nope"})
    assert status is ReportStatus.INVALID
    assert event is None
    assert len(processor.storage) == 0


def test_processor_rejects_non_object_payload() -> None:
    processor = ReportProcessor()
    status, event = processor.process(["not", "an", "object"])
    assert status is ReportStatus.INVALID
    assert event is None


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


def test_rate_limiter_allows_up_to_limit() -> None:
    limiter = RateLimiter(max_events=3, window_seconds=60.0)
    key = ("source", "directive", "document")
    assert all(limiter.allow(key, now=100.0 + index) for index in range(3))
    assert limiter.allow(key, now=103.0) is False


def test_rate_limiter_window_slides() -> None:
    limiter = RateLimiter(max_events=2, window_seconds=10.0)
    key = ("source", "directive", "document")
    assert limiter.allow(key, now=0.0) is True
    assert limiter.allow(key, now=1.0) is True
    assert limiter.allow(key, now=2.0) is False
    # After the window elapses, the earliest hits expire and capacity returns.
    assert limiter.allow(key, now=11.0) is True
    assert limiter.allow(key, now=12.0) is True
    assert limiter.allow(key, now=12.5) is False


def test_rate_limiter_tracks_keys_independently() -> None:
    limiter = RateLimiter(max_events=1, window_seconds=10.0)
    assert limiter.allow(("a", "d", "u"), now=0.0) is True
    assert limiter.allow(("b", "d", "u"), now=0.0) is True
    assert limiter.allow(("a", "d", "u"), now=1.0) is False


def test_rate_limiter_validates_arguments() -> None:
    with pytest.raises(ValueError):
        RateLimiter(max_events=0)
    with pytest.raises(ValueError):
        RateLimiter(window_seconds=0)


def test_processor_rate_limits_distinct_documents() -> None:
    processor = ReportProcessor(rate_limiter=RateLimiter(max_events=2, window_seconds=60.0, key_func=lambda key: key[:2]))
    statuses = []
    for index in range(3):
        body = dict(LEGACY_REPORT["csp-report"])
        body["document-uri"] = f"http://example.com/page-{index}.html"
        statuses.append(processor.process({"csp-report": body})[0])

    assert statuses == [ReportStatus.STORED, ReportStatus.STORED, ReportStatus.RATE_LIMITED]
    assert len(processor.storage) == 2


def test_processor_duplicates_count_against_rate_limit() -> None:
    processor = ReportProcessor(rate_limiter=RateLimiter(max_events=2, window_seconds=60.0, key_func=lambda key: key[:2]))
    assert processor.process(LEGACY_REPORT)[0] is ReportStatus.STORED
    assert processor.process(LEGACY_REPORT)[0] is ReportStatus.DUPLICATE
    # The two prior attempts consumed the rate-limit budget for this key.
    assert processor.process(LEGACY_REPORT)[0] is ReportStatus.RATE_LIMITED


# --------------------------------------------------------------------------- #
# Endpoint view
# --------------------------------------------------------------------------- #


def test_view_stores_valid_report() -> None:
    response = _post(LEGACY_REPORT)
    assert response.status_code == 202
    assert json.loads(response.content) == {"status": ReportStatus.STORED.value}


def test_view_deduplicates_second_report() -> None:
    assert _post(LEGACY_REPORT).status_code == 202
    second = _post(LEGACY_REPORT)
    assert second.status_code == 202
    assert json.loads(second.content) == {"status": ReportStatus.DUPLICATE.value}


def test_view_rejects_get() -> None:
    request = rf.get(DEFAULT_REPORT_PATH)
    response = report_uri(request)
    assert response.status_code == 405
    assert response.headers["Allow"] == "POST"


def test_view_rejects_invalid_json() -> None:
    request = rf.post(DEFAULT_REPORT_PATH, data="not-json", content_type="application/csp-report")
    response = report_uri(request)
    assert response.status_code == 400
    assert json.loads(response.content) == {"status": ReportStatus.INVALID.value}


def test_view_rejects_unrecognized_payload() -> None:
    response = _post({"unexpected": "payload"})
    assert response.status_code == 400
    assert json.loads(response.content) == {"status": ReportStatus.INVALID.value}


@override_settings(CSP_REPORTS={"RATE_LIMIT": {"MAX_EVENTS": 2, "WINDOW_SECONDS": 60.0}})
def test_view_rate_limit_setting() -> None:
    def payload(document: str) -> dict:
        body = dict(LEGACY_REPORT["csp-report"])
        body["document-uri"] = document
        return {"csp-report": body}

    first = _post(payload("http://example.com/page-1.html"))
    second = _post(payload("http://example.com/page-2.html"))
    third = _post(payload("http://example.com/page-3.html"))
    # Distinct document-uri values give distinct dedup keys, but the rate limiter
    # shares one budget per source/directive, so the third report is throttled.
    assert json.loads(first.content) == {"status": ReportStatus.STORED.value}
    assert json.loads(second.content) == {"status": ReportStatus.STORED.value}
    assert third.status_code == 202
    assert json.loads(third.content) == {"status": ReportStatus.RATE_LIMITED.value}


@override_settings(CSP_REPORTS={"PATH": "/custom/csp-endpoint/"})
def test_middleware_serves_configured_path() -> None:
    middleware = ReportEndpointMiddleware(lambda request: pytest.fail("should short-circuit"))

    request = rf.post("/custom/csp-endpoint/", data=json.dumps(LEGACY_REPORT), content_type="application/csp-report")
    response = middleware(request)
    assert response.status_code == 202

    other = rf.get("/some/normal/page/")
    sentinel = object()
    passthrough = ReportEndpointMiddleware(lambda request: sentinel)
    assert passthrough(other) is sentinel


def test_middleware_default_path() -> None:
    middleware = ReportEndpointMiddleware(lambda request: pytest.fail("should short-circuit"))
    request = rf.post(DEFAULT_REPORT_PATH, data=json.dumps(LEGACY_REPORT), content_type="application/csp-report")
    assert middleware(request).status_code == 202
