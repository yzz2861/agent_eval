from __future__ import annotations

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.decorators import csp_report_only
from csp.middleware import CSPMiddleware
from csp.request_attrs import (
    REQUEST_CONFIG,
    REQUEST_EXEMPT,
    REQUEST_REPLACE,
    REQUEST_REPORT_ONLY,
    REQUEST_UPDATE,
)
from csp.tests.utils import response

mw = CSPMiddleware(response())
rf = RequestFactory()


def test_request_config_overrides_settings() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_CONFIG, {"default-src": ["example.com"]})
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert resp[HEADER] == "default-src example.com"


def test_request_update_appends_to_settings() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_UPDATE, {"img-src": ["img.example.com"]})
    resp = HttpResponse()
    mw.process_response(request, resp)
    policy = sorted(resp[HEADER].split("; "))
    assert policy == ["default-src 'self'", "img-src img.example.com"]


def test_request_replace_replaces_directive() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_REPLACE, {"default-src": ["strict.example.com"]})
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert resp[HEADER] == "default-src strict.example.com"


def test_request_exempt_skips_enforcement_header() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_EXEMPT, True)
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert HEADER not in resp


def test_request_report_only_routes_enforced_policy_to_report_only_header() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_REPORT_ONLY, True)
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert HEADER not in resp
    assert HEADER_REPORT_ONLY in resp
    assert resp[HEADER_REPORT_ONLY] == "default-src 'self'"


@override_settings(CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": ["report-only.example.com"]}})
def test_request_report_only_suppresses_standalone_report_only_policy() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_REPORT_ONLY, True)
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert HEADER not in resp
    assert resp[HEADER_REPORT_ONLY] == "default-src 'self'"


def test_request_report_only_combined_with_request_config() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_REPORT_ONLY, True)
    setattr(request, REQUEST_CONFIG, {"default-src": ["dynamic.example.com"]})
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert HEADER not in resp
    assert resp[HEADER_REPORT_ONLY] == "default-src dynamic.example.com"


def test_response_attribute_takes_precedence_over_request_attribute() -> None:
    request = rf.get("/")
    setattr(request, REQUEST_CONFIG, {"default-src": ["request.example.com"]})
    resp = HttpResponse()
    setattr(resp, "_csp_config", {"default-src": ["response.example.com"]})
    mw.process_response(request, resp)
    assert resp[HEADER] == "default-src response.example.com"


def test_csp_report_only_decorator_routes_to_report_only_header() -> None:
    @csp_report_only
    def view(request: object) -> HttpResponse:
        return HttpResponse()

    request = rf.get("/")
    resp = view(request)
    mw.process_response(request, resp)
    assert HEADER not in resp
    assert resp[HEADER_REPORT_ONLY] == "default-src 'self'"
