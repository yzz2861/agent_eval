from __future__ import annotations

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.decorators import csp_update
from csp.exceptions import CSPReportEndpointError
from csp.middleware import CSPMiddleware
from csp.reports import is_allowed_report_endpoint
from csp.request_attrs import REQUEST_UPDATE
from csp.tests.utils import response as response_factory
from csp.utils import build_policy

rf = RequestFactory()
mw = CSPMiddleware(response_factory())


def test_relative_report_uri_is_allowed() -> None:
    request = rf.get("/")
    assert is_allowed_report_endpoint("/csp-report/", request=request) is True


def test_bare_report_to_token_is_allowed() -> None:
    request = rf.get("/")
    assert is_allowed_report_endpoint("endpoint-group", request=request) is True


def test_https_same_origin_is_allowed() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    assert is_allowed_report_endpoint("https://testserver/csp-report/", request=request) is True


def test_http_endpoint_is_rejected() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    assert is_allowed_report_endpoint("http://evil.example.com/report", request=request) is False


def test_https_cross_origin_without_allowlist_is_rejected() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    assert is_allowed_report_endpoint("https://evil.example.com/report", request=request) is False


def test_https_cross_origin_with_allowlist_is_allowed() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    assert (
        is_allowed_report_endpoint(
            "https://reports.example.com/collect",
            request=request,
            allowed_origins=["https://reports.example.com"],
        )
        is True
    )


def test_scheme_relative_endpoint_requires_secure_request() -> None:
    secure_request = rf.get("/", secure=True, SERVER_NAME="testserver")
    insecure_request = rf.get("/", SERVER_NAME="testserver")
    assert is_allowed_report_endpoint("//testserver/report", request=secure_request) is True
    assert is_allowed_report_endpoint("//testserver/report", request=insecure_request) is False


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'"], "report-uri": ["http://evil.example.com/report"]}}
)
def test_build_policy_rejects_insecure_report_uri() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    with pytest.raises(CSPReportEndpointError):
        build_policy(request=request)


@override_settings(
    CONTENT_SECURITY_POLICY={
        "REPORT_ALLOWLIST": ["https://reports.example.com"],
        "DIRECTIVES": {"default-src": ["'self'"], "report-uri": ["https://reports.example.com/collect"]},
    }
)
def test_build_policy_allows_allowlisted_report_uri() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    policy = build_policy(request=request)
    assert "report-uri https://reports.example.com/collect" in policy


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'"], "report-uri": ["https://evil.example.com/report"]}}
)
def test_build_policy_rejects_cross_origin_https_without_allowlist() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    with pytest.raises(CSPReportEndpointError):
        build_policy(request=request)


def test_build_policy_validates_request_level_overrides() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    with pytest.raises(CSPReportEndpointError):
        build_policy(
            config={"default-src": ["'self'"], "report-uri": ["http://evil.example.com/report"]},
            request=request,
        )


def test_middleware_rejects_invalid_report_uri_from_view_decorator() -> None:
    @csp_update({"report-uri": ["http://evil.example.com/collect"]})
    def bad_view(request: object) -> HttpResponse:
        return HttpResponse()

    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    resp = bad_view(request)
    with pytest.raises(CSPReportEndpointError):
        mw.process_response(request, resp)


def test_middleware_rejects_invalid_report_uri_from_request_override() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    setattr(request, REQUEST_UPDATE, {"report-uri": ["http://evil.example.com/collect"]})
    resp = HttpResponse()
    with pytest.raises(CSPReportEndpointError):
        mw.process_response(request, resp)


def test_middleware_allows_relative_report_uri_from_request_override() -> None:
    request = rf.get("/", secure=True, SERVER_NAME="testserver")
    setattr(request, REQUEST_UPDATE, {"report-uri": ["/csp-report/"]})
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert "report-uri /csp-report/" in resp["Content-Security-Policy"]
