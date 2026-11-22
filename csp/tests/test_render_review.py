from __future__ import annotations

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.test import Client
from django.test.utils import override_settings
from django.urls import path
from django.utils.deprecation import MiddlewareMixin

from csp.constants import HEADER, HEADER_REPORT_ONLY, SELF
from csp.decorators import csp_replace, csp_update

ENFORCED_POLICY = {"DIRECTIVES": {"default-src": [SELF]}}
REPORT_ONLY_POLICY = {"DIRECTIVES": {"default-src": [SELF], "img-src": ["reports.example.com"]}}

REVIEW_MIDDLEWARE = [
    "csp.middleware.CSPRenderReviewMiddleware",
    "csp.middleware.CSPMiddleware",
    "csp.tests.test_render_review.CarryOverErrorMiddleware",
]

REVIEW_SETTINGS = {
    "ROOT_URLCONF": "csp.tests.test_render_review",
    "MIDDLEWARE": REVIEW_MIDDLEWARE,
    "CONTENT_SECURITY_POLICY": ENFORCED_POLICY,
    "CONTENT_SECURITY_POLICY_REPORT_ONLY": REPORT_ONLY_POLICY,
}


def normal_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse("normal page")


def export_view(request: HttpRequest) -> HttpResponse:
    # Simulates an in-site export request that is dispatched internally, is
    # granted a CSP "approval" object, and then fails into the shared error
    # page.
    setattr(request, "csp_approval", "default-src 'none'; img-src exports.example.com")
    raise RuntimeError("export failed")


def plain_error_view(request: HttpRequest) -> HttpResponse:
    raise RuntimeError("boom")


@csp_replace({"default-src": ["'none'"]})
def redirect_view(request: HttpRequest) -> HttpResponseRedirect:
    return HttpResponseRedirect("/review-target/")


@csp_update({"img-src": ["images.example.com"]})
def target_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse("target page")


class CarryOverErrorMiddleware(MiddlewareMixin):
    """
    Simulates engineering that carries a previous CSP approval object along
    onto the shared error page after an internal dispatch fails.
    """

    def process_exception(self, request: HttpRequest, exception: Exception) -> HttpResponse:
        response = HttpResponse("shared error page", status=500)
        approval = getattr(request, "csp_approval", None)
        if approval is not None:
            response[HEADER] = approval
        return response


urlpatterns = [
    path("normal/", normal_view),
    path("export/", export_view),
    path("error/", plain_error_view),
    path("redirect/", redirect_view),
    path("review-target/", target_view),
]


def parse_policy(header: str) -> dict[str, str]:
    return dict(part.split(" ", 1) for part in header.split("; "))


@override_settings(**REVIEW_SETTINGS)
def test_normal_page_review() -> None:
    response = Client().get("/normal/")
    assert response.status_code == 200

    review = response.csp_review
    assert review["path"] == "/normal/"
    assert review["status"] == 200
    assert review["decision_only"] is False
    assert review["authorizes_followup"] is False

    assert response[HEADER] == "default-src 'self'"
    assert review["enforced"] == {
        "header": "default-src 'self'",
        "source": "settings",
        "scope_valid": True,
    }

    assert parse_policy(response[HEADER_REPORT_ONLY]) == {
        "default-src": "'self'",
        "img-src": "reports.example.com",
    }
    assert review["report_only"]["source"] == "settings"
    assert review["report_only"]["scope_valid"] is True


@override_settings(**REVIEW_SETTINGS)
def test_error_page_review_flags_carried_over_approval() -> None:
    response = Client().get("/export/")
    assert response.status_code == 500

    # The shared error page actually carries the export's approved policy.
    assert response[HEADER] == "default-src 'none'; img-src exports.example.com"

    review = response.csp_review
    # The enforced header does not match the final response's own scope.
    assert review["enforced"]["source"] == "foreign"
    assert review["enforced"]["scope_valid"] is False
    assert review["enforced"]["header"] == "default-src 'none'; img-src exports.example.com"

    # The report-only policy was not carried over and comes from this
    # response's own scope.
    assert review["report_only"]["source"] == "settings"
    assert review["report_only"]["scope_valid"] is True


@override_settings(**REVIEW_SETTINGS)
def test_error_page_without_carryover_uses_own_scope() -> None:
    response = Client().get("/error/")
    assert response.status_code == 500

    assert response[HEADER] == "default-src 'self'"
    review = response.csp_review
    assert review["enforced"]["source"] == "settings"
    assert review["enforced"]["scope_valid"] is True
    assert review["report_only"]["source"] == "settings"
    assert review["report_only"]["scope_valid"] is True


@override_settings(**REVIEW_SETTINGS)
def test_redirect_decision_does_not_authorize_followup() -> None:
    client = Client()

    redirect_response = client.get("/redirect/")
    assert redirect_response.status_code == 302
    # The redirect itself only leaves an auditable decision behind.
    redirect_review = redirect_response.csp_review
    assert redirect_review["decision_only"] is True
    assert redirect_review["authorizes_followup"] is False
    assert redirect_review["enforced"]["source"] == "replace"
    assert redirect_review["enforced"]["scope_valid"] is True
    assert redirect_response[HEADER] == "default-src 'none'"

    # A separate, isolated request after the redirect gets its own policy
    # from its own scope; the redirect's decision granted it nothing.
    followup = client.get("/review-target/")
    assert followup.status_code == 200
    followup_review = followup.csp_review
    assert followup_review["decision_only"] is False
    assert followup_review["enforced"]["source"] == "update"
    assert followup_review["enforced"]["scope_valid"] is True
    assert parse_policy(followup[HEADER]) == {
        "default-src": "'self'",
        "img-src": "images.example.com",
    }
    assert followup_review["report_only"]["source"] == "settings"
    assert followup_review["report_only"]["scope_valid"] is True
