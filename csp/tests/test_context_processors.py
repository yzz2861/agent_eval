import base64

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF
from csp.context_processors import nonce
from csp.exceptions import CSPNonceError
from csp.middleware import DEFAULT_NONCE_LENGTH, MIN_NONCE_LENGTH, CSPMiddleware
from csp.tests.utils import response

rf = RequestFactory()
mw = CSPMiddleware(response())


def test_nonce_context_processor() -> None:
    request = rf.get("/")
    mw.process_request(request)
    context = nonce(request)

    response = HttpResponse()
    csp_nonce = getattr(request, "csp_nonce")
    mw.process_response(request, response)

    assert context["CSP_NONCE"] == csp_nonce


def test_nonce_context_processor_after_response() -> None:
    # The context processor evaluates the nonce eagerly, so it is safe to read
    # again after the response has been processed (the value is still the same).
    request = rf.get("/")
    mw.process_request(request)
    context = nonce(request)

    response = HttpResponse()
    csp_nonce = getattr(request, "csp_nonce")
    mw.process_response(request, response)

    assert context["CSP_NONCE"] == str(csp_nonce)
    assert str(getattr(request, "csp_nonce")) == context["CSP_NONCE"]
    assert f"'nonce-{context['CSP_NONCE']}'" in response[HEADER]


def test_nonce_context_processor_with_middleware_disabled() -> None:
    request = rf.get("/")
    context = nonce(request)

    assert context["CSP_NONCE"] == ""


def test_context_nonce_has_at_least_128_bits_of_entropy() -> None:
    request = rf.get("/")
    mw.process_request(request)
    context = nonce(request)
    value = str(context["CSP_NONCE"])

    assert len(base64.b64decode(value)) >= MIN_NONCE_LENGTH
    assert len(base64.b64decode(value)) == DEFAULT_NONCE_LENGTH


def test_context_nonce_matches_response_header() -> None:
    request = rf.get("/")
    mw.process_request(request)
    context = nonce(request)
    response = HttpResponse()
    mw.process_response(request, response)

    assert f"'nonce-{context['CSP_NONCE']}'" in response[HEADER]
    assert response[HEADER] == f"default-src 'self' 'nonce-{context['CSP_NONCE']}'"


def test_context_nonce_matches_report_only_header() -> None:
    request = rf.get("/")
    mw.process_request(request)
    context = nonce(request)
    response = HttpResponse()

    with override_settings(
        CONTENT_SECURITY_POLICY=None,
        CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF, NONCE]}},
    ):
        mw.process_response(request, response)

    assert HEADER not in response
    assert f"'nonce-{context['CSP_NONCE']}'" in response[HEADER_REPORT_ONLY]


def test_context_nonce_reused_across_responses_raises() -> None:
    first_request = rf.get("/")
    mw.process_request(first_request)
    context = nonce(first_request)
    reused_nonce = str(context["CSP_NONCE"])
    first_response = HttpResponse()
    mw.process_response(first_request, first_response)
    assert f"'nonce-{reused_nonce}'" in first_response[HEADER]

    cached_request = rf.get("/")
    mw.process_request(cached_request)
    # Replaying a cached page reuses the nonce from the previous request.
    setattr(cached_request, "_csp_nonce", reused_nonce)
    cached_response = HttpResponse()
    with pytest.raises(CSPNonceError):
        mw.process_response(cached_request, cached_response)


def test_context_nonce_length_is_configurable() -> None:
    request = rf.get("/")
    with override_settings(CONTENT_SECURITY_POLICY={"NONCE_LENGTH": 32}):
        mw.process_request(request)
        context = nonce(request)
        value = str(context["CSP_NONCE"])

    assert len(base64.b64decode(value)) == 32
