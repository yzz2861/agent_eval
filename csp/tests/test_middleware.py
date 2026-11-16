import base64

from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseServerError,
)
from django.template import Context, Template, engines
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF
from csp.exceptions import CSPNonceError
from csp.middleware import DEFAULT_NONCE_LENGTH, MIN_NONCE_LENGTH, CheckableLazyObject, CSPMiddleware
from csp.tests.utils import response

mw = CSPMiddleware(response())
rf = RequestFactory()


def _decoded_nonce_length(nonce: str) -> int:
    return len(base64.b64decode(nonce))


def test_checkable_lazy_object() -> None:
    def generate_value() -> str:
        return "generated"

    lazy = CheckableLazyObject(generate_value)

    # Before wrapped object is initiated, lazy is falsy
    assert bool(lazy) is False

    # After str(lazy) calls generate_value, lazy is truthy
    assert str(lazy) == "generated"
    assert bool(lazy) is True


def test_add_header() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["example.com"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_both_headers() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": {"example.com"}}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": {SELF}}},
)
def test_directives_configured_as_sets() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


def test_exempt() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_exempt", True)
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": ["/inlines-r-us"]})
def test_exclude() -> None:
    request = rf.get("/inlines-r-us/foo")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(
    CONTENT_SECURITY_POLICY=None,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_report_only() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response
    assert HEADER_REPORT_ONLY in response
    assert response[HEADER_REPORT_ONLY] == "default-src 'self'"


def test_dont_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    response[HEADER] = "default-src example.com"
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_config() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_config", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_update() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_update", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self' example.com"


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_use_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_replace", {"img-src": ["bar.com"]})
    mw.process_response(request, response)
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]


@override_settings(DEBUG=True)
def test_debug_errors_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseServerError()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(DEBUG=True)
def test_debug_notfound_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseNotFound()
    mw.process_response(request, response)
    assert HEADER not in response


def test_nonce_created_when_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()
    mw.process_response(request, response)
    assert nonce in response[HEADER]
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"


def test_nonce_is_false_before_access_and_true_after() -> None:
    request = rf.get("/")
    mw.process_request(request)
    assert bool(getattr(request, "csp_nonce")) is False
    nonce = str(getattr(request, "csp_nonce"))
    assert bool(getattr(request, "csp_nonce")) is True

    response = HttpResponse()
    mw.process_response(request, response)
    assert bool(getattr(request, "csp_nonce")) is True
    assert getattr(request, "csp_nonce") == nonce


def test_nonce_conditional_in_django_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = Template(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_django_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = Template("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_nonce_conditional_in_jinja2_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = engines["jinja2"].from_string(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_jinja2_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = engines["jinja2"].from_string("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_no_nonce_when_not_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    response = HttpResponse()
    mw.process_response(request, response)
    assert "nonce-" not in response[HEADER]
    assert response[HEADER] == "default-src 'self'"


def test_nonce_regenerated_on_new_request() -> None:
    request1 = rf.get("/")
    request2 = rf.get("/")
    mw.process_request(request1)
    mw.process_request(request2)
    nonce1 = str(getattr(request1, "csp_nonce"))
    nonce2 = str(getattr(request2, "csp_nonce"))
    assert nonce1 != nonce2

    response1 = HttpResponse()
    response2 = HttpResponse()
    mw.process_response(request1, response1)
    mw.process_response(request2, response2)
    assert nonce1 not in response2[HEADER]
    assert nonce2 not in response1[HEADER]


def test_nonce_has_at_least_128_bits_of_entropy() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    # 16 random bytes == 128 bits of entropy before base64 encoding.
    assert _decoded_nonce_length(nonce) >= MIN_NONCE_LENGTH
    assert _decoded_nonce_length(nonce) == DEFAULT_NONCE_LENGTH
    assert len(nonce) >= MIN_NONCE_LENGTH


def test_nonce_length_is_configurable() -> None:
    request = rf.get("/")
    with override_settings(
        CONTENT_SECURITY_POLICY={"NONCE_LENGTH": 32, "DIRECTIVES": {"default-src": [SELF, NONCE]}},
    ):
        mw.process_request(request)
        nonce = str(getattr(request, "csp_nonce"))
        response = HttpResponse()
        mw.process_response(request, response)

    assert _decoded_nonce_length(nonce) == 32
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"


@pytest.mark.parametrize("bad_length", [0, 8, 15, -1, "16", 16.0, True])
def test_nonce_length_below_128_bits_raises(bad_length: object) -> None:
    request = rf.get("/")
    with override_settings(CONTENT_SECURITY_POLICY={"NONCE_LENGTH": bad_length}):
        mw.process_request(request)
        with pytest.raises(CSPNonceError):
            str(getattr(request, "csp_nonce"))


def test_nonce_reused_across_responses_raises() -> None:
    # Simulate a cached page: the nonce generated for the first request ends
    # up being written into a second response instead of a fresh nonce.
    first_request = rf.get("/")
    mw.process_request(first_request)
    nonce = str(getattr(first_request, "csp_nonce"))
    first_response = HttpResponse()
    mw.process_response(first_request, first_response)
    assert f"'nonce-{nonce}'" in first_response[HEADER]

    cached_request = rf.get("/")
    mw.process_request(cached_request)
    # A cached response replays the previously consumed nonce.
    setattr(cached_request, "_csp_nonce", nonce)
    cached_response = HttpResponse()
    with pytest.raises(CSPNonceError):
        mw.process_response(cached_request, cached_response)


def test_single_request_uses_single_nonce_in_both_headers() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()

    with override_settings(
        CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF, NONCE]}},
        CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF, NONCE]}},
    ):
        mw.process_response(request, response)

    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"
    assert response[HEADER_REPORT_ONLY] == f"default-src 'self' 'nonce-{nonce}'"
    assert f"'nonce-{nonce}'" in response[HEADER]
    assert f"'nonce-{nonce}'" in response[HEADER_REPORT_ONLY]


def test_unused_nonce_is_not_tracked_as_consumed() -> None:
    # A nonce that was never written into a header must not be flagged later.
    request = rf.get("/")
    mw.process_request(request)
    response = HttpResponse()
    mw.process_response(request, response)
    assert "nonce-" not in response[HEADER]


def test_no_nonce_access_after_middleware_is_attribute_error() -> None:
    # Test `CSPNonceError` is raised when accessing an unset nonce after the response has been processed.
    request = rf.get("/")
    mw.process_request(request)
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", True)) is False
    with pytest.raises(CSPNonceError):
        str(getattr(request, "csp_nonce"))


def test_set_nonce_access_after_middleware_is_ok() -> None:
    # Test accessing a set nonce after the response has been processed is OK.
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", False)) is True
    assert str(getattr(request, "csp_nonce")) == nonce
