from django.core.checks import run_checks
from django.core.checks.registry import registry as check_registry
from django.test.utils import override_settings

from csp.checks import (
    check_django_csp_lt_4_0,
    check_exclude_url_prefixes_is_not_string,
    check_site_csp_headers,
    migrate_settings,
)
from csp.constants import NONCE, SELF


@override_settings(
    CSP_REPORT_PERCENTAGE=0.25,
    CSP_EXCLUDE_URL_PREFIXES=["/admin/"],
    CSP_REPORT_ONLY=False,
    CSP_DEFAULT_SRC=["'self'", "example.com"],
)
def test_migrate_settings() -> None:
    config, report_only = migrate_settings()
    assert config == {
        "REPORT_PERCENTAGE": 25.0,
        "EXCLUDE_URL_PREFIXES": ["/admin/"],
        "DIRECTIVES": {"default-src": ["'self'", "example.com"]},
    }
    assert report_only is False


@override_settings(
    CSP_REPORT_ONLY=True,
    CSP_DEFAULT_SRC=["'self'", "example.com"],
    CSP_SCRIPT_SRC=["'self'", "example.com", "'unsafe-inline'"],
    CSP_INCLUDE_NONCE_IN=["script-src"],
)
def test_migrate_settings_report_only() -> None:
    config, report_only = migrate_settings()
    assert config == {
        "DIRECTIVES": {
            "default-src": ["'self'", "example.com"],
            "script-src": ["'self'", "example.com", "'unsafe-inline'", NONCE],
        }
    }
    assert report_only is True


@override_settings(
    CSP_DEFAULT_SRC=["'self'", "example.com"],
)
def test_check_django_csp_lt_4_0() -> None:
    errors = check_django_csp_lt_4_0(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E001"
    assert "update your settings to use the new format" in error.msg


def test_check_django_csp_lt_4_0_no_config() -> None:
    assert check_django_csp_lt_4_0(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": "/admin/"},
)
def test_check_exclude_url_prefixes_is_not_string() -> None:
    errors = check_exclude_url_prefixes_is_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY settings must be a list or tuple."


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"EXCLUDE_URL_PREFIXES": "/admin/"},
)
def test_check_exclude_url_prefixes_ro_is_not_string() -> None:
    errors = check_exclude_url_prefixes_is_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY_REPORT_ONLY settings must be a list or tuple."


SITE_CHECK_SETTINGS = {
    "ROOT_URLCONF": "csp.tests.site_check_urls",
    "MIDDLEWARE": ["csp.middleware.CSPMiddleware"],
    "CONTENT_SECURITY_POLICY": {"DIRECTIVES": {"default-src": [SELF]}},
}


def test_check_site_csp_headers_no_registry() -> None:
    assert check_site_csp_headers(None) == []


@override_settings(CSP_SITE_CHECKS=["not-a-dict"])
def test_check_site_csp_headers_invalid_registry() -> None:
    errors = check_site_csp_headers(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E003"
    assert "CSP_SITE_CHECKS must be a dict" in errors[0].msg


@override_settings(
    **SITE_CHECK_SETTINGS,
    CSP_SITE_CHECKS={
        "main": {
            "ok": {"path": "/ok/", "expect": {"default-src": [SELF]}},
            "error": {"path": "/error/", "expect": {"default-src": [SELF]}},
            "redirect": {"path": "/redirect/", "expect": {"default-src": [SELF]}},
        },
    },
)
def test_check_site_csp_headers_pass() -> None:
    assert check_site_csp_headers(None) == []


@override_settings(
    **SITE_CHECK_SETTINGS,
    CSP_SITE_CHECKS={
        "main": {
            "ok": {"path": "/ok/", "expect": {"default-src": [SELF], "img-src": ["cdn.example.com"]}},
            "error": {"path": "/error/", "expect": {"default-src": [SELF]}},
            "redirect": {"path": "/redirect/", "expect": {"default-src": [SELF]}},
        },
    },
)
def test_check_site_csp_headers_success_page_must_present_own_config() -> None:
    # The error page's CSP is provided by the shared layer (middleware + CONTENT_SECURITY_POLICY),
    # so it passes. The success page of the same site must still present its own config
    # credentials (here: img-src) and fails when it only carries the shared policy.
    errors = check_site_csp_headers(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E006"
    assert "'main'" in error.msg
    assert "ok: /ok/" in error.msg
    assert "img-src" in error.msg
    assert "cdn.example.com" in error.msg


@override_settings(
    **SITE_CHECK_SETTINGS,
    CSP_SITE_CHECKS={
        "main": {
            "ok": {"path": "/ok-own/", "expect": {"default-src": [SELF], "img-src": ["cdn.example.com"]}},
            "error": {"path": "/error/", "expect": {"default-src": [SELF]}},
        },
    },
)
def test_check_site_csp_headers_own_config_present() -> None:
    assert check_site_csp_headers(None) == []


@override_settings(
    **SITE_CHECK_SETTINGS,
    CSP_SITE_CHECKS={
        "main": {
            "redirect": {"path": "/ok/", "expect": {"default-src": [SELF]}},
        },
    },
)
def test_check_site_csp_headers_unexpected_status() -> None:
    errors = check_site_csp_headers(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E004"
    assert "redirect" in error.msg
    assert "200" in error.msg


@override_settings(
    ROOT_URLCONF="csp.tests.site_check_urls",
    MIDDLEWARE=[],
    CSP_SITE_CHECKS={
        "main": {
            "ok": {"path": "/ok/", "expect": {"default-src": [SELF]}},
        },
    },
)
def test_check_site_csp_headers_missing_header() -> None:
    errors = check_site_csp_headers(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E005"
    assert "no Content-Security-Policy header" in error.msg


@override_settings(
    **SITE_CHECK_SETTINGS,
    TEMPLATES=[
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [],
            "APP_DIRS": True,
            "OPTIONS": {},
        },
    ],
    CSP_SITE_CHECKS={
        "main": {
            "ok": {"path": "/ok/", "expect": {"default-src": [SELF], "img-src": ["cdn.example.com"]}},
        },
    },
)
def test_check_site_csp_headers_runs_alongside_django_checks() -> None:
    registered = check_registry.get_checks(include_deployment_checks=True)
    assert check_site_csp_headers in registered
    assert check_django_csp_lt_4_0 in registered
    assert check_exclude_url_prefixes_is_not_string in registered

    errors = run_checks()
    site_check_errors = [error for error in errors if error.id == "csp.E006"]
    assert len(site_check_errors) == 1
