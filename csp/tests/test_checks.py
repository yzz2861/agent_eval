from django.core.checks import Error, Warning
from django.test.utils import override_settings

from csp.checks import (
    check_directive_names,
    check_django_csp_lt_4_0,
    check_duplicate_sources,
    check_exclude_url_prefixes_is_not_string,
    check_nonce_hash_conflicts,
    check_report_only_consistency,
    check_uri_sources,
    migrate_settings,
)
from csp.constants import NONCE


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


# ---------------------------------------------------------------------------
# Directive whitelist / deprecated directive checks
# ---------------------------------------------------------------------------


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"not-a-real-directive": ["'self'"]}},
)
def test_check_directive_names_unknown_is_error() -> None:
    messages = check_directive_names(None)
    assert len(messages) == 1
    message = messages[0]
    assert isinstance(message, Error)
    assert message.id == "csp.E003"
    assert "not-a-real-directive" in message.msg
    assert "CONTENT_SECURITY_POLICY" in message.msg


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"typo-src": ["'self'"]}},
)
def test_check_directive_names_unknown_in_report_only() -> None:
    messages = check_directive_names(None)
    assert len(messages) == 1
    assert messages[0].id == "csp.E003"
    assert "CONTENT_SECURITY_POLICY_REPORT_ONLY" in messages[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"plugin-types": ["application/pdf"]}},
)
def test_check_directive_names_deprecated_is_warning() -> None:
    messages = check_directive_names(None)
    assert len(messages) == 1
    message = messages[0]
    assert isinstance(message, Warning)
    assert message.id == "csp.W001"
    assert "plugin-types" in message.msg


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "report-uri": ["/csp-report/"],
        }
    },
)
def test_check_directive_names_valid_directives_pass() -> None:
    # ``report-uri`` is deprecated, so only that warning is expected; the others pass.
    messages = check_directive_names(None)
    assert [message.id for message in messages] == ["csp.W001"]


def test_check_directive_names_no_config() -> None:
    assert check_directive_names(None) == []


# ---------------------------------------------------------------------------
# URI syntax checks
# ---------------------------------------------------------------------------


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": ["/csp-report/"]}},
)
def test_check_uri_sources_relative_path_valid() -> None:
    assert check_uri_sources(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": ["https://reports.example.com/collect"]}},
)
def test_check_uri_sources_absolute_url_valid() -> None:
    assert check_uri_sources(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": ["/csp report/"]}},
)
def test_check_uri_sources_whitespace_invalid() -> None:
    messages = check_uri_sources(None)
    assert len(messages) == 1
    assert messages[0].id == "csp.E004"
    assert "/csp report/" in messages[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": ["data:application/json"]}},
)
def test_check_uri_sources_non_http_scheme_invalid() -> None:
    messages = check_uri_sources(None)
    assert len(messages) == 1
    assert messages[0].id == "csp.E004"


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"report-uri": [""]}},
)
def test_check_uri_sources_empty_invalid() -> None:
    messages = check_uri_sources(None)
    assert len(messages) == 1
    assert messages[0].id == "csp.E004"
    assert "CONTENT_SECURITY_POLICY_REPORT_ONLY" in messages[0].msg


# ---------------------------------------------------------------------------
# Nonce / hash coexistence checks
# ---------------------------------------------------------------------------


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"script-src": [NONCE, "'sha256-RFV0E2dRa17i1yqC9t4p5nR1f3wZ4x6y7z8='"]}
    },
)
def test_check_nonce_hash_conflict_with_sentinel() -> None:
    messages = check_nonce_hash_conflicts(None)
    assert len(messages) == 1
    message = messages[0]
    assert isinstance(message, Warning)
    assert message.id == "csp.W002"
    assert "script-src" in message.msg


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"script-src": ["'nonce-abc123'", "'sha384-abcdefabcdefabcdef='"]}
    },
)
def test_check_nonce_hash_conflict_with_literal_nonce() -> None:
    messages = check_nonce_hash_conflicts(None)
    assert len(messages) == 1
    assert messages[0].id == "csp.W002"


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"script-src": [NONCE, "'self'"]}},
)
def test_check_nonce_without_hash_passes() -> None:
    assert check_nonce_hash_conflicts(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"script-src": ["'sha256-abcdef='", "'self'"]}},
)
def test_check_hash_without_nonce_passes() -> None:
    assert check_nonce_hash_conflicts(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": [NONCE, "'sha256-abcdef='"]}},
)
def test_check_nonce_hash_ignored_for_non_script_directive() -> None:
    # ``img-src`` does not accept nonce/hash source expressions.
    assert check_nonce_hash_conflicts(None) == []


# ---------------------------------------------------------------------------
# Duplicate source checks
# ---------------------------------------------------------------------------


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'", "'self'", "example.com"]}},
)
def test_check_duplicate_sources_warns() -> None:
    messages = check_duplicate_sources(None)
    assert len(messages) == 1
    message = messages[0]
    assert isinstance(message, Warning)
    assert message.id == "csp.W003"
    assert "default-src" in message.msg
    assert "'self'" in message.msg


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'", "example.com"]}},
)
def test_check_duplicate_sources_passes() -> None:
    assert check_duplicate_sources(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"upgrade-insecure-requests": True}},
)
def test_check_duplicate_sources_ignores_boolean_directives() -> None:
    assert check_duplicate_sources(None) == []


# ---------------------------------------------------------------------------
# Report-only / enforce consistency checks
# ---------------------------------------------------------------------------


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'"], "img-src": ["'self'"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "DIRECTIVES": {"default-src": ["'self'", "example.com"], "script-src": ["'self'"]}
    },
)
def test_check_report_only_consistency_flags_mismatch() -> None:
    messages = check_report_only_consistency(None)
    assert len(messages) == 1
    message = messages[0]
    assert isinstance(message, Warning)
    assert message.id == "csp.W004"
    assert "default-src" in message.msg


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": ["'self'"]}},
)
def test_check_report_only_consistency_aligned_passes() -> None:
    assert check_report_only_consistency(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'", "example.com"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": ["example.com", "'self'"]}},
)
def test_check_report_only_consistency_order_insensitive() -> None:
    assert check_report_only_consistency(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'"]}},
)
def test_check_report_only_consistency_without_report_only() -> None:
    assert check_report_only_consistency(None) == []
