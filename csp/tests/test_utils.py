import copy

import pytest
from django.test.utils import override_settings
from django.utils.functional import lazy

from csp.constants import NONCE, NONE, SELF
from csp.utils import (
    DEFAULT_DIRECTIVES,
    build_policy,
    deduplication_key,
    default_config,
    directive_name,
    normalize_violation_report,
)


def policy_eq(a: str, b: str) -> None:
    parts_a = sorted(a.split("; "))
    parts_b = sorted(b.split("; "))
    assert parts_a == parts_b, f"{a!r} != {b!r}"


def literal(s: str) -> str:
    return s


lazy_literal = lazy(literal, str)


def test_default_config_none() -> None:
    assert default_config(None) is None


def test_default_config_empty() -> None:
    # Test `default_config` with an empty dict returns defaults.
    assert default_config({}) == DEFAULT_DIRECTIVES


def test_default_config_drops_unknown() -> None:
    # Test `default_config` drops unknown keys.
    config = {"foo-src": ["example.com"]}
    assert default_config(config) == DEFAULT_DIRECTIVES


def test_default_config() -> None:
    # Test `default_config` keeps config along with defaults.
    config = {"img-src": ["example.com"]}
    assert default_config(config) == {**DEFAULT_DIRECTIVES, **config}


def test_empty_policy() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": None}})
def test_default_src_none() -> None:
    policy = build_policy()
    policy_eq("", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["example.com", "example2.com"]}})
def test_default_src() -> None:
    policy = build_policy()
    policy_eq("default-src example.com example2.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": {"example.com", "example2.com"}}})
def test_default_src_is_set() -> None:
    policy = build_policy()
    policy_eq("default-src example.com example2.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"script-src": ["example.com"]}})
def test_script_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; script-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"script-src-attr": ["example.com"]}})
def test_script_src_attr() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; script-src-attr example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"script-src-elem": ["example.com"]}})
def test_script_src_elem() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; script-src-elem example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"object-src": ["example.com"]}})
def test_object_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; object-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"prefetch-src": ["example.com"]}})
def test_prefetch_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; prefetch-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"style-src": ["example.com"]}})
def test_style_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; style-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"style-src-attr": ["example.com"]}})
def test_style_src_attr() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; style-src-attr example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"style-src-elem": ["example.com"]}})
def test_style_src_elem() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; style-src-elem example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["example.com"]}})
def test_img_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; img-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"media-src": ["example.com"]}})
def test_media_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; media-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"frame-src": ["example.com"]}})
def test_frame_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; frame-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"font-src": ["example.com"]}})
def test_font_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; font-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"connect-src": ["example.com"]}})
def test_connect_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; connect-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"sandbox": ["allow-scripts"]}})
def test_sandbox() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; sandbox allow-scripts", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"sandbox": []}})
def test_sandbox_empty() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; sandbox", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": "/foo"}})
def test_report_uri() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; report-uri /foo", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": lazy_literal("/foo")}})
def test_report_uri_lazy() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; report-uri /foo", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-to": "some_endpoint"}})
def test_report_to() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; report-to some_endpoint", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["example.com"]}})
def test_update_img() -> None:
    policy = build_policy(update={"img-src": "example2.com"})
    policy_eq("default-src 'self'; img-src example.com example2.com", policy)


def test_update_missing_setting() -> None:
    """update should work even if the setting is not defined."""
    policy = build_policy(update={"img-src": "example.com"})
    policy_eq("default-src 'self'; img-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["example.com"]}})
def test_replace_img() -> None:
    policy = build_policy(replace={"img-src": "example2.com"})
    policy_eq("default-src 'self'; img-src example2.com", policy)


def test_replace_missing_setting() -> None:
    """replace should work even if the setting is not defined."""
    policy = build_policy(replace={"img-src": "example.com"})
    policy_eq("default-src 'self'; img-src example.com", policy)


def test_config() -> None:
    policy = build_policy(config={"default-src": [NONE], "img-src": [SELF]})
    policy_eq("default-src 'none'; img-src 'self'", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ("example.com",)}})
def test_update_string() -> None:
    """
    GitHub issue #40 - given project settings as a tuple, and
    an update/replace with a string, concatenate correctly.
    """
    policy = build_policy(update={"img-src": "example2.com"})
    policy_eq("default-src 'self'; img-src example.com example2.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ("example.com",)}})
def test_replace_string() -> None:
    """
    Demonstrate that GitHub issue #40 doesn't affect replacements
    """
    policy = build_policy(replace={"img-src": "example2.com"})
    policy_eq("default-src 'self'; img-src example2.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ("example.com",)}})
def test_update_set() -> None:
    """
    GitHub issue #40 - given project settings as a tuple, and
    an update/replace with a string, concatenate correctly.
    """
    policy = build_policy(update={"img-src": {"example2.com"}})
    policy_eq("default-src 'self'; img-src example.com example2.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ("example.com",)}})
def test_replace_set() -> None:
    """
    Demonstrate that GitHub issue #40 doesn't affect replacements
    """
    policy = build_policy(replace={"img-src": {"example2.com"}})
    policy_eq("default-src 'self'; img-src example2.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"form-action": ["example.com"]}})
def test_form_action() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; form-action example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"base-uri": ["example.com"]}})
def test_base_uri() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; base-uri example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"child-src": ["example.com"]}})
def test_child_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; child-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"frame-ancestors": ["example.com"]}})
def test_frame_ancestors() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; frame-ancestors example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"navigate-to": ["example.com"]}})
def test_navigate_to() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; navigate-to example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"manifest-src": ["example.com"]}})
def test_manifest_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; manifest-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"worker-src": ["example.com"]}})
def test_worker_src() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; worker-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"plugin-types": ["application/pdf"]}})
def test_plugin_types() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; plugin-types application/pdf", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"require-sri-for": ["script"]}})
def test_require_sri_for() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; require-sri-for script", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"require-trusted-types-for": ["'script'"]}})
def test_require_trusted_types_for() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; require-trusted-types-for 'script'", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"trusted-types": ["strictPolicy", "laxPolicy", "default", "'allow-duplicates'"]}})
def test_trusted_types() -> None:
    policy = build_policy()
    policy_eq(
        "default-src 'self'; trusted-types strictPolicy laxPolicy default 'allow-duplicates'",
        policy,
    )


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"upgrade-insecure-requests": True}})
def test_upgrade_insecure_requests() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; upgrade-insecure-requests", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"block-all-mixed-content": True}})
def test_block_all_mixed_content() -> None:
    policy = build_policy()
    policy_eq("default-src 'self'; block-all-mixed-content", policy)


def test_nonce() -> None:
    policy = build_policy(nonce="abc123")
    policy_eq("default-src 'self' 'nonce-abc123'", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF], "script-src": [SELF, NONCE], "style-src": [SELF, NONCE]}})
def test_nonce_in_value() -> None:
    policy = build_policy(nonce="abc123")
    policy_eq(
        "default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self' 'nonce-abc123'",
        policy,
    )


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [NONCE]}})
def test_only_nonce_in_value() -> None:
    policy = build_policy(nonce="abc123")
    policy_eq("default-src 'nonce-abc123'", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["example.com", "example.com"]}})
def test_deduplicate_values() -> None:
    """
    GitHub issue #40 - given project settings as a tuple, and
    an update/replace with a string, concatenate correctly.
    """
    policy = build_policy()
    policy_eq("default-src 'self'; img-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["example.com", "example.com"]}})
def test_deduplicate_values_update() -> None:
    """
    GitHub issue #40 - given project settings as a tuple, and
    an update/replace with a string, concatenate correctly.
    """
    policy = build_policy(update={"img-src": "example.com"})
    policy_eq("default-src 'self'; img-src example.com", policy)


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ("example.com",)}})
def test_deduplicate_values_replace() -> None:
    """
    Demonstrate that GitHub issue #40 doesn't affect replacements
    """
    policy = build_policy(replace={"img-src": ["example2.com", "example2.com"]})
    policy_eq("default-src 'self'; img-src example2.com", policy)


def test_boolean_directives() -> None:
    for directive in ["upgrade-insecure-requests", "block-all-mixed-content"]:
        with override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {directive: True}}):
            policy = build_policy()
            policy_eq(f"default-src 'self'; {directive}", policy)
        with override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {directive: False}}):
            policy = build_policy()
            policy_eq("default-src 'self'", policy)


LEGACY_REPORT = {
    "csp-report": {
        "document-uri": "http://example.com/page.html",
        "referrer": "http://example.com/",
        "violated-directive": "img-src https://cdn.example.com",
        "effective-directive": "img-src",
        "original-policy": "default-src 'self'; img-src https://cdn.example.com",
        "disposition": "enforce",
        "blocked-uri": "http://evil.example.com/image.png",
        "line-number": 12,
        "column-number": 34,
        "source-file": "http://example.com/script.js",
        "status-code": 200,
        "script-sample": "",
    }
}

REPORTING_API_REPORT = {
    "type": "csp-violation",
    "url": "http://example.com/page.html",
    "body": {
        "documentURL": "http://example.com/page.html",
        "referrer": "http://example.com/",
        "violatedDirective": "script-src",
        "effectiveDirective": "script-src",
        "originalPolicy": "default-src 'self'",
        "disposition": "report",
        "blockedURL": "eval",
        "lineNumber": 7,
        "columnNumber": 9,
        "sourceFile": "http://example.com/app.js",
        "statusCode": 0,
        "sample": "alert(1)",
    },
}


def test_normalize_legacy_report() -> None:
    event = normalize_violation_report(LEGACY_REPORT)
    assert event["document_uri"] == "http://example.com/page.html"
    assert event["referrer"] == "http://example.com/"
    assert event["violated_directive"] == "img-src https://cdn.example.com"
    assert event["effective_directive"] == "img-src"
    assert event["original_policy"] == "default-src 'self'; img-src https://cdn.example.com"
    assert event["blocked_uri"] == "http://evil.example.com/image.png"
    assert event["source_file"] == "http://example.com/script.js"
    assert event["line_number"] == 12
    assert event["column_number"] == 34
    assert event["status_code"] == 200
    assert event["disposition"] == "enforce"
    assert event["sample"] == ""
    assert event["raw"] == LEGACY_REPORT


def test_normalize_reporting_api_body() -> None:
    event = normalize_violation_report(REPORTING_API_REPORT)
    assert event["document_uri"] == "http://example.com/page.html"
    assert event["violated_directive"] == "script-src"
    assert event["effective_directive"] == "script-src"
    assert event["blocked_uri"] == "eval"
    assert event["line_number"] == 7
    assert event["column_number"] == 9
    assert event["sample"] == "alert(1)"
    assert event["disposition"] == "report"


def test_normalize_accepts_bare_report_body() -> None:
    bare = LEGACY_REPORT["csp-report"]
    event = normalize_violation_report(bare)
    assert event["document_uri"] == "http://example.com/page.html"
    assert event["blocked_uri"] == "http://evil.example.com/image.png"
    assert event["raw"] == bare


def test_normalize_missing_fields_use_unknown() -> None:
    event = normalize_violation_report({"csp-report": {"violated-directive": "script-src"}})
    assert event["document_uri"] == "unknown"
    assert event["referrer"] == "unknown"
    assert event["blocked_uri"] == "unknown"
    assert event["original_policy"] == "unknown"
    assert event["effective_directive"] == "script-src"
    assert event["line_number"] is None
    assert event["column_number"] is None
    assert event["status_code"] is None
    assert event["source_file"] is None
    assert event["sample"] == ""
    assert event["disposition"] == ""


def test_normalize_effective_directive_derived_from_violated() -> None:
    event = normalize_violation_report(
        {"csp-report": {"violated-directive": "style-src 'self'", "document-uri": "http://x"}}
    )
    assert event["effective_directive"] == "style-src"


def test_normalize_int_fields_tolerate_garbage() -> None:
    event = normalize_violation_report(
        {"csp-report": {"line-number": "nope", "column-number": True, "status-code": "418"}}
    )
    assert event["line_number"] is None
    assert event["column_number"] is None
    assert event["status_code"] == 418


def test_normalize_rejects_non_object() -> None:
    with pytest.raises(ValueError):
        normalize_violation_report(["not", "an", "object"])


def test_normalize_rejects_unrelated_object() -> None:
    with pytest.raises(ValueError):
        normalize_violation_report({"unexpected": "payload"})


def test_normalize_rejects_non_csp_reporting_api_type() -> None:
    with pytest.raises(ValueError):
        normalize_violation_report({"type": "deprecation", "body": {"id": "abc"}})


def test_directive_name_strips_source_list() -> None:
    assert directive_name("img-src https://cdn.example.com") == "img-src"
    assert directive_name("script-src") == "script-src"


def test_deduplication_key_uses_source_directive_document() -> None:
    event = normalize_violation_report(LEGACY_REPORT)
    key = deduplication_key(event)
    assert key == (
        "http://evil.example.com/image.png",
        "img-src",
        "http://example.com/page.html",
    )


def test_deduplication_key_collapses_volatile_fields() -> None:
    first = normalize_violation_report(LEGACY_REPORT)
    second_payload = copy.deepcopy(LEGACY_REPORT)
    second_body = second_payload["csp-report"]
    second_body["line-number"] = 999
    second_body["column-number"] = 1
    second_body["violated-directive"] = "img-src 'self'"
    second = normalize_violation_report(second_payload)
    assert deduplication_key(first) == deduplication_key(second)


def test_deduplication_key_distinguishes_sources() -> None:
    first = normalize_violation_report(LEGACY_REPORT)
    other = copy.deepcopy(LEGACY_REPORT)
    other["csp-report"]["blocked-uri"] = "http://other.example.com/x.png"
    assert deduplication_key(first) != deduplication_key(normalize_violation_report(other))
