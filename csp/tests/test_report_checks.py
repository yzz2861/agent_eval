from django.test.utils import override_settings

from csp.report_checks import check_report_endpoints


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": ["http://evil.example.com/report"]}}
)
def test_check_flags_insecure_report_uri() -> None:
    errors = check_report_endpoints(None)
    assert any(error.id == "csp.E004" for error in errors)
    assert errors


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": ["https://evil.example.com/report"]}}
)
def test_check_flags_cross_origin_https_without_allowlist() -> None:
    errors = check_report_endpoints(None)
    assert any(error.id == "csp.E004" for error in errors)


@override_settings(
    CONTENT_SECURITY_POLICY={
        "REPORT_ALLOWLIST": ["https://reports.example.com"],
        "DIRECTIVES": {"report-uri": ["https://reports.example.com/collect"]},
    }
)
def test_check_accepts_allowlisted_https_origin() -> None:
    assert check_report_endpoints(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-uri": ["/csp-report/"]}}
)
def test_check_accepts_relative_same_origin_endpoint() -> None:
    assert check_report_endpoints(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"report-to": ["endpoint-group"]}}
)
def test_check_accepts_bare_report_to_token() -> None:
    assert check_report_endpoints(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"REPORT_ALLOWLIST": ["http://insecure.example.com"]}
)
def test_check_flags_non_https_allowlist_entry() -> None:
    errors = check_report_endpoints(None)
    assert any(error.id == "csp.E003" for error in errors)


@override_settings(
    CONTENT_SECURITY_POLICY={"REPORT_ALLOWLIST": "https://reports.example.com"}
)
def test_check_flags_string_allowlist() -> None:
    errors = check_report_endpoints(None)
    assert any(error.id == "csp.E003" for error in errors)


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"report-uri": ["http://evil.example.com/report"]}}
)
def test_check_covers_report_only_setting() -> None:
    errors = check_report_endpoints(None)
    assert any(error.id == "csp.E004" and "CONTENT_SECURITY_POLICY_REPORT_ONLY" in error.msg for error in errors)

