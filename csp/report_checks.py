from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from django.conf import settings
from django.core import checks
from django.core.checks import Error, register

from csp.reports import ALLOWLIST_SETTING, REPORT_DIRECTIVES, is_allowed_report_endpoint

if TYPE_CHECKING:
    from django.apps.config import AppConfig


POLICY_SETTINGS = (
    "CONTENT_SECURITY_POLICY",
    "CONTENT_SECURITY_POLICY_REPORT_ONLY",
)


def _is_https_origin(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


@register(checks.Tags.security)
def check_report_endpoints(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    """Validate report-uri/report-to endpoints and the report allowlist.

    Reporting endpoints must be relative (same-origin), a bare report-to
    group token, or an absolute https URL whose origin is explicitly listed
    in REPORT_ALLOWLIST. Non-https allowlist entries are configuration
    conflicts because the allowlist may only name https origins.
    """
    errors: list[Error] = []
    for setting_name in POLICY_SETTINGS:
        policy = getattr(settings, setting_name, None)
        if not isinstance(policy, dict):
            continue

        allowlist = policy.get(ALLOWLIST_SETTING) or []
        if isinstance(allowlist, str) or not isinstance(allowlist, (list, tuple)):
            errors.append(
                Error(
                    f"{ALLOWLIST_SETTING} in {setting_name} settings must be a list or tuple of https origins.",
                    id="csp.E003",
                )
            )
            continue

        allowed_origins: list[str] = []
        for entry in allowlist:
            entry = str(entry)
            if not _is_https_origin(entry):
                errors.append(
                    Error(
                        f"Invalid {ALLOWLIST_SETTING} entry {entry!r} in {setting_name}: only https origins are allowed.",
                        id="csp.E003",
                    )
                )
            else:
                allowed_origins.append(entry)

        directives = policy.get("DIRECTIVES") or {}
        for directive in REPORT_DIRECTIVES:
            values = directives.get(directive)
            if values is None:
                continue
            endpoints = [values] if isinstance(values, (str, bytes)) else list(values)
            for value in endpoints:
                endpoint = str(value)
                if not is_allowed_report_endpoint(endpoint, request=None, allowed_origins=allowed_origins):
                    errors.append(
                        Error(
                            f"Invalid {directive} endpoint {endpoint!r} in {setting_name}: reporting endpoints must be "
                            f"relative (same-origin) or an https origin listed in {ALLOWLIST_SETTING}.",
                            id="csp.E004",
                        )
                    )

    return errors
