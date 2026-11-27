from __future__ import annotations

import pprint
from collections.abc import Sequence
from importlib.metadata import version
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core import checks
from django.core.checks import Error, register
from django.test.utils import override_settings

from packaging.version import Version

from csp.constants import HEADER, NONCE

if TYPE_CHECKING:
    from django.apps.config import AppConfig


OUTDATED_SETTINGS = [
    "CSP_CHILD_SRC",
    "CSP_CONNECT_SRC",
    "CSP_DEFAULT_SRC",
    "CSP_SCRIPT_SRC",
    "CSP_SCRIPT_SRC_ATTR",
    "CSP_SCRIPT_SRC_ELEM",
    "CSP_OBJECT_SRC",
    "CSP_STYLE_SRC",
    "CSP_STYLE_SRC_ATTR",
    "CSP_STYLE_SRC_ELEM",
    "CSP_FONT_SRC",
    "CSP_FRAME_SRC",
    "CSP_IMG_SRC",
    "CSP_MANIFEST_SRC",
    "CSP_MEDIA_SRC",
    "CSP_PREFETCH_SRC",
    "CSP_WORKER_SRC",
    "CSP_BASE_URI",
    "CSP_PLUGIN_TYPES",
    "CSP_SANDBOX",
    "CSP_FORM_ACTION",
    "CSP_FRAME_ANCESTORS",
    "CSP_NAVIGATE_TO",
    "CSP_REQUIRE_SRI_FOR",
    "CSP_REQUIRE_TRUSTED_TYPES_FOR",
    "CSP_TRUSTED_TYPES",
    "CSP_UPGRADE_INSECURE_REQUESTS",
    "CSP_BLOCK_ALL_MIXED_CONTENT",
    "CSP_REPORT_URI",
    "CSP_REPORT_TO",
]


def migrate_settings() -> tuple[dict[str, Any], bool]:
    # This function is used to migrate settings from the old format to the new format.
    config: dict[str, Any] = {
        "DIRECTIVES": {},
    }

    REPORT_ONLY = getattr(settings, "CSP_REPORT_ONLY", False)

    _EXCLUDE_URL_PREFIXES = getattr(settings, "CSP_EXCLUDE_URL_PREFIXES", None)
    if _EXCLUDE_URL_PREFIXES is not None:
        config["EXCLUDE_URL_PREFIXES"] = _EXCLUDE_URL_PREFIXES

    _REPORT_PERCENTAGE = getattr(settings, "CSP_REPORT_PERCENTAGE", None)
    if _REPORT_PERCENTAGE is not None:
        config["REPORT_PERCENTAGE"] = _REPORT_PERCENTAGE * 100

    include_nonce_in = getattr(settings, "CSP_INCLUDE_NONCE_IN", [])

    for setting in OUTDATED_SETTINGS:
        if hasattr(settings, setting):
            directive = setting[4:].replace("_", "-").lower()
            value = getattr(settings, setting)
            if value:
                config["DIRECTIVES"][directive] = value
            if directive in include_nonce_in:
                config["DIRECTIVES"][directive].append(NONCE)

    return config, REPORT_ONLY


@register(checks.Tags.security)
def check_django_csp_lt_4_0(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    check_settings = OUTDATED_SETTINGS + ["CSP_REPORT_ONLY", "CSP_EXCLUDE_URL_PREFIXES", "CSP_REPORT_PERCENTAGE"]
    if any(hasattr(settings, setting) for setting in check_settings):
        # Try to build the new config.
        config, REPORT_ONLY = migrate_settings()
        warning = (
            "You are using django-csp < 4.0 settings. Please update your settings to use the new format.\n"
            "See https://django-csp.readthedocs.io/en/latest/migration-guide.html for more information.\n\n"
            "We have attempted to build the new CSP config for you based on your current settings:\n\n"
            f"CONTENT_SECURITY_POLICY{'_REPORT_ONLY' if REPORT_ONLY else ''} = " + pprint.pformat(config, sort_dicts=True)
        )
        return [Error(warning, id="csp.E001")]

    return []


@register(checks.Tags.security)
def check_exclude_url_prefixes_is_not_string(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    """
    Check that EXCLUDE_URL_PREFIXES in settings is not a string.

    If it is a string it can lead to a security issue where the string is treated as a list of
    characters, resulting in '/' matching all paths excluding the CSP header from all responses.

    """
    # Skip check for django-csp < 4.0.
    if Version(version("django-csp")) < Version("4.0a1"):
        return []

    errors = []
    keys = (
        "CONTENT_SECURITY_POLICY",
        "CONTENT_SECURITY_POLICY_REPORT_ONLY",
    )
    for key in keys:
        config = getattr(settings, key, {})
        if isinstance(config, dict) and isinstance(config.get("EXCLUDE_URL_PREFIXES"), str):
            errors.append(
                Error(
                    f"EXCLUDE_URL_PREFIXES in {key} settings must be a list or tuple.",
                    id="csp.E002",
                )
            )

    return errors


SITE_CHECK_STATUS_RANGES = {
    "ok": range(200, 300),
    "redirect": range(300, 400),
    "error": range(400, 600),
}


def _parse_csp_header(header: str) -> dict[str, set[str]]:
    directives: dict[str, set[str]] = {}
    for part in header.split(";"):
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = set(tokens[1:])
    return directives


def _normalize_expected_directives(expect: dict[str, Any]) -> dict[str, set[str]]:
    normalized = {}
    for directive, values in expect.items():
        if values is None:
            normalized[directive.lower()] = set()
        elif isinstance(values, str):
            normalized[directive.lower()] = {values}
        else:
            normalized[directive.lower()] = {str(value) for value in values}
    return normalized


@register(checks.Tags.security)
def check_site_csp_headers(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    """
    Local regression check for the per-site CSP registry.

    Sites are registered in the CSP_SITE_CHECKS setting, keyed by site name. Each site registers
    fixed synthetic requests for the "ok", "error" and "redirect" response kinds, along with the
    CSP directives the site is responsible for:

    CSP_SITE_CHECKS = {
        "main": {
            "ok": {"path": "/", "expect": {"default-src": ["'self'"]}},
            "error": {"path": "/missing/", "expect": {"default-src": ["'self'"]}},
            "redirect": {"path": "/old/", "expect": {"default-src": ["'self'"]}},
        },
    }

    The check issues the synthetic requests locally and verifies the Content-Security-Policy
    response headers against the registered responsibilities. Error pages may be generated by a
    shared layer, so each response kind is checked independently.
    """
    registry = getattr(settings, "CSP_SITE_CHECKS", None)
    if registry is None:
        return []
    if not isinstance(registry, dict):
        return [Error("CSP_SITE_CHECKS must be a dict keyed by site name.", id="csp.E003")]

    from django.test import Client

    errors: list[Error] = []
    allowed_hosts = list(getattr(settings, "ALLOWED_HOSTS", []))
    if "testserver" not in allowed_hosts:
        allowed_hosts.append("testserver")

    with override_settings(ALLOWED_HOSTS=allowed_hosts, DEBUG=False):
        client = Client(raise_request_exception=False)
        for site, spec in registry.items():
            if not isinstance(spec, dict):
                errors.append(Error(f"CSP_SITE_CHECKS['{site}'] must be a dict of synthetic request specs.", id="csp.E003"))
                continue
            for kind, status_range in SITE_CHECK_STATUS_RANGES.items():
                entry = spec.get(kind)
                if entry is None:
                    continue
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    errors.append(Error(f"CSP_SITE_CHECKS['{site}']['{kind}'] must be a dict with a 'path' string.", id="csp.E003"))
                    continue
                expect = entry.get("expect", {})
                if not isinstance(expect, dict):
                    errors.append(Error(f"CSP_SITE_CHECKS['{site}']['{kind}']['expect'] must be a dict of directives.", id="csp.E003"))
                    continue
                path = entry["path"]
                try:
                    response = client.get(path)
                except Exception as exc:
                    errors.append(Error(f"CSP site check for site '{site}' ({kind}: {path}) raised {exc!r}.", id="csp.E004"))
                    continue
                if response.status_code not in status_range:
                    errors.append(
                        Error(
                            f"CSP site check for site '{site}' expected a {kind} response "
                            f"({status_range.start}s) from {path} but got status {response.status_code}.",
                            id="csp.E004",
                        )
                    )
                    continue
                header = response.headers.get(HEADER, "")
                if not header:
                    errors.append(
                        Error(
                            f"CSP site check for site '{site}' ({kind}: {path}) returned no Content-Security-Policy header.",
                            id="csp.E005",
                        )
                    )
                    continue
                actual = _parse_csp_header(header)
                expected = _normalize_expected_directives(expect)
                problems = []
                for directive, values in expected.items():
                    if directive not in actual:
                        suffix = f" (expected values: {' '.join(sorted(values))})" if values else ""
                        problems.append(f"directive '{directive}' is missing{suffix}")
                    else:
                        missing = values - actual[directive]
                        if missing:
                            problems.append(f"directive '{directive}' is missing values: {' '.join(sorted(missing))}")
                if problems:
                    errors.append(
                        Error(
                            f"CSP site check for site '{site}' ({kind}: {path}) failed: " + "; ".join(problems) + ".",
                            id="csp.E006",
                        )
                    )
    return errors
