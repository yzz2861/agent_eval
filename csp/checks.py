from __future__ import annotations

import pprint
from collections.abc import Sequence
from importlib.metadata import version
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from django.conf import settings
from django.core import checks
from django.core.checks import Error, Warning, register

from packaging.version import Version

from csp.constants import NONCE
from csp.utils import DEFAULT_DIRECTIVES

if TYPE_CHECKING:
    from django.apps.config import AppConfig


#: Settings keys that hold a full CSP policy configuration.
POLICY_SETTINGS = (
    "CONTENT_SECURITY_POLICY",
    "CONTENT_SECURITY_POLICY_REPORT_ONLY",
)

#: Directives that have been removed or deprecated by the CSP specification.
#: They still work in some browsers, but projects should migrate away from them.
DEPRECATED_DIRECTIVES = frozenset(
    {
        "prefetch-src",
        "plugin-types",
        "block-all-mixed-content",
        "report-uri",
    }
)

#: Directives whose values are source expressions and therefore accept the
#: ``NONCE`` sentinel / ``'nonce-...'`` and ``'<alg>-...'`` hash expressions.
NONCE_HASH_DIRECTIVES = frozenset(
    {
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "worker-src",
        "child-src",
        "default-src",
    }
)

#: Directives whose values are URIs rather than host sources.
URI_DIRECTIVES = frozenset({"report-uri"})

#: Accepted CSP hash algorithms.
HASH_ALGORITHMS = ("sha256", "sha384", "sha512")


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


def _iter_policies() -> list[tuple[str, dict[str, Any]]]:
    """Yield ``(setting_name, policy_dict)`` for every configured policy."""
    policies: list[tuple[str, dict[str, Any]]] = []
    for setting_name in POLICY_SETTINGS:
        config = getattr(settings, setting_name, None)
        if isinstance(config, dict):
            policies.append((setting_name, config))
    return policies


def _as_list(value: Any) -> list[Any]:
    """Normalize a directive value into a list, mirroring ``build_policy``."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _is_hash_expression(value: Any) -> bool:
    return isinstance(value, str) and any(value.startswith(f"'{alg}-") for alg in HASH_ALGORITHMS)


def _is_nonce_expression(value: Any) -> bool:
    return value is NONCE or (isinstance(value, str) and value.startswith("'nonce-"))


def _is_valid_uri(value: Any) -> bool:
    """
    Validate a URI expression used by reporting directives.

    Relative references (e.g. ``/csp-report/``) and fully qualified URLs are both allowed. A value
    containing whitespace cannot be expressed as a single CSP source and is rejected.
    """
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        return False
    parsed = urlsplit(value)
    # A scheme, when present, must be followed by ``://`` (an absolute URI) rather than be a
    # relative reference such as ``example.com/path`` which is ambiguous with a host source.
    if parsed.scheme and not value.startswith(f"{parsed.scheme}://"):
        return False
    return True


def _normalize_directives(directives: dict[str, Any]) -> dict[str, list[Any]]:
    """Normalize directives into order-insensitive, duplicate-free source lists."""
    normalized: dict[str, list[Any]] = {}
    for directive, value in directives.items():
        normalized[directive] = sorted(set(_as_list(value)), key=str)
    return normalized


@register(checks.Tags.security)
def check_directive_names(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error | Warning]:
    """Warn about deprecated directives and error on directives django-csp does not know about."""
    messages: list[Error | Warning] = []
    for setting_name, policy in _iter_policies():
        directives = policy.get("DIRECTIVES")
        if not isinstance(directives, dict):
            continue
        for directive in directives:
            if directive not in DEFAULT_DIRECTIVES:
                messages.append(
                    Error(
                        f"Unknown directive {directive!r} in {setting_name} is not a supported CSP directive "
                        "and will be dropped from the policy.",
                        hint=f"Supported directives: {', '.join(sorted(DEFAULT_DIRECTIVES))}.",
                        id="csp.E003",
                    )
                )
            elif directive in DEPRECATED_DIRECTIVES:
                messages.append(
                    Warning(
                        f"Directive {directive!r} in {setting_name} is deprecated and support may be removed "
                        "from browsers. Consider migrating to a modern alternative.",
                        id="csp.W001",
                    )
                )
    return messages


@register(checks.Tags.security)
def check_uri_sources(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    """Validate the URI syntax of reporting directives."""
    messages: list[Error] = []
    for setting_name, policy in _iter_policies():
        directives = policy.get("DIRECTIVES")
        if not isinstance(directives, dict):
            continue
        for directive in URI_DIRECTIVES:
            for value in _as_list(directives.get(directive)):
                if not _is_valid_uri(value):
                    messages.append(
                        Error(
                            f"Invalid URI {value!r} in {directive!r} of {setting_name}. "
                            "Use an absolute URL or a same-site relative path without whitespace.",
                            id="csp.E004",
                        )
                    )
    return messages


@register(checks.Tags.security)
def check_nonce_hash_conflicts(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Warning]:
    """
    Warn when a directive relies on both nonces and hashes.

    Browsers implementing CSP Level 2 ignore hash expressions when a nonce is present, so combining
    them usually indicates a misconfiguration rather than a deliberate defense in depth.
    """
    messages: list[Warning] = []
    for setting_name, policy in _iter_policies():
        directives = policy.get("DIRECTIVES")
        if not isinstance(directives, dict):
            continue
        for directive, value in directives.items():
            if directive not in NONCE_HASH_DIRECTIVES:
                continue
            sources = _as_list(value)
            has_nonce = any(_is_nonce_expression(source) for source in sources)
            has_hash = any(_is_hash_expression(source) for source in sources)
            if has_nonce and has_hash:
                messages.append(
                    Warning(
                        f"Directive {directive!r} in {setting_name} combines a nonce with a hash expression. "
                        "CSP Level 2 browsers ignore hashes when a nonce is present, so the hash may have no effect.",
                        hint="Prefer a single mechanism; keep the hash only for browsers without nonce support.",
                        id="csp.W002",
                    )
                )
    return messages


@register(checks.Tags.security)
def check_duplicate_sources(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Warning]:
    """Warn about repeated source expressions within a directive."""
    messages: list[Warning] = []
    for setting_name, policy in _iter_policies():
        directives = policy.get("DIRECTIVES")
        if not isinstance(directives, dict):
            continue
        for directive, value in directives.items():
            sources = _as_list(value)
            seen: set[Any] = set()
            duplicates: set[Any] = set()
            for source in sources:
                if source in seen:
                    duplicates.add(source)
                seen.add(source)
            if duplicates:
                rendered = ", ".join(repr(source) for source in sorted(duplicates, key=str))
                messages.append(
                    Warning(
                        f"Directive {directive!r} in {setting_name} contains duplicate source(s): {rendered}. "
                        "Duplicates are ignored by browsers and make the policy harder to review.",
                        id="csp.W003",
                    )
                )
    return messages


@register(checks.Tags.security)
def check_report_only_consistency(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Warning]:
    """
    Warn when the report-only and enforced policies diverge.

    A report-only policy is meant to preview changes to the enforced policy. When the two policies
    define different sources for the same directive, violations reported in report-only mode will
    not match the headers that are actually enforced.
    """
    enforce = getattr(settings, "CONTENT_SECURITY_POLICY", None)
    report_only = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None)
    if not isinstance(enforce, dict) or not isinstance(report_only, dict):
        return []

    enforce_directives = _normalize_directives(enforce.get("DIRECTIVES") or {})
    report_directives = _normalize_directives(report_only.get("DIRECTIVES") or {})

    messages: list[Warning] = []
    for directive in sorted(set(enforce_directives) & set(report_directives)):
        if enforce_directives[directive] != report_directives[directive]:
            messages.append(
                Warning(
                    f"Directive {directive!r} differs between CONTENT_SECURITY_POLICY and "
                    "CONTENT_SECURITY_POLICY_REPORT_ONLY. Report-only findings may not reflect what is enforced.",
                    hint="Keep shared directives aligned, or add the directive only to the policy that needs it.",
                    id="csp.W004",
                )
            )
    return messages
