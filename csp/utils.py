from __future__ import annotations

import copy
import re
from itertools import chain
from typing import Any, Callable

from django.conf import settings
from django.utils.encoding import force_str

from csp.constants import NONCE, SELF

# Placeholder used when a violation report omits a field. It keeps the
# normalized event auditable without crashing on incomplete browser payloads.
REPORT_UNKNOWN = "unknown"

# ``type`` value used by the Reporting API (``report-to``) for CSP violations.
REPORT_TYPE_CSP_VIOLATION = "csp-violation"

DEFAULT_DIRECTIVES = {
    # Fetch Directives
    "child-src": None,
    "connect-src": None,
    "default-src": [SELF],
    "script-src": None,
    "script-src-attr": None,
    "script-src-elem": None,
    "object-src": None,
    "style-src": None,
    "style-src-attr": None,
    "style-src-elem": None,
    "font-src": None,
    "frame-src": None,
    "img-src": None,
    "manifest-src": None,
    "media-src": None,
    "prefetch-src": None,  # Deprecated.
    # Document Directives
    "base-uri": None,
    "plugin-types": None,  # Deprecated.
    "sandbox": None,
    # Navigation Directives
    "form-action": None,
    "frame-ancestors": None,
    "navigate-to": None,
    # Reporting Directives
    "report-uri": None,
    "report-to": None,
    "require-sri-for": None,
    # Trusted Types Directives
    "require-trusted-types-for": None,
    "trusted-types": None,
    # Other Directives
    "webrtc": None,
    "worker-src": None,
    # Directives Defined in Other Documents
    "upgrade-insecure-requests": False,
    "block-all-mixed-content": False,  # Deprecated.
}

DIRECTIVES_T = dict[str, Any]


def default_config(csp: DIRECTIVES_T | None) -> DIRECTIVES_T | None:
    if csp is None:
        return None
    # Make a copy of the passed in config to avoid mutating it, and also to drop any unknown keys.
    config = {}
    for key, value in DEFAULT_DIRECTIVES.items():
        config[key] = csp.get(key, value)
    return config


def build_policy(
    config: DIRECTIVES_T | None = None,
    update: DIRECTIVES_T | None = None,
    replace: DIRECTIVES_T | None = None,
    nonce: str | None = None,
    report_only: bool = False,
) -> str:
    """Builds the policy as a string from the settings."""

    if config is None:
        if report_only:
            config = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None
        else:
            config = getattr(settings, "CONTENT_SECURITY_POLICY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None

    # If config is still `None`, return empty policy.
    if config is None:
        return ""

    update = update if update is not None else {}
    replace = replace if replace is not None else {}

    csp = {}

    for k in set(chain(config, replace)):
        if k in replace:
            v = replace[k]
        else:
            v = config[k]
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            csp[k] = v

    for k, v in update.items():
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            if csp.get(k) is None:
                csp[k] = v
            else:
                csp[k] += tuple(v)

    report_uri = csp.pop("report-uri", None)

    policy_parts = {}

    for key, value in csp.items():
        # Check for boolean directives.
        if len(value) == 1 and isinstance(value[0], bool):
            if value[0] is True:
                policy_parts[key] = ""
            continue
        if NONCE in value:
            if nonce:
                value = [f"'nonce-{nonce}'" if v == NONCE else v for v in value]
            else:
                # Strip the `NONCE` sentinel value if no nonce is provided.
                value = [v for v in value if v != NONCE]

        value = list(dict.fromkeys(value))  # Deduplicate
        policy_parts[key] = " ".join(value)

    if report_uri:
        report_uri = map(force_str, report_uri)
        policy_parts["report-uri"] = " ".join(report_uri)

    return "; ".join([f"{k} {val}".strip() for k, val in policy_parts.items()])


def _default_attr_mapper(attr_name: str, val: str) -> str:
    if val:
        return f' {attr_name}="{val}"'
    else:
        return ""


def _bool_attr_mapper(attr_name: str, val: bool) -> str:
    # Only return the bare word if the value is truthy
    # ie - defer=False should actually return an empty string
    if val:
        return f" {attr_name}"
    else:
        return ""


def _async_attr_mapper(attr_name: str, val: str | bool) -> str:
    """The `async` attribute works slightly different than the other bool
    attributes. It can be set explicitly to `false` with no surrounding quotes
    according to the spec."""
    if val in [False, "False"]:
        return f" {attr_name}=false"
    elif val:
        return f" {attr_name}"
    else:
        return ""


# Allow per-attribute customization of returned string template
SCRIPT_ATTRS: dict[str, Callable[[str, Any], str]] = {
    "nonce": _default_attr_mapper,
    "id": _default_attr_mapper,
    "src": _default_attr_mapper,
    "type": _default_attr_mapper,
    "async": _async_attr_mapper,
    "defer": _bool_attr_mapper,
    "integrity": _default_attr_mapper,
    "nomodule": _bool_attr_mapper,
}

# Generates an interpolatable string of valid attrs eg - '{nonce}{id}...'
ATTR_FORMAT_STR = "".join([f"{{{a}}}" for a in SCRIPT_ATTRS])


_script_tag_contents_re = re.compile(
    r"""<script        # match the opening script tag
            [\s|\S]*?> # minimally match attrs and spaces in opening script tag
    ([\s|\S]+)         # greedily capture the script tag contents
    </script>          # match the closing script tag
""",
    re.VERBOSE,
)


def _unwrap_script(text: str) -> str:
    """Extract content defined between script tags"""
    matches = re.search(_script_tag_contents_re, text)
    if matches and len(matches.groups()):
        return matches.group(1).strip()

    return text


def build_script_tag(content: str | None = None, **kwargs: Any) -> str:
    data = {}
    # Iterate all possible script attrs instead of kwargs to make
    # interpolation as easy as possible below
    for attr_name, mapper in SCRIPT_ATTRS.items():
        data[attr_name] = mapper(attr_name, kwargs.get(attr_name))

    # Don't render block contents if the script has a 'src' attribute
    c = _unwrap_script(content) if content and not kwargs.get("src") else ""
    attrs = ATTR_FORMAT_STR.format(**data).rstrip()
    return f"<script{attrs}>{c}</script>".strip()


def _normalized_string(value: Any) -> str:
    if value is None:
        return REPORT_UNKNOWN
    if isinstance(value, str):
        return value
    return force_str(value)


def _normalized_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None


def _extract_report_body(payload: Any) -> dict[str, Any]:
    """Return the violation body for either supported report shape.

    The legacy ``report-uri`` shape wraps the data in a ``csp-report`` key,
    while the Reporting API (``report-to``) uses ``type``/``body``.
    """
    if not isinstance(payload, dict):
        raise ValueError("CSP violation report must be a JSON object")

    if isinstance(payload.get("csp-report"), dict):
        return payload["csp-report"]

    if isinstance(payload.get("body"), dict):
        report_type = payload.get("type")
        if report_type is None or report_type == REPORT_TYPE_CSP_VIOLATION:
            return payload["body"]

    if "document-uri" in payload or "violated-directive" in payload:
        return payload

    raise ValueError("CSP violation report contains no recognizable report body")


def directive_name(directive: str) -> str:
    """Return the directive name without any source-list value.

    Browsers send ``violated-directive`` as e.g. ``"img-src https://example.com"``;
    only the leading token identifies the directive.
    """
    return directive.strip().split(" ", 1)[0]


def normalize_violation_report(payload: Any) -> dict[str, Any]:
    """Normalize a raw CSP violation report into a flat, auditable event dict.

    Missing or malformed fields fall back to safe defaults (``"unknown"`` for
    strings, ``None`` for numbers) instead of raising, so partial browser
    payloads can still be recorded. Raises ``ValueError`` only when the payload
    does not contain any recognizable violation body.
    """
    body = _extract_report_body(payload)

    def _field(legacy_key: str, reporting_key: str | None = None) -> Any:
        """Read a field supporting both legacy kebab-case and Reporting API camelCase names."""
        if legacy_key in body:
            return body[legacy_key]
        if reporting_key is not None and reporting_key in body:
            return body[reporting_key]
        return None

    document_uri_value = _field("document-uri", "documentURL") or body.get("url")
    violated_directive = _normalized_string(_field("violated-directive", "violatedDirective"))
    effective_directive = _normalized_string(_field("effective-directive", "effectiveDirective"))
    if effective_directive == REPORT_UNKNOWN and violated_directive != REPORT_UNKNOWN:
        effective_directive = directive_name(violated_directive)
    elif effective_directive != REPORT_UNKNOWN:
        effective_directive = directive_name(effective_directive)

    return {
        "document_uri": _normalized_string(document_uri_value),
        "referrer": _normalized_string(_field("referrer")),
        "violated_directive": violated_directive,
        "effective_directive": effective_directive,
        "original_policy": _normalized_string(_field("original-policy", "originalPolicy")),
        "blocked_uri": _normalized_string(_field("blocked-uri", "blockedURL")),
        "source_file": _normalized_string(_field("source-file", "sourceFile")) if _field("source-file", "sourceFile") is not None else None,
        "line_number": _normalized_int(_field("line-number", "lineNumber")),
        "column_number": _normalized_int(_field("column-number", "columnNumber")),
        "sample": _normalized_string(_field("script-sample", "sample")) if _field("script-sample", "sample") is not None else "",
        "disposition": _normalized_string(_field("disposition")) if _field("disposition") is not None else "",
        "status_code": _normalized_int(_field("status-code", "statusCode")),
        "raw": payload if isinstance(payload, dict) else {},
    }


def deduplication_key(normalized: dict[str, Any]) -> tuple[str, str, str]:
    """Build the source/directive/document-uri tuple used for dedup and throttling.

    The directive is reduced to its name only, and the blocked URI is treated as
    the violation source, so reports differing only in source-list values or
    volatile fields (line numbers, samples) collapse into one auditable event.
    """
    source = _normalized_string(normalized.get("blocked_uri"))
    directive = directive_name(_normalized_string(normalized.get("violated_directive")))
    document_uri = _normalized_string(normalized.get("document_uri"))
    return (source, directive, document_uri)
