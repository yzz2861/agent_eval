from __future__ import annotations

# Per-request override attributes. These mirror the per-response attributes set
# by the decorators in ``csp.decorators`` but are read from the ``HttpRequest``,
# allowing middleware or the view itself to adjust the policy for a single
# request without touching the response object.

# Full policy override (replaces the settings-based config).
REQUEST_CONFIG = "_csp_request_config"
REQUEST_CONFIG_RO = "_csp_request_config_ro"
# Values appended to the configured policy.
REQUEST_UPDATE = "_csp_request_update"
REQUEST_UPDATE_RO = "_csp_request_update_ro"
# Values replacing the configured policy directives.
REQUEST_REPLACE = "_csp_request_replace"
REQUEST_REPLACE_RO = "_csp_request_replace_ro"
# Exemption flags.
REQUEST_EXEMPT = "_csp_request_exempt"
REQUEST_EXEMPT_RO = "_csp_request_exempt_ro"

# When ``True`` the enforced policy is emitted using the report-only header for
# this request instead of the enforcement header, and the standalone
# report-only policy is suppressed to avoid emitting the same policy twice.
REQUEST_REPORT_ONLY = "_csp_report_only"
