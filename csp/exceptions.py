class CSPNonceError(Exception):
    pass


class CSPReportEndpointError(ValueError):
    """Raised when a ``report-uri``/``report-to`` endpoint is not allowed.

    Reporting endpoints must be same-origin (a relative path, or an absolute
    ``https`` URL whose origin matches the request) or explicitly listed in the
    ``REPORT_ALLOWLIST`` policy setting.
    """
