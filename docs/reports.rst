.. _reports-chapter:

=====================
CSP Violation Reports
=====================

When something on a page violates the Content-Security-Policy, and the policy defines a
``report-uri`` directive, the user agent may POST a report_. Reports are JSON blobs containing
information about how the policy was violated.

Note: django-csp no longer handles report processing itself, so you will need to stand up your own
app to receive them, or else make use of a third-party report processing service.


Throttling the number of reports
--------------------------------
To throttle the number of requests made to your ``report-uri`` endpoint, you can use
``csp.contrib.rate_limiting.RateLimitedCSPMiddleware`` instead of ``csp.middleware.CSPMiddleware``
and set the ``REPORT_PERCENTAGE`` option:

``REPORT_PERCENTAGE``
    Percentage of requests that should see the ``report-uri`` directive.  Use this to throttle the
    number of CSP violation reports made to your ``report-uri``. A **float** between 0.0 and 100.0
    (0.0 = no reports at all, 100.0 = always report).  Ignored if ``report-uri`` isn't set.

.. _report: http://www.w3.org/TR/CSP/#sample-violation-report

Endpoint security
------------------

Reporting endpoints receive detailed information about violations (and the
pages on which they occurred), so django-csp validates every ``report-uri`` and
``report-to`` endpoint before it is written to a header. An endpoint is only
accepted when it is one of:

* a relative reference such as ``/csp-report/``, which is same-origin by
  construction (including scheme-relative ``//host/path`` URLs on secure
  requests);
* a bare ``report-to`` group token (a non-URL identifier matching a
  ``Reporting-Endpoints`` header), which is not an exfiltration URL;
* an absolute ``https`` URL that is same-origin with the current request;
* an absolute ``https`` URL whose origin is explicitly listed in the
  ``REPORT_ALLOWLIST`` policy setting.

Plain ``http`` URLs and cross-origin ``https`` URLs that are not allowlisted
are rejected. At request time an invalid endpoint raises
``csp.exceptions.CSPReportEndpointError``; the same problems in the global
settings are reported by Django system checks (``csp.E003`` for a malformed
allowlist and ``csp.E004`` for a disallowed endpoint).

Configure trusted third-party report collectors per policy, for example:

.. code-block:: python

    CONTENT_SECURITY_POLICY = {
        "REPORT_ALLOWLIST": ["https://reports.example.com"],
        "DIRECTIVES": {
            "default-src": ["example.com"],
            "report-uri": ["https://reports.example.com/collect"],
        },
    }
