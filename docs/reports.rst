.. _reports-chapter:

=====================
CSP Violation Reports
=====================

When something on a page violates the Content-Security-Policy, and the policy defines a
``report-uri`` directive, the user agent may POST a report_. Reports are JSON blobs containing
information about how the policy was violated.

django-csp ships an optional report-receiving endpoint that parses those reports, normalizes them
into auditable events, deduplicates them, and applies a sliding-window rate limit. Both the legacy
``report-uri`` payload (``{"csp-report": {...}}``) and the Reporting API / ``report-to`` payload
(``{"type": "csp-violation", "body": {...}}``) are accepted.

.. contents:: On this page
   :local:


Configuration
-------------

All endpoint settings live in an optional ``CSP_REPORTS`` dictionary. Every key has a sensible
default, so the setting can be omitted entirely::

    CSP_REPORTS = {
        # Path handled by ReportEndpointMiddleware (the view can be mounted anywhere).
        "PATH": "/csp/report/",
        # Dotted path to a csp.reports.storage.ReportStorage implementation.
        "STORAGE": "csp.reports.storage.InMemoryStorage",
        # Sliding-window rate limit applied per source/directive pair.
        "RATE_LIMIT": {
            "MAX_EVENTS": 100,
            "WINDOW_SECONDS": 60.0,
        },
    }


Wiring up the endpoint
----------------------

There are two ways to expose the report endpoint.

**URLconf view.** Add ``csp.reports.views.report_uri`` to your ``urlpatterns``::

    from django.urls import path

    from csp.reports.views import report_uri

    urlpatterns = [
        path("csp/report/", report_uri, name="csp-report"),
    ]

Then point the policy at it, for example with the ``report-uri`` directive::

    CONTENT_SECURITY_POLICY = {
        "DIRECTIVES": {
            "default-src": ["'self'"],
            "report-uri": "/csp/report/",
        }
    }

**Middleware.** If you would rather not add a URLconf entry, add
``csp.reports.ReportEndpointMiddleware`` to ``MIDDLEWARE``. Requests whose path matches
``CSP_REPORTS["PATH"]`` are handled directly by the report view::

    MIDDLEWARE = (
        # ...
        "csp.reports.ReportEndpointMiddleware",
    )

The endpoint only accepts ``POST`` requests (other methods receive ``405 Method Not Allowed``).
Malformed JSON and payloads without a recognizable report body receive ``400 Bad Request``.
Stored, duplicated and rate-limited reports all return ``202 Accepted`` so browsers do not retry
them; the JSON response body describes the outcome (``stored``, ``duplicate``, ``rate_limited`` or
``invalid``).


Normalized events
-----------------

Raw browser payloads are normalized by ``csp.utils.normalize_violation_report`` into a flat
``csp.reports.CSPViolationEvent``. Missing or malformed fields never discard a report: string fields
fall back to ``"unknown"`` and numeric fields (``line_number``, ``column_number``, ``status_code``)
fall back to ``None``. The original payload is retained on ``CSPViolationEvent.raw`` for auditing.


Deduplication and rate limiting
-------------------------------

Each event is identified by a ``(source, directive, document-uri)`` tuple built by
``csp.utils.deduplication_key``. The directive is reduced to its name (for example ``img-src`` from
``img-src https://cdn.example.com``) and the blocked URI is used as the source, so reports that only
differ in volatile details (line numbers, columns, script samples, source-list values) collapse into
a single auditable event.

- Reports whose tuple has already been stored are marked ``duplicate`` and not written again.
- ``csp.reports.RateLimiter`` implements a sliding window: at most ``MAX_EVENTS`` attempts per
  source/directive pair are accepted within any rolling ``WINDOW_SECONDS`` interval. Further
  attempts are marked ``rate_limited``.

The default ``InMemoryStorage`` keeps events in process memory and is intended for tests and small
deployments. For durable auditing, subclass ``csp.reports.storage.ReportStorage`` (``store``,
``seen`` and ``clear``) and set ``CSP_REPORTS["STORAGE"]`` to its dotted path.


Throttling the number of reports
--------------------------------
To throttle the number of requests made to your ``report-uri`` endpoint in the browser, you can use
``csp.contrib.rate_limiting.RateLimitedCSPMiddleware`` instead of ``csp.middleware.CSPMiddleware``
and set the ``REPORT_PERCENTAGE`` option:

``REPORT_PERCENTAGE``
    Percentage of requests that should see the ``report-uri`` directive.  Use this to throttle the
    number of CSP violation reports made to your ``report-uri``. A **float** between 0.0 and 100.0
    (0.0 = no reports at all, 100.0 = always report).  Ignored if ``report-uri`` isn't set.

.. _report: http://www.w3.org/TR/CSP/#sample-violation-report
