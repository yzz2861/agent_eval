CVSS
====

This Python package contains CVSS v2, v3 and v4 computation utilities and
interactive calculator (for v2 and v3 only) compatible with Python 3. CVSS
(Common Vulnerability Scoring System) is an standardized method for rating
the severity of security issues on a scale from 0 (no impact) to 10 (critical).

The library is tested on all currently-supported Python versions available
via GitHub Actions but it is simple enough to run on even older versions.

Installation
------------

::

    # pip install cvss

Usage
-----

Library
~~~~~~~

.. code-block:: python

    from cvss import CVSS2, CVSS3, CVSS4


    vector = 'AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M'
    c = CVSS2(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())
    print(c.severities())

    print()

    vector = 'CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X'
    c = CVSS3(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())
    print(c.severities())

    print()

    vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N'
    c = CVSS4(vector)
    print(vector)
    print(c.clean_vector())
    print(c.scores())
    print(c.severities())

Sample output:

::

   AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M
   AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/CDP:L/TD:H/AR:M
   (5.0, 4.0, 4.6)
   ('Medium', 'Medium', 'Medium')

   CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X
   CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L
   (6.5, 6.0, 5.3)
   ('Medium', 'Medium', 'Medium')

   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N
   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N
   (9.9,)
   ('Critical',)

Product-line vulnerability cases
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A single advisory can affect several product lines, each with its own
environment vector and its own remediation plan. One shared score cannot
represent all of them. The ``cvss.case`` module keeps one immutable,
independently reviewable ``Assessment`` per (CVSS version, vector, evidence)
combination, groups them per product in a ``VulnerabilityCase``, and applies
caller-supplied disposition rules to build a reviewable queue.

Assessment identity is a content hash of the CVSS version, the raw vector, and
the evidence basis. Two assessments that produce the same numeric score from
different vectors or CVSS versions therefore stay distinct, while products that
reference the same assessment resolve to the same id. Assessments are
immutable: fixing one environment appends a new revision instead of changing
history, and every queue ticket snapshots the assessment that caused it, so a
ticket remains explainable after later remediation.

.. code-block:: python

    from cvss import VulnerabilityCase, ThresholdRule, CallableRule

    case = VulnerabilityCase("CVE-2026-0001", title="multi-product advisory")

    # Each product line brings its own vector and evidence basis.
    case.add_product(
        "product-a",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H",
        basis={"environment": "product-a runtime", "ticket": "TA-1"},
    )
    case.add_product(
        "product-b",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        basis={"environment": "product-b runtime", "ticket": "TB-2"},
    )

    # One product can reference another product assessment. Both point at the
    # same immutable assessment id, but can be revised independently later.
    case.share_assessment("product-b", "product-c", note="shared base image")

    # Caller-supplied disposition rules decide which products enter the queue.
    tickets = case.apply_disposition(ThresholdRule(9.0, score_kind="base"))

    # A ticket links back to the product line own vector, evidence basis, and
    # the exact disposition condition, even after later remediation.
    explanation = case.explain_ticket(tickets[0].ticket_id)

    # Fixing one environment appends a revision; other products and existing
    # tickets stay reviewable.
    case.remediate_environment(
        "product-a",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",
        basis={"environment": "product-a rebuilt"},
        reason="container image rebuilt",
    )

Callables are supported through ``CallableRule``; both plain booleans and
``(queued, reason)`` tuples are accepted. Use ``case.audit_log()`` and
``case.as_dict()`` for JSON-serializable provenance.

Interactive calculator
~~~~~~~~~~~~~~~~~~~~~~

For interactive calculator run the following:

::

    $ cvss_calculator

For help on the calculator options run:

::

    $ cvss_calculator --help

Testing
-------

For extensive testing, the test vectors were generated using official
JavaScript generators and `cvsslib <https://github.com/ctxis/cvsslib>`_.

To run all tests using all supported versions of Python 2 and Python 3 installed:

::

    $ tox
    $ tox -e py311   # Run tests using a specific version of Python
