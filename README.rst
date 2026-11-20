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

Queue migration reconciliation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Governance teams can compare an old CVSS 3.1 queue decision with a CVSS 4.0
decision before switching.  Each rule set must declare the dimensions it uses
(``score`` and/or ``severity``); cross-computation only uses dimensions declared
by both rule sets with the same metric.  A missing vector is reported as missing
evidence and is never filled in from the other vector.

.. code-block:: python

    from cvss import QueueRuleSet, migrate_queues

    old_rules = QueueRuleSet(
        "3.1",
        ["score"],
        [
            {"queue": "priority", "min_score": 8.0},
            {"queue": "standard"},
        ],
    )
    new_rules = QueueRuleSet(
        "4.0",
        ["score"],
        [
            {"queue": "priority", "min_score": 8.0, "min_inclusive": False},
            {"queue": "standard"},
        ],
    )

    old_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"  # 8.0 High
    new_vector = (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L/E:U"
    )  # 8.0 High

    result = migrate_queues(old_vector, new_vector, old_rules, new_rules)
    print(result.report())

Both vectors score 8.0, but the inclusive/exclusive thresholds put the risk in
different queues.  The report attributes the difference to ``rule_changed`` and
rejects ``scoring_data_changed`` for the declared ``score`` basis.  If either
vector is ``None``, that side has no score, severity, or queue, and both
explanations remain possible instead of being guessed.

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
