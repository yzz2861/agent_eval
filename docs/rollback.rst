Rollback review
===============

A maintenance order may allow a compatibility layer to be rolled back, but an
incident review still has to answer a different question: *which advisory
conditions become true again after the rollback?*  The :mod:`cpe.review`
module answers that question with the two matching algorithms already provided
by this package:

* ``CPESet2_3.name_match`` for a candidate CPE Name (a name advisory),
* ``CPELanguage2_3.language_match`` for a CPE Language platform expression
  (a language advisory).

The module also unbinds URI and formatted-string CPE Names before comparing
them.  A machine whose compatibility-layer spelling changed from
``cpe:/a:acme:edge_agent:2.0`` to
``cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*`` is therefore unchanged.  A
machine that really rolled back from ``2.0`` to ``1.5`` is not.


Scenario input
--------------

The simplest input is one JSON document::

    {
      "approved": ["cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*"],
      "devices": [
        {
          "id": "edge-nyc-01",
          "before": ["cpe:/a:acme:edge_agent:2.0"],
          "after": ["cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*"]
        },
        {
          "id": "edge-sfo-02",
          "before": ["cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*"],
          "after": [
            "cpe:/a:acme:edge_agent:1.5",
            "cpe:2.3:a:acme:legacy_bridge:1.*:*:*:*:*:*:*:*"
          ]
        }
      ],
      "advisories": [
        {
          "id": "ADV-EDGE-1.5",
          "type": "name",
          "cpe": "cpe:2.3:a:acme:edge_agent:1.5:*:*:*:*:*:*:*"
        },
        {
          "id": "ADV-BRIDGE-AND",
          "type": "language",
          "expression": "<cpe:platform-specification ...>...</cpe:platform-specification>"
        }
      ]
    }

An advisory may be written as:

* ``type: name`` with a ``cpe`` field,
* ``type: language`` with an XML ``expression``,
* ``type: json`` with an NVD-style node list (``cpe_match`` entries may carry
  the ``vulnerable`` flag).

Language expressions are not reduced to a single boolean in the report.  A
``fact-ref`` whose installed CPE contains a wildcard (for example
``version="1\\.*"``) produces the ``unknown`` state instead of being silently
treated as a non-match; the report keeps the attribute that is still unknown.


Python API
----------

::

    from cpe.review import analyze

    report = analyze(
        approved=["cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*"],
        before={"edge-nyc-01": ["cpe:/a:acme:edge_agent:2.0"]},
        after={"edge-nyc-01": ["cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*"]},
        advisories=[{
            "id": "ADV-EDGE-1.5",
            "type": "name",
            "cpe": "cpe:2.3:a:acme:edge_agent:1.5:*:*:*:*:*:*:*",
        }],
    )

The report contains:

``devices``
    Per-device change class (``unchanged``, ``representation_only`` or
    ``components_changed``), changed attributes, approval status before and
    after the rollback, and the ticket recommendation.

``approved_devices``
    For each pre-approved CPE, the machines it covered before and after the
    rollback, plus the machines whose approval was lost.

``advisories``
    Per-advisory ``reentered_devices``, ``unknown_dependencies`` and
    ``branch_sources``.  A branch source records the logical path and the CPE
    that satisfied it.  For NVD-style input the node path and operator (AND /
    OR) are included.

``tickets``
    Suggestions ready for a ticketing system.  A representation-only change
    receives ``no_review``; a real component rollback receives ``re_review``.
    An advisory that becomes true again adds ``reopen_advisory_review``.
    Undecidable wildcard dependencies add ``hold_for_unknown_dependency``.


Command line
------------

::

    $ python -m cpe.review --input tests/rollback_review.json --output report.json
    $ python -m cpe --input tests/rollback_review.json

The acceptance fixture is ``tests/rollback_review.json``.  It contains one
machine with only a URI-to-formatted-string spelling change and one machine
with a real ``2.0`` to ``1.5`` rollback plus a wildcarded dependency.  The
first machine receives ``no_review``; the second receives ``re_review``,
``reopen_advisory_review`` for the 1.5 name advisory, and
``hold_for_unknown_dependency`` for the wildcarded bridge version.
