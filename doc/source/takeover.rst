Takeover Adjudication Layer
===========================

.. contents:: :local:

Why this layer exists
---------------------

Rolling Bandit out as a blocking gate is hard when a repository already
carries hundreds of accepted findings and its directory layout is being split
between teams.  ``bandit.takeover`` is a reusable decision layer that sits
between the raw Bandit scan result and the rendered reports.  It combines:

* the **legacy report** - the previous Bandit JSON output whose findings are
  the accepted backlog ("old debt"),
* the **current scan** - the Bandit JSON output of the run being gated,
* the **ownership policy** - which team owns each directory today,
* the **handoff ledger** - explicit records of accepted directory moves,
* the **scan manifest** - the directories the run was supposed to cover.

The layer produces both a new approval document and an independent
legacy-format report, so existing report consumers keep working unchanged.

Finding dispositions
--------------------

Every finding from the current scan receives exactly one disposition:

``legacy_debt``
    Matches a finding in the legacy report and stays under a valid ownership
    chain.  Non-blocking; the backlog is carried forward.

``escalated``
    Matches a legacy finding whose severity or confidence was raised in the
    current scan.  Blocks the gate even when the directory move itself was
    accepted.

``cross_boundary_unaccepted``
    Matches a legacy finding that crossed an ownership boundary **without** a
    handoff record.  The old debt cannot travel with the code, so the current
    owner is treated as having introduced a new finding.  Blocks the gate.

``new_finding``
    No match in the legacy report.  Blocks the gate.

Legacy findings absent from the current scan are listed separately as
``resolved_legacy`` so they can be verified before being closed.

Identity and matching
---------------------

Findings are matched by a fingerprint built from ``test_id``, ``test_name``,
``issue_text`` and CWE id.  Line numbers and paths are excluded (both move
when code is edited or relocated), and severity/confidence are excluded so an
escalated finding is still recognised as the same piece of debt.  When a
directory has a handoff record, the current path is translated back to its
pre-handoff location before matching.

Coverage and unknown risk
-------------------------

A directory that failed to scan, or that never appeared in the run despite
being listed in the scan manifest, is reported as
``scanned`` / ``partial`` / ``failed`` / ``not_scanned``.  Every state other
than a fully successful scan marks the directory as **unknown risk** and fails
the gate.  A missing scan is never silently treated as clean.

Policy document
---------------

See ``examples/takeover/ownership-policy.yaml`` for the full schema:

* ``ownership`` - ordered list of ``directory`` / ``team`` mappings, longest
  prefix wins; unmatched paths are reported as ``UNOWNED``.
* ``path_moves`` - old prefix to new prefix renames from the repository split.
* ``handoffs`` - accepted moves; the only evidence that lets old debt cross an
  ownership boundary.
* ``scan_manifest`` - directories the scan is expected to cover.

Command line
------------

Run the full adjudication::

    bandit-takeover \
        --policy examples/takeover/ownership-policy.yaml \
        --current examples/takeover/bandit-current.json \
        --legacy examples/takeover/bandit-legacy.json \
        --approval-out reports/approval-detail.txt \
        --json-out reports/adjudication.json \
        --legacy-json-out reports/bandit-compat.json

Exit codes: ``0`` gate passed, ``1`` gate failed (blocking finding or unknown
risk directory), ``2`` input error.

Generate only the legacy-format report, independent of adjudication::

    bandit-takeover --policy policy.yaml --current scan.json \
        --legacy-json-only --legacy-json-out compat.json

Worked example
--------------

``examples/takeover/`` contains a directory handoff from ``platform-team`` to
``portal-team`` (record ``HO-2026-0117``) plus an unrecorded move into
``billing-team``.  The generated approval document shows:

* ``portal-team`` inherits the ``B105`` hardcoded password as non-blocking
  legacy debt thanks to the handoff record,
* the ``B608`` XSS finding moved with the same handoff but was escalated
  MEDIUM -> HIGH, so it must be fixed now,
* the ``B321`` XML parsing finding is new and must be fixed now,
* ``billing-team`` cannot inherit the ``B602`` shell-injection finding from
  ``tools/admin`` because no handoff record exists,
* ``svc/billing`` is only partially scanned and ``tools/admin`` was not
  scanned at all, so both directories require a rescan.

Programmatic use
----------------

.. code-block:: python

    from bandit.takeover.engine import AdjudicationEngine
    from bandit.takeover.loader import load_policy, load_report

    bundle = load_policy("ownership-policy.yaml")
    engine = AdjudicationEngine(
        bundle.ownership_policy,
        bundle.handoff_ledger,
        bundle.path_map,
    )
    report = engine.adjudicate(
        load_report("bandit-current.json"),
        load_report("bandit-legacy.json"),
        manifest_directories=bundle.scan_manifest,
    )
    assert report.gate_failed is False  # or inspect report.blocking()
