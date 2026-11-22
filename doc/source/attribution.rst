Release attribution
===================

Bandit reports findings against source files.  A weekly risk leaderboard often
needs a different answer: which maintained release artifact should carry the
finding?  After a repository split, two artifacts may still build the same
source component.  A naive report then counts one finding twice.

The ``bandit-attribution`` command adds a deterministic, manifest-driven
attribution step for report consumers.  It consumes a finished Bandit JSON
report and a release manifest.  It does not change the scan itself, so scan
output and ownership policy can be reproduced independently.

Command line
------------

.. code-block:: console

   bandit -r . -f json -o bandit-report.json
   bandit-attribution --manifest release-manifest.json \
       --report bandit-report.json --output attribution.json

The command accepts these options:

``--manifest``
   Release manifest JSON.  Required.

``--report``
   Bandit JSON report.  Defaults to standard input.

``--output``
   Output file.  Defaults to standard output.

``--format json|text``
   Machine-readable output or a short human summary.

``--view both|current|legacy``
   Report current ownership, legacy ownership, or both.  The default is
   ``both``.

``--fail-on-unattributed``
   Exit with status 1 when any finding is unattributed or only has an
   investigation lead.

The output contains no timestamps.  For fixed finding and manifest inputs the
JSON output is byte-for-byte stable.  A single manifest can represent both
sides of a handover by evaluating it with different ``as_of`` dates; a handover
that is not effective yet is rejected for that run.

Manifest contract
-----------------

A manifest has five top-level parts: components, artifacts, relations,
handovers, and options.  All identifiers must be unique.

.. code-block:: json

   {
     "schema_version": 1,
     "manifest_id": "2026-11-web-split",
     "as_of": "2026-11-20",
     "components": [
       {
         "component_id": "shared-core",
         "owner": "team-platform",
         "legacy_owner": "team-legacy",
         "paths": ["src/shared"],
         "files": ["src/generated/version.py"]
       }
     ],
     "artifacts": [
       {
         "artifact_id": "portal-old@1.8.0",
         "owner": "team-platform",
         "legacy_owner": "team-legacy",
         "status": "maintenance"
       },
       {
         "artifact_id": "portal-new@2.0.0",
         "owner": "team-platform",
         "legacy_owner": "team-legacy",
         "status": "active"
       }
     ],
     "relations": [
       {
         "artifact_id": "portal-old@1.8.0",
         "component_id": "shared-core",
         "evidence": {
           "kind": "build-provenance",
           "id": "build-100",
           "digest": "sha256:example"
         }
       },
       {
         "artifact_id": "portal-new@2.0.0",
         "component_id": "shared-core",
         "evidence": {
           "kind": "build-provenance",
           "id": "build-200",
           "digest": "sha256:example"
         }
       }
     ],
     "handovers": [
       {
         "component_id": "shared-core",
         "from_owner": "team-legacy",
         "to_owner": "team-platform",
         "effective": "2026-11-01",
         "proof": {
           "kind": "change-request",
           "id": "CHG-4242",
           "uri": "https://changes.example/CHG-4242",
           "digest": "sha256:handover"
         }
       }
     ],
     "options": {
       "fuzzy_match_threshold": 0.82
     }
   }

Components
   A component is the unit of risk.  ``paths`` are directory roots and
   ``files`` are exact file paths.  Paths are normalized with POSIX rules.
   A relative manifest path may match an absolute report path when one is an
   exact suffix of the other.

Artifacts
   An artifact is a build or release output.  ``status`` is one of ``active``,
   ``maintenance``, ``sunset``, ``eol``, or ``discontinued``.  ``eol_date``
   can also move an artifact to end of life for a manifest with an ``as_of``
   date.

Relations
   A relation is the only way to connect an artifact to a component.  The
   relation is finite and explicit.  The optional ``evidence`` object records
   the build provenance used for the relation.

Handovers
   A handover moves current maintenance responsibility.  It must have
   ``from_owner``, ``to_owner``, a scope (``component_id`` or
   ``artifact_id``), and proof with at least one of ``id``, ``ticket``,
   ``uri``, or ``digest``.  An unproven or not-yet-effective handover is
   rejected and
   listed under ``manifest.handovers_rejected``.

Attribution rules
-----------------

1. Only exact path matches are used for attribution.  A fuzzy filename match
   appears in ``investigation_queue`` and carries no risk.
2. When several components match, the most specific path wins.  A tie is
   reported as ``ambiguous_exact_component_match`` and is not counted.
3. A matched component must have at least one explicit artifact relation.
   Source code with no release relation is not part of release risk.
4. Risk is counted once per source component for each finding.  Every affected
   artifact is still listed in ``allocation.affected_artifacts``.
5. If two or more artifacts share the component, the result sets
   ``double_count.detected`` and gives a machine-readable ``reason`` plus a
   human-readable ``detail``.
6. Current ownership is resolved from a valid component handover, then the
   component owner, then an artifact handover, then the artifact owner.  Ties
   and conflicts are deterministic and carry an ``owner_note``.
7. Legacy ownership is always reported separately in
   ``legacy_attribution`` and ``legacy_risk_by_owner``.  It is not removed when
   current ownership changes.
8. Artifacts in ``maintenance`` or ``sunset`` still count while they accept
   work orders.  ``eol`` and ``discontinued`` artifacts do not count, but their
   legacy attribution remains reportable.

Risk weights
------------

Risk points use the Bandit ranking values: ``UNDEFINED`` 1, ``LOW`` 3,
``MEDIUM`` 5, and ``HIGH`` 10.  Confidence is reported but does not multiply
the points.  The weights are repeated in
``reproducibility.risk_weights``.

Output
------

The result contains:

``summary``
   Finding counts, current risk points, legacy entry count, and avoided double
   count points.

``risk_by_owner`` and ``risk_by_component``
   De-duplicated current risk ledgers.

``legacy_risk_by_owner`` and ``legacy_attribution``
   Report-only old attribution.  Each legacy entry names its source, such as
   ``artifact.legacy_owner`` or ``handover.from_owner``.

``artifact_impact``
   Informational artifact-level view.  It is explicitly not intended for
   summing across artifacts that share a component.

``investigation_queue``
   Filename similarity and basename collision leads.  These never carry risk.

``manifest`` and ``reproducibility``
   Manifest identity, accepted and rejected handovers, the manifest digest,
   the findings digest, risk weights, and the double count policy.

Acceptance fixtures
-------------------

Two fake release manifests cover the split and handover phases:

``tests/fixtures/attribution/release_manifest.phase1.json``
   Before handover.  Old and new artifacts share ``shared-core`` and
   ``web-ui``.  The old artifact is in maintenance, the console artifact is
   end of life, and legacy attribution is reportable.

``tests/fixtures/attribution/release_manifest.phase2.json``
   After a proven handover.  Current risk moves to ``team-platform``, legacy
   risk stays visible for ``team-legacy``, the old artifact still accepts work
   orders, and an unproven handover is rejected.

``tests/fixtures/attribution/bandit_report.json``
   A small fake Bandit report, including a basename collision that must remain
   an investigation lead.

The acceptance tests live in ``tests/unit/core/test_attribution.py``.
