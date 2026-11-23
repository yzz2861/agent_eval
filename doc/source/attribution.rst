Attributing Findings to Maintained Code
=======================================

Bandit's JSON report describes findings by source filename.  A weekly risk
leaderboard often needs a second, team-level view: which build artifacts contain
the finding, which source component is responsible for it, and which team is
currently maintaining that component.  The ``bandit-attribution`` command
consumes an existing Bandit JSON report and a finite set of release manifests
to build that view.

The attribution result is deterministic.  It uses no wall-clock value and
records SHA-256 digests for the report, every manifest and the combined
evidence, so the same inputs always produce the same output.

Command line
------------

.. code-block:: console

    bandit-attribution report.json \
        --manifest release-legacy.json \
        --manifest release-handover.json \
        --as-of 2026-11-20T00:00:00Z \
        --output attribution.json

``--report`` (or the first positional argument) is a normal Bandit JSON report.
Each ``--manifest`` is applied in order; later manifests refine earlier
declarations.  ``--as-of`` pins the lifecycle and handover evaluation time.
When it is omitted, the latest ``as_of`` declared by the manifests is used.

Manifest model
--------------

A manifest contains three finite relations:

* ``artifacts``: reviewed build artifacts and the source components they
  contain;
* ``components``: source paths, revisions and the team that maintains each
  component;
* ``handovers``: team-to-team transfers, including an effective date and proof.

Legacy attribution is optional but is always reported when present.

.. code-block:: json

    {
      "schema_version": 1,
      "as_of": "2026-11-20T00:00:00Z",
      "artifacts": [
        {
          "id": "product-a-1.2.0",
          "digest": "sha256:...",
          "stop_ship_at": "2026-12-31T00:00:00Z",
          "components": ["shared-runtime"]
        },
        {
          "id": "product-b-2.0.0",
          "digest": "sha256:...",
          "components": ["shared-runtime"]
        }
      ],
      "components": [
        {
          "id": "shared-runtime",
          "paths": ["src/shared/runtime.py"],
          "revision": "git:abc123",
          "maintainer": "team-platform",
          "legacy_owner": "team-old-platform"
        }
      ],
      "handovers": [
        {
          "component": "shared-runtime",
          "from": "team-old-platform",
          "to": "team-platform",
          "effective_at": "2026-11-01T00:00:00Z",
          "proof": {"ticket": "OPS-1204", "digest": "sha256:..."}
        }
      ],
      "legacy_attribution": [
        {
          "filename": "src/old/runtime.py",
          "artifact": "product-a-1.0.0",
          "owner": "team-old-platform"
        }
      ]
    }

Common aliases are accepted for integration with existing release tooling.
For example, ``releases`` may be used instead of ``artifacts``,
``source_components`` instead of ``components``, ``ownership_transfers``
instead of ``handovers``, and ``maintainer``/``owner``/``team`` are treated as
the same owner field.

Python API
----------

The same evidence can be submitted without creating a manifest file first.
This is useful for a report consumer that already has the finite relations
and handover proofs in memory.

.. code-block:: python

    from bandit.core import attribution

    result = attribution.attribute(
        report,
        as_of="2026-11-20T00:00:00Z",
        artifacts=[
            {"id": "product-a-1.2.0", "components": ["shared-runtime"]}
        ],
        components=[
            {
                "id": "shared-runtime",
                "paths": ["src/shared/runtime.py"],
                "owner": "team-platform",
                "revision": "git:abc123",
            }
        ],
        relations={"product-a-1.2.0": ["shared-runtime"]},
        handovers=[
            {
                "component": "shared-runtime",
                "to": "team-core",
                "effective_at": "2026-11-01T00:00:00Z",
                "proof": {"ticket": "OPS-1204"},
            }
        ],
        legacy_attribution=[
            {"filename": "src/shared/runtime.py", "owner": "team-legacy"}
        ],
    )

    result["risk_burden"]
    result["legacy_attribution"]
    result["double_counting"]

Attribution rules
-----------------

* A finding is attributed only through an exact source-path relation declared by
  a manifest.  Absolute build paths may end with a manifest path, and manifest
  globs are supported, but a basename by itself is not an exact relation.
* A proven handover is applied when its effective date is not later than
  ``as_of``.  An unproven handover is ignored and recorded in
  ``evidence.warnings``.
* A finding is counted once per owner.  If two artifacts refer to the same
  component, both artifact IDs are retained but the burden is counted once and
  ``double_counting`` records the reason ``shared_component``.
* An artifact that has not reached ``stop_ship_at`` may still receive tickets,
  including an old product.  Once the fixed ``as_of`` reaches the stop-ship
  boundary, its findings stay in ``legacy_attribution`` but do not add new risk
  burden.
* Conflicting exact claims from different owners are not guessed.  They are
  marked ``needs_review`` and the reason is reported as
  ``conflicting_owner_claims``.
* Similar filenames are never used for attribution.  They appear only in
  ``review_candidates`` with ``counted: false`` and a reason such as
  ``same_basename_different_path`` or ``similar_filename``.

Output sections
---------------

``attributions``
    One row per finding.  It records the resolved owner, component and artifact
    evidence, whether the finding was counted, and any duplicate reasons.

``risk_burden``
    Risk grouped by current owner.  Each finding contributes once to its
    owner's ``finding_count`` and ``risk_weight``.

``component_burden``
    The same counted findings grouped by owner and component for drill-down.

``legacy_attribution``
    The prior owner/artifact mapping for each matched finding.  This section is
    emitted even when the current owner differs, so legacy reporting keeps
    working during a transition.

``double_counting``
    Explicit reasons for deduplicated or unresolved claims.  Typical reasons
    are ``shared_component``, ``shared_maintained_code``,
    ``multiple_component_claims``, ``conflicting_owner_claims`` and
    ``duplicate_report_entry``.

``review_candidates``
    Filename-similarity clues only.  They have no effect on ``risk_burden``.

``evidence``
    The fixed ``as_of`` value, input digests and parser warnings used to
    recompute the result.
