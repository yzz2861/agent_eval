Offline Evidence Review
=======================

Incident retrospectives often receive only a reduced Sigma event export. The
``sigma.matching.review`` module answers two practical questions for every
rule in a collection:

* Can the alert be recomputed from the retained fields alone?
* If not, which original fields must the collection team recover, and for
  which time window?

The reviewer combines three explicitly supplied inputs:

1. The parsed Sigma rules.
2. The before/after field mapping produced by a processing pipeline.
3. A caller-provided :class:`~sigma.matching.RetentionPolicy`.

It never guesses whether a missing field was never collected or was removed by
a retention process. That distinction must come from the caller.

Quick Start
-----------

.. code-block:: python

    from datetime import datetime, timezone

    from sigma.collection import SigmaCollection
    from sigma.matching import (
        EventExport,
        MissingFieldReason,
        OfflineReviewer,
        RetentionPolicy,
        TimeWindow,
    )
    from sigma.processing.pipeline import ProcessingPipeline

    collection = SigmaCollection.load_ruleset(["rules/"])
    pipeline = ProcessingPipeline.from_yaml(open("ecs_pipeline.yml").read())
    export = EventExport.from_file("export.json")

    policy = RetentionPolicy(
        never_captured_fields={"process.parent.name"},
        purged_fields={
            "process.executable": TimeWindow(
                start=datetime(2026, 11, 1, tzinfo=timezone.utc),
                end=datetime(2026, 11, 20, tzinfo=timezone.utc),
            )
        },
    )

    report = OfflineReviewer(
        collection,
        policy,
        pipeline=pipeline,
    ).review(export)

    for review in report:
        print(review.title, review.status.value)
        for finding in review.backfill_fields:
            print("  recover", finding.field, finding.applicable_window)
        for finding in review.unrecoverable_fields:
            print("  cannot recover", finding.field, finding.reason.value)

The convenience function :func:`~sigma.matching.review_offline` accepts the
same arguments:

.. code-block:: python

    from sigma.matching import review_offline

    report = review_offline(collection, export, policy, pipeline=pipeline)

Export Format
-------------

:class:`~sigma.matching.EventExport` accepts the following JSON shape. The
``retained_fields`` list is the export field schema and is the primary way to
distinguish a dropped field from a field that was retained but had no value.

.. code-block:: json

    {
      "exported_at": "2026-11-20T08:00:00Z",
      "retained_fields": [
        "process.parent.name",
        "process.command_line",
        "process.executable"
      ],
      "events": [
        {
          "timestamp": "2026-11-18T10:15:00Z",
          "logsource": {
            "category": "process_creation",
            "product": "windows"
          },
          "data": {
            "process.parent.name": "C:\\\\Office16\\\\WINWORD.EXE",
            "process.command_line": "powershell.exe -Command IEX(...)",
            "process.executable": "C:\\\\Windows\\\\System32\\\\pwsh.exe"
          }
        }
      ]
    }

A bare JSON list of event records is also accepted. Event records may carry a
``raw`` member when keyword detections need the original log text. Timestamps
may use ``timestamp``, ``@timestamp``, ``time``, or ``ts``.

Retention Policy
----------------

:class:`~sigma.matching.RetentionPolicy` is the caller declaration about the
export. The following inputs are supported:

``retained_fields``
    Fallback field schema when the export does not carry ``retained_fields``.

``never_captured_fields``
    Fields the source never recorded. There is genuinely no value to recover.

``purged_fields``
    Fields removed by a retention or rollover process. Values may be a
    :class:`~sigma.matching.TimeWindow`, a single ``datetime`` cutoff, or a
    pair of datetimes.

``archived_fields``
    Fields known to exist in an archive. The value is the restore window.

``field_policies``
    Per-field :class:`~sigma.matching.FieldRetention` overrides. Use this when a
    field is not recoverable, or when a custom note is needed.

``purge_before``
    A global cutoff. Missing fields whose evidence starts before the cutoff are
    classified as retention-purged even when no per-field rule exists.

``notes``
    Optional human-readable notes keyed by field name.

Missing Field Reasons
---------------------

The report separates "no value" from "value removed by retention":

.. list-table::
   :header-rows: 1

   * - Reason
     - Meaning
     - Recoverable
   * - ``never_captured``
     - The source never collected the field.
     - No
   * - ``source_absent``
     - The export retained the field, but no relevant event had a value.
     - No
   * - ``not_retained``
     - The export omitted the field and no destruction is known.
     - Usually yes
   * - ``retention_purged``
     - A retention process removed the field from the export.
     - Usually yes
   * - ``archived``
     - A known archive copy exists.
     - Yes

``source_absent`` findings are non-blocking: absence is real event data and the
matcher can still evaluate conditions such as ``exists: false``. All other
findings block independent review unless an explicit field policy marks them
recoverable.

Report Semantics
----------------

Each :class:`~sigma.matching.RuleReview` exposes:

* ``status``: ``reviewable``, ``needs_backfill``, ``unrecoverable``, or
  ``not_applicable``.
* ``required_fields``: original rule fields referenced by the actual
  condition. Detections not selected by the condition are excluded.
* ``mapped_fields``: post-conversion field names used by the matcher.
* ``field_mappings``: original to mapped field names for this rule.
* ``fields_to_backfill``: the minimum recoverable original fields to request.
* ``backfill_fields`` and ``unrecoverable_fields``: detailed findings.
* ``source_absent_fields``: retained fields with no value in the evidence.
* ``matches``: actual :class:`~sigma.matching.SigmaMatch` results when the rule
  is reviewable.

When a rule is reviewable, the reviewer runs
:class:`~sigma.matching.SigmaMatcher` over the export. ``reproduced`` is true
only when at least one match is produced. This means a rule can be reviewable
while still not reproducing the original alert.

Time Windows
------------

Every blocking :class:`~sigma.matching.MissingField` carries:

* ``applicable_from`` / ``applicable_to``: the evidence window for which the
  finding applies, intersected with the relevant retention window.
* ``restore_from`` / ``restore_to``: when an archive copy is available.

These values let the collection team scope a backfill request instead of
re-exporting the full incident history.

Limitations
-----------

* Correlation rules include their group-by and condition fields together
  with the requirements of the referenced base rules. The base rules are also
  reviewed individually, which makes partial evidence explicit.
* Keyword detections add a synthetic ``<raw>`` requirement. Supply the
  original ``raw`` member in the export when keyword semantics matter.
* The module is an offline analysis helper. It uses the pure-Python matching
  engine and is not intended for high-throughput production pipelines.

Minimum field sets
^^^^^^^^^^^^^^^^^^

``required_fields`` is not simply the union of every field mentioned by a rule.
The reviewer evaluates the condition tree and selects a minimum true branch:

* ``AND`` requires the union of its operands.
* ``OR`` selects the branch with the fewest unrecoverable fields, then the
  fewest recoverable fields, then the fewest total fields.
* ``NOT`` swaps the true and false requirements, so ``NOT (A and B)`` can be
  proven with only ``A`` or only ``B`` when that suffices.

Availability and recoverability are part of the cost, so an already retained
branch is preferred over one that would require a backfill.
