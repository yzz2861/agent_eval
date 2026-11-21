Offline Temporal Correlation
============================

A single temporal correlation rule often has two consumers with different latency
requirements:

* the **real-time** consumer must publish a *provisional* relationship as soon as the
  events arrive, so that the on-call operator can act;
* the **next-day review** consumer must re-evaluate the same rule on **event time** after
  late records have been backfilled.

:class:`~sigma.matching.OfflineCorrelationContract` makes that split explicit and
testable. Both consumers share the rule's field aliases, ``group-by`` semantics and
``timespan``; only the time basis and the lifecycle of the conclusion differ.

Creating the contract
---------------------

.. code-block:: python

    from datetime import datetime, timezone
    from sigma.collection import SigmaCollection
    from sigma.matching import (
        ConclusionStatus,
        Event,
        EventLogSource,
        OfflineCorrelationContract,
        TimeBasis,
    )

    collection = SigmaCollection.from_yaml(rules_yaml)
    contract = OfflineCorrelationContract(
        collection,
        "login_followed_by_access",
        provisional_basis=TimeBasis.ARRIVAL_TIME,
        final_basis=TimeBasis.EVENT_TIME,
    )

``provisional_basis`` defaults to ``ARRIVAL_TIME`` and ``final_basis`` defaults to
``EVENT_TIME``. Both can be set explicitly to the same basis when a deployment wants a
single clock, but the choice is never implicit.

Event time and arrival time
---------------------------

:class:`~sigma.matching.Event` carries both clocks:

* ``timestamp`` is the event time reported by the source system;
* ``arrival_time`` is the time at which the operations platform received the record.

An explicit arrival time is required whenever the contract evaluates on
``ARRIVAL_TIME``. It may be passed on the event or to
:meth:`~sigma.matching.OfflineCorrelationContract.observe`:

.. code-block:: python

    event = Event(
        timestamp=datetime(2026, 11, 21, 10, 0, tzinfo=timezone.utc),
        arrival_time=datetime(2026, 11, 21, 10, 12, tzinfo=timezone.utc),
        logsource=EventLogSource(category="test", product="test"),
        data={"event": "login", "user": "alice"},
    )

    contract.observe(event)
    # or: contract.observe(event, arrival_time=received_at)

Real-time provisional results
-----------------------------

Each call to :meth:`~sigma.matching.OfflineCorrelationContract.observe` returns the
provisional conclusions that were emitted by that event:

.. code-block:: python

    for provisional in contract.observe(event):
        publish_to_on_call(
            id=provisional.conclusion_id,
            group=provisional.group_values,
            rules=provisional.rule_names,
            window=(provisional.window_start, provisional.window_end),
        )

Provisional conclusions are immutable. A backfill never edits them in place; it emits a
:class:`~sigma.matching.CorrelationRevision` that refers to the original
``conclusion_id``.

The on-call view is retained verbatim:

.. code-block:: python

    viewed_at_sequence_7 = contract.on_call_view(7)
    every_snapshot = contract.audit_trail()

Both return frozen :class:`~sigma.matching.OnCallSnapshot` objects containing frozen
:class:`~sigma.matching.CorrelationConclusion` objects, so a later review cannot rewrite
what the operator saw.

Next-day backfill and review
----------------------------

Late records are supplied through
:meth:`~sigma.matching.OfflineCorrelationContract.backfill`. The contract only reconciles
the late record's group and provisional relationships whose event-time window is within
one ``timespan`` of the late record:

.. code-block:: python

    report = contract.backfill(late_events)

    for revision in report.revisions:
        if revision.status is ConclusionStatus.CONFIRMED:
            mark_confirmed(revision.conclusion_id)
        elif revision.status is ConclusionStatus.RETRACTED:
            withdraw(revision.conclusion_id)
            notify_on_call(revision.conclusion_id, revision.reason)

Records that were never seen by the real-time consumer but complete a relationship on
event time appear in ``report.new_conclusions``. At the end of the review,
:meth:`~sigma.matching.OfflineCorrelationContract.review` (or its alias ``finalize``)
resolves every still-provisional conclusion and returns the same
:class:`~sigma.matching.RevisionReport` shape.

Conclusion lifecycle
--------------------

.. list-table::
   :header-rows: 1

   * - Status
     - Meaning
   * - ``PROVISIONAL``
     - Emitted in real time on the provisional time basis. Immutable and retained for
       audit.
   * - ``CONFIRMED``
     - Re-evaluating the same participant events on the final time basis still satisfies
       the rule.
   * - ``RETRACTED``
     - The participant events no longer satisfy the rule once ordered and windowed by the
       final time basis.

Shared grouping semantics
-------------------------

``group-by`` fields and their per-rule aliases are resolved by the same helper for both
the provisional and final evaluations. Two records that map to the same group under the
rule's aliases therefore stay in the same correlation group for both consumers; one that
maps to a different value is never revised by the other group's backfill.

Short replay
------------

The repository includes a deterministic replay that shows both outcomes:

.. code-block:: bash

    python examples/offline_correlation_replay.py

The first scenario emits a provisional ``login_rule -> access_rule`` relationship in
arrival order and then shows a late record **confirming** it on event time. The second
scenario emits the same relationship from an out-of-order pair and shows a late record
**retracting** it. In both cases the replay asserts that the on-call snapshot is unchanged
after the backfill.
