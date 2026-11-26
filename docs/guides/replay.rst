Dual-Clock Replay
=================

The :mod:`sigma.replay` module replays local events through
:class:`~sigma.matching.SigmaMatcher` while keeping two clocks:

* **event time** -- the timestamp carried by the event;
* **observation time** -- event time with approved maintenance removed.

This is useful when a maintenance request pauses the monitoring clock for a
while but the collection pipeline keeps running.  The replay must not treat the
collected data as ordinary evidence, and it must not treat a planned pause as a
missing-data incident.

Quick start
-----------

.. code-block:: python

    from datetime import datetime, timedelta, timezone

    from sigma.collection import SigmaCollection
    from sigma.matching import Event, EventLogSource, SigmaMatcher
    from sigma.replay import DualClockReplay, MaintenanceSchedule, MaintenanceWindow

    utc = timezone.utc
    maintenance = MaintenanceWindow(
        start=datetime(2026, 11, 27, 2, 0, tzinfo=utc),
        end=datetime(2026, 11, 27, 3, 0, tzinfo=utc),
        reason="control-plane upgrade",
        reference="CHG-1042",
    )
    schedule = MaintenanceSchedule([maintenance])

    collection = SigmaCollection.from_yaml(rules_yaml)
    with SigmaMatcher(collection) as matcher:
        replay = DualClockReplay(
            schedule,
            matcher,
            bucket_size=timedelta(hours=1),
        )
        result = replay.run(events)

Each real event receives an :class:`~sigma.replay.ObservationStatus`:

* :attr:`~sigma.replay.ObservationStatus.OBSERVABLE` -- normal, countable and
  passed to the matcher;
* :attr:`~sigma.replay.ObservationStatus.SUPPRESSED_MAINTENANCE` -- data exists
  but the monitoring clock was stopped, so the matcher is not called;
* :attr:`~sigma.replay.ObservationStatus.BOUNDARY` -- a synthetic marker at a
  maintenance boundary, never matched;
* :attr:`~sigma.replay.ObservationStatus.UNOBSERVABLE` -- a real missing-data
  interval outside maintenance.

Landing buckets and boundary markers
------------------------------------

Every event is assigned to a half-open event-time bucket ``[start, end)``.  An
event exactly on a boundary lands in the following bucket.  The same event also
has an observation-clock reading, which can differ from its landing point when
maintenance precedes it.

For a maintenance window from 02:00 to 03:00 with one-hour buckets, the synthetic
markers land as follows:

* start marker: event time 02:00, landing bucket 02:00, observation 02:00;
* end marker: event time 03:00, landing bucket 03:00, observation 02:00.

The different landing points keep the end marker out of the paused bucket,
while the observation reading shows that the monitoring clock did not advance.

Missing data versus suppressed data
-----------------------------------

:attr:`~sigma.replay.ReplayResult.gaps` contains only the genuinely
unobservable parts of a silence.  If events exist at 02:30 and 05:00 while the
maintenance window covers 02:00--03:00, the actual gap starts at 03:00, not
02:30, and the gap length excludes maintenance time.

:meth:`~sigma.replay.ReplayResult.window_reports` reports each maintenance
record separately.  A window with collected events has
``has_data == True``; a silent maintenance window has ``has_data == False``.
This distinguishes data that exists but cannot count from time that was not
observed at all.

The result exposes the spans separately so they cannot be confused:

* ``wall_span`` -- elapsed wall-clock time covered by the replay;
* ``maintenance_span`` -- approved maintenance inside that range;
* ``observation_span`` -- ``wall_span`` minus ``maintenance_span``;
* ``unobservable_span`` -- sum of actual data gaps outside maintenance;
* ``data_span`` -- ``observation_span`` minus ``unobservable_span``.

Snapshots and replaced records
------------------------------

Capture a snapshot before changing the maintenance record:

.. code-block:: python

    snapshot = replay.snapshot(label="original-change-record")
    replay.replace_schedule(MaintenanceSchedule([corrected_window]))
    result = replay.run(events)

``replace_schedule`` retains the previous state as a snapshot.  The returned
snapshot, or any snapshot taken earlier, still carries its original schedule and
matches:

.. code-block:: python

    explanation = snapshot.explain_rule("mimikatz_rule")
    for entry in explanation.contributing_events:
        print(entry.wall_time, entry.landing_point, entry.status)
    for entry in explanation.suppressed_events:
        print("excluded by maintenance:", entry.wall_time, entry.window)

This makes it possible to show why an old hit held even after the maintenance
record was corrected or replaced.

Notes
-----

* ``run`` sorts events by event time before matching.  ``feed`` is available for
  incremental use and expects events to arrive in replay order.
* Reusing a stateful correlation matcher across independent runs requires a
  fresh matcher because correlation windows retain state.
* All timestamps must be timezone-aware.
