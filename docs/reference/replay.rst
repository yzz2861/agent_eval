Replay
======

The ``sigma.replay`` package provides a local dual-clock replay on top of
:class:`~sigma.matching.SigmaMatcher`.  It separates three situations that a
post-incident review must not conflate:

* normal events that the monitor observed and that count towards rule hits;
* events collected during an approved maintenance window: the data exists, but
  the monitoring clock was stopped and the events cannot count;
* intervals without any data outside maintenance, which are genuinely
  unobservable gaps.

Every replayed entry carries both a wall-clock timestamp (when the event
happened) and an observation-clock timestamp (the same instant with approved
maintenance time removed).  Events are also assigned to half-open event-time
landing buckets.  Synthetic boundary events mark both ends of every maintenance
window, so the two clock readings can be compared at each landing point.
Snapshots retain the schedule in force at capture time; replacing the
maintenance record leaves old snapshots intact, so a previously produced hit can
still be explained against the record that originally justified it.

Maintenance records
-------------------

.. autoclass:: sigma.replay.MaintenanceWindow
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.MaintenanceSchedule
   :members:
   :undoc-members:
   :show-inheritance:

Dual-clock replay
-----------------

.. autoclass:: sigma.replay.DualClockReplay
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.ReplayEvent
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.ReplayEventKind
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.ObservationStatus
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.ReplayBucket
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.ObservationGap
   :members:
   :undoc-members:
   :show-inheritance:

Results and explanations
------------------------

.. autoclass:: sigma.replay.WindowReport
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.ReplayResult
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.ReplaySnapshot
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.replay.MatchExplanation
   :members:
   :undoc-members:
   :show-inheritance:
