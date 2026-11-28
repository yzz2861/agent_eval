=================
Finding triage
=================

Bandit reports every finding its plugins can prove.  A responder often has
capacity for only a few findings per shift, so a scanner result needs a
second, explicit allocation step before it is handed to the on-call queue.
``bandit.core.triage`` provides that step without changing ``Issue`` or any
existing formatter.

Responsibilities and quotas
---------------------------

Callers assign each issue to a responsibility and provide a cumulative quota
for that responsibility.  ``responsibilities`` may be a string, a callable,
or a mapping.  A mapping is looked up by the issue object, ``(filename,
line)``, ``(filename, line, column)``, ``(filename, test_id)``, ``test_id``,
plugin name, or filename.  An issue with a ``responsibility``, ``owner`` or
``team`` attribute is used directly when no mapping is supplied.
Responsibilities absent from ``quotas`` use ``default_quota`` (zero by
default), so a caller must grant capacity explicitly.

.. code-block:: python

    from bandit.core import triage

    result = triage.allocate(
        manager.get_issue_list(),
        responsibilities={"app.py": "payments"},
        quotas={"payments": 5},
        non_deferrable=("HIGH",),
    )

    for finding in result.actionable:
        print(finding.responsibility, finding.test_ids, finding.severity)

``TriageAllocator`` is the stateful form.  Usage accumulates across
``allocate()`` calls, so feeding a scan in several batches does not reset a
responsibility's quota.  Use ``reset_quota()`` for a new duty period, or set
``reset_interval`` to let a later ``allocate(now=...)`` roll the period over
automatically.

.. code-block:: python

    allocator = triage.TriageAllocator(
        {"payments": 5},
        non_deferrable=("HIGH",),
        reset_interval=datetime.timedelta(hours=8),
    )
    first = allocator.allocate(batch_one)
    second = allocator.allocate(batch_two)
    released = allocator.reset_quota(now=shift_end)

Duplicate alerts and shared locations
-------------------------------------

An exact alert repeated inside the same responsibility consumes one quota
slot; the extra occurrences are recorded in ``result.duplicates``.  Alerts
from different plugins at the same filename and line are merged into one
``Finding``.  The merged finding uses the highest contributing severity, so
grouping cannot hide a HIGH result behind a MEDIUM one, and ``test_ids``
retains every contributing rule identifier.

Deferral queue
--------------

Findings that do not fit the quota are placed in ``result.deferred`` (also
available as ``result.queue``).  Each ``DeferredFinding`` records:

* ``resume_at`` / ``available_at``: when the quota makes it eligible again;
* ``resume_reason``: currently ``"quota_reset"``;
* ``reason``: currently ``"quota_exhausted"``;
* ``required_quota`` and ``remaining_quota_at_deferral``: the cost of the
  finding and the remaining quota when it was deferred.

``deferred.resumable(now)`` and ``DeferredFinding.is_resumable(now)`` make
the time check explicit, which is useful when a caller runs on a fake or
injected clock.

Mandatory findings
------------------

Severities at or above the lowest level in ``non_deferrable`` (HIGH by
default) are never placed in the deferral queue.  If they arrive after the
quota is exhausted they remain in ``result.actionable`` with ``over_quota``
set, and they are counted in the usage so the next allocation can account for
the overrun.  Consequently a HIGH finding is always visible, even when the
quota is zero or already spent.

Compatibility
-------------

``TriageResult.as_dict()`` keeps the issue keys used by the JSON formatter in
``results`` (all grouped findings, actionable and deferred) and adds
``actionable``, ``deferred``, ``deferral_queue``, ``duplicates`` and
``summary``.  Existing formatters continue to consume
``manager.get_issue_list()`` unchanged.  ``triage_manager()`` is a
convenience wrapper for callers that want to allocate directly from a
``BanditManager``.
