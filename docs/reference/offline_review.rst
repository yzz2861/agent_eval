Offline Evidence Review
=======================

The offline review API evaluates whether a reduced event export still contains
enough evidence to recompute each alert, and reports the minimum fields to
recover when it does not.

See also: :doc:`/guides/offline_review`.

RetentionPolicy
---------------

.. autoclass:: sigma.matching.RetentionPolicy
   :members:
   :undoc-members:
   :show-inheritance:

FieldRetention
--------------

.. autoclass:: sigma.matching.FieldRetention
   :members:
   :undoc-members:
   :show-inheritance:

TimeWindow
----------

.. autoclass:: sigma.matching.TimeWindow
   :members:
   :undoc-members:
   :show-inheritance:

EventExport
-----------

.. autoclass:: sigma.matching.EventExport
   :members:
   :undoc-members:
   :show-inheritance:

OfflineReviewer
---------------

.. autoclass:: sigma.matching.OfflineReviewer
   :members:
   :undoc-members:
   :show-inheritance:

RuleReview
----------

.. autoclass:: sigma.matching.RuleReview
   :members:
   :undoc-members:
   :show-inheritance:

ReviewReport
------------

.. autoclass:: sigma.matching.ReviewReport
   :members:
   :undoc-members:
   :show-inheritance:

MissingField
------------

.. autoclass:: sigma.matching.MissingField
   :members:
   :undoc-members:
   :show-inheritance:

Enums
-----

.. autoclass:: sigma.matching.MissingFieldReason
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.matching.ReviewStatus
   :members:
   :undoc-members:
   :show-inheritance:

Convenience Functions
---------------------

.. autofunction:: sigma.matching.review_offline

.. autofunction:: sigma.matching.review_alerts
