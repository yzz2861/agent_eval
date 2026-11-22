.. _review:

Reviewing View Migrations
=========================

``sqlparse.review`` provides an offline, bounded review for a narrow
governance question: after applying a planned migration, can every frozen
evidence object still reach its evidence sources through a live query path?

The review never opens a database connection and never executes SQL. It
parses three inputs with the sqlparse token tree:

* baseline ``CREATE`` statements for views, materialized views, snapshots,
  and tables;
* a freeze list naming evidence objects, optionally with required anchors;
* a planned migration containing supported ``CREATE``, ``ALTER`` and
  ``DROP`` statements.

Object identity is assigned independently of names. Dependency edges point at
object ids, not names, so ``ALTER VIEW ... RENAME TO ...`` keeps downstream
lineage intact and leaves a trace from the old name to the new one. Dropping
an object and creating a new object with the same name is reported as
``name_reuse``; a removed dependency that cannot be replaced is reported as
``incomplete_dependency``. The two conditions are kept in separate result
collections.

Example
-------

.. code-block:: python

    import sqlparse

    result = sqlparse.review.review(
        declarations="""\
            CREATE VIEW temp_audit AS SELECT id, actor FROM audit_log;
            CREATE VIEW forensic_snapshot AS SELECT * FROM temp_audit;
        """,
        freeze=["forensic_snapshot"],
        migration="ALTER VIEW temp_audit RENAME TO archive_audit;",
    )

    assert result.safe
    assert result.evidence[0].reason == "renamed"
    assert result.evidence[0].renames == (("temp_audit", "archive_audit"),)

A migration that drops the only chain to ``audit_log`` produces an unsafe
result with ``EvidenceReport.reason == "incomplete_dependency"``.

API
---

.. autofunction:: sqlparse.review.review

.. autofunction:: sqlparse.review.review_files

.. autofunction:: sqlparse.review.parse_freeze_list

.. autofunction:: sqlparse.review.normalize_name

.. autoclass:: sqlparse.review.ReviewResult
   :members:

.. autoclass:: sqlparse.review.EvidenceReport
   :members:

.. autoclass:: sqlparse.review.QueryPath
   :members:

.. autoclass:: sqlparse.review.Finding
   :members:

.. autoclass:: sqlparse.review.FindingKind
   :members:

.. autoclass:: sqlparse.review.FindingCategory
   :members:

.. autoclass:: sqlparse.review.FrozenObject
   :members:

Command line
------------

The module can be run directly::

    python -m sqlparse.review \
        --declarations schema.sql \
        --freeze freeze.txt \
        --migration migration.sql

It exits with status 0 when the reviewed migration is safe and 1 otherwise.
``--json`` emits a machine-readable report.

Bounded grammar
---------------

The review understands a deliberately small DDL subset: ``CREATE`` views,
materialized views, snapshots and tables; ``ALTER ... RENAME TO``;
``ALTER ... SET SCHEMA``; and ``DROP`` of those relation kinds. Dependencies
are collected from ``FROM`` and ``JOIN`` factors, including nested subqueries
and common table expressions. Other statements are reported as
``unsupported_statement`` errors instead of being guessed at.
