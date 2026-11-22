Privilege precheck
==================

``sqlparse.precheck`` is an offline, static precheck for a deliberately small
subset of migration SQL. It parses statements with :func:`sqlparse.parse`,
follows explicit transactions and savepoints, and reports the privilege state
that would remain after commit. It never connects to a database and never
executes SQL.

The precheck is an approval aid, not an authorization boundary. It cannot see
roles, object ownership, default privileges, row security, column grants or
server-side extension behaviour.

Python API
----------

.. code-block:: python

   from sqlparse.precheck import (
       ApprovedChange, InitialObject, precheck_migration,
   )

   result = precheck_migration(
       sql_text,
       initial_objects=[
           InitialObject(
               object_id='public.orders',
               schema='public',
               name='orders',
               kind='table',
               privileges={'analyst': ['SELECT']},
           ),
       ],
       approved_changes=[
           ApprovedChange(
               object_id='public.orders',
               grantee='analyst',
               privilege='UPDATE',
               action='grant',
           ),
       ],
   )
   print(result.decision)
   print(result.privilege_diff)

``object_id`` is the stable identity. When it is omitted it defaults to the
initial qualified name. An ``ALTER TABLE ... RENAME TO`` or ``SET SCHEMA``
changes the current schema and name but keeps the same identity, so grants
before and after the rename are attributed to one object. Approvals may refer
to the stable id or to any name the object had during the migration.

``InitialObject.privileges`` maps a grantee to a privilege string or an
iterable of privileges. ``ApprovedChange.action`` is ``grant`` or ``revoke``.
An approval with privilege ``ALL`` or ``*`` covers every privilege for that
object, grantee and action.

Supported grammar subset
------------------------

The subset is intentionally explicit. Keywords are matched without regard to
case; whitespace and SQL comments are ignored. Only one- and two-part object
names are accepted. Identifier matching is case-insensitive after quoted
identifiers are unquoted; the precheck does not model quoted-identifier case
sensitivity.

Transaction control:

.. code-block:: text

   BEGIN [WORK | TRANSACTION];
   START TRANSACTION;
   COMMIT [WORK | TRANSACTION];
   ROLLBACK [WORK];
   ROLLBACK [WORK] TO [SAVEPOINT] name;
   SAVEPOINT name;
   RELEASE [SAVEPOINT] name;

Privileges:

.. code-block:: text

   GRANT privilege [, ...] ON [TABLE | SEQUENCE | SCHEMA | DATABASE] object
       TO role [, ...];
   REVOKE privilege [, ...] ON [TABLE | SEQUENCE | SCHEMA | DATABASE] object
       FROM role [, ...];
   ALL [PRIVILEGES]

The known privileges are ``SELECT``, ``INSERT``, ``UPDATE``, ``DELETE``,
``TRUNCATE``, ``REFERENCES``, ``TRIGGER``, ``USAGE``, ``CREATE``, ``CONNECT``,
``TEMPORARY``, ``TEMP`` and ``EXECUTE``. ``ALL`` expands according to the
object kind. A privilege that is not valid for the object kind is a statement
failure.

Object names:

.. code-block:: text

   ALTER TABLE [schema.]old_name RENAME TO new_name;
   ALTER TABLE [schema.]old_name SET SCHEMA new_schema;

Only table renames are supported. The precheck rejects column/constraint
renames, three-part names, DML, other DDL, column-level grants, role/group
syntax, ``WITH GRANT OPTION``, ``CASCADE``/``RESTRICT``, ``GRANT ... ON ALL
TABLES IN SCHEMA``, function signatures and PL/pgSQL blocks.

Transaction and savepoint semantics
-----------------------------------

Outside an explicit transaction every statement is treated as autocommit.
Inside a transaction the precheck keeps a working copy of the catalog.

* ``COMMIT`` makes the working copy the committed state.
* ``ROLLBACK`` discards the working copy.
* A savepoint snapshots both privilege grants and current object names.
* ``ROLLBACK TO SAVEPOINT`` restores that snapshot, discards all later
  savepoints and marks effects after the target as rolled back. The target
  savepoint remains valid, as in PostgreSQL.
* ``RELEASE SAVEPOINT`` destroys the named savepoint and all nested savepoints
  but keeps their effects in the transaction.

If a recognized statement cannot be applied (for example, an unknown object,
an invalid privilege for the object kind, or a missing savepoint), the
statement is rejected. Inside a transaction the transaction becomes aborted:
later non-control statements are skipped, ``COMMIT`` behaves as ``ROLLBACK``,
and ``ROLLBACK TO SAVEPOINT`` can recover to an earlier savepoint. Outside a
transaction the migration is treated as stopping at the failure.

.. important::

   A statement outside the grammar subset is not guessed. It makes the
   transaction outcome and the affected post-commit privilege conclusions
   unknown, and the result lists those affected conclusions in
   ``uncertainties``. An open or failed transaction at end of file has the
   same effect. All of these cases force ``manual_review``.

Decision rule
-------------

``decision`` is ``approved`` only when all of the following hold:

* the post-commit state is known;
* every net privilege delta between initial and committed state appears in
  the approved allowlist, including revokes;
* no statement failed or is unsupported, and no transaction is left open or
  unknown.

Otherwise ``decision`` is ``manual_review`` and ``release_ok`` is false.
Approvals are a whitelist, not a required plan: a permitted change that has no
net effect is reported in ``approved_changes_not_applied`` but does not by
itself block approval.

Result shape
------------

``PrecheckResult.to_dict()`` returns JSON-serializable data. The main keys are:

``decision``, ``release_ok``, ``summary``, ``status``
   Approval outcome, with ``status`` equal to ``known`` or ``unknown``.

``initial_objects``, ``post_commit_objects``
   Catalog snapshots. ``post_commit_objects`` is ``None`` when the commit
   outcome is unknown.

``privilege_diff``
   ``added`` and ``removed`` lists, each item carrying stable ``object_id``,
   current ``object_name``, ``grantee``, ``privilege``, ``action`` and an
   ``approved`` boolean. ``unapproved`` lists the blocking deltas.

``statements``
   One entry per statement with its original SQL, ``kind``, ``status``,
   human-readable ``reason`` and concrete ``effects``. Statuses include
   ``committed``, ``uncommitted``, ``rolled_back``, ``rejected``,
   ``unsupported``, ``skipped`` and ``unknown``.

``uncertainties``
   Each entry names the statement, the reason and the
   ``affected_conclusions``. This is where unsupported syntax, failed
   transactions and open transactions are made explicit.

Command line
------------

Use the installed console script or the module entry point:

.. code-block:: bash

   sqlparse-precheck migration.sql --state state.json
   python -m sqlparse.precheck migration.sql --state state.json --json

The state file is JSON with ``initial_objects`` and optional
``approved_changes``. Exit status is ``0`` for approved, ``1`` for manual
review and ``2`` for bad input.

Two closely related sample migrations live in
``examples/privilege_precheck/``. They have the same rename and grants, but
one places the savepoint before a risky ``DELETE`` and the other places it
after. The savepoint coverage is therefore different, which is the difference
between an approved result and a manual-review result.
