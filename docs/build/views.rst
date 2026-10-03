============
Database Views
============

Alembic can create, drop, replace and autogenerate ordinary (non
materialized) database views. View management is dependency aware: the
order in which views are created and dropped is derived from the
relations referenced in each view body, so multi-level views build and
tear down correctly. The same operations work online and in offline
(``--sql``) mode, including against PostgreSQL and SQLite.

Operations
==========

Use :meth:`.Operations.create_view` and :meth:`.Operations.drop_view`
directly in a migration::

    def upgrade():
        op.create_view(
            "active_users",
            "SELECT id, name FROM users WHERE status = 'active'",
        )

    def downgrade():
        op.drop_view("active_users")

The view body may be a bare ``SELECT``, a full ``CREATE VIEW ... AS``
statement, or a SQLAlchemy :class:`.SelectBase` expression. The view and
schema names accept :class:`.quoted_name` to force quoting of otherwise
legal-but-unusual identifiers::

    from sqlalchemy.sql.elements import quoted_name

    op.create_view(
        quoted_name("Order", True),
        'SELECT "id" FROM "Order"',
        schema=quoted_name("my schema", True),
    )

:meth:`.Operations.replace_view` swaps a definition portably using
``DROP VIEW`` followed by ``CREATE VIEW`` (SQLite does not support
``CREATE OR REPLACE``). Passing the previous body makes it reversible::

    op.replace_view(
        "active_users",
        "SELECT id, name FROM users WHERE status = 'active' AND dept = 42",
        old_definition="SELECT id, name FROM users WHERE status = 'active'",
    )

Autogeneration
==============

Tell autogenerate which views should exist with a
:class:`.ViewRegistry` passed through the ``target_views`` option of
:meth:`.EnvironmentContext.configure` in ``env.py``::

    from alembic.operations.views import View, ViewRegistry

    target_views = ViewRegistry(
        [
            View("v_one", "SELECT id, val FROM base WHERE n > 0"),
            View("v_two", "SELECT id FROM v_one"),
            View("v_three", "SELECT id FROM v_two JOIN v_one ON ..."),
        ]
    )

    def run_migrations_online():
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            target_views=target_views,
        )

A registry may also be attached per-metadata via
``my_metadata.info['views']``.

When a view that other views depend on is modified, Alembic emits an
explicit, reviewable teardown/rebuild plan: dependent views are dropped
first (in dependency order), the changed view is recreated, and the
dependents are rebuilt afterwards. If the declared views contain a
dependency cycle, autogeneration raises :class:`.ViewCycleError` naming
every view participating in a cycle.

Definition comparison
=====================

Different backends store view definitions differently. SQLite keeps the
text supplied at creation time while PostgreSQL rewrites and normalizes
it. Alembic therefore compares definitions with a small, conservative
SQL tokenizer:

* whitespace, line and block comments are insignificant;
* the case of unquoted identifiers/keywords is insignificant;
* the contents of string literals and quoted identifiers are significant
  (so ``'ab'`` is not treated as ``'AB'`` and ``"X"`` is not ``"x"``);
* optional keywords, column order and relation qualification are
  significant and are never rewritten away.

A single trailing semicolon is ignored. This is deliberately more
conservative than naive whitespace stripping: a definition whose meaning
could plausibly differ is reported as a change.
