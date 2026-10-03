.. change::
    :tags: feature, operations, autogenerate

    Added first-class support for ordinary SQL views.  New
    :meth:`.Operations.create_view`, :meth:`.Operations.drop_view` and
    :meth:`.Operations.replace_view` operations emit portable
    ``CREATE VIEW`` / ``DROP VIEW`` DDL, including online execution on
    SQLite and offline SQL generation for PostgreSQL.  Views are
    declared with the new :class:`~alembic.views.View` construct and
    compared by autogenerate: view-to-view dependencies determine
    create/drop order, changing a view that other views depend on
    produces an executable "drop dependents first, then recreate"
    plan (with the downgrade restoring the previous definitions), and a
    cycle raises :class:`~alembic.views.CircularViewDependencyError`
    naming the involved views.  Definition comparison is conservative
    -- it ignores only whitespace/comments between lexical tokens, a
    reflected ``CREATE VIEW ... AS`` wrapper and keyword letter case,
    while preserving identifiers, quoted names, string and numeric
    literals exactly -- and custom schemas as well as quoted view names
    are quoted correctly.
