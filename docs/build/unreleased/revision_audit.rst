.. change::
    :tags: feature, autogenerate

    Added an opt-in migration operation-tree audit phase, enabled via the
    new ``revision_audit`` configuration option / ``--revision-audit`` flag
    of the ``alembic revision`` command.  The audit walks the in-memory
    :class:`.MigrationScript` operation tree (including batch /
    :class:`.ModifyTableOps` containers and multi-engine upgrade/downgrade
    branches), reporting ``drop_table``, ``drop_column`` and potentially
    data-losing ``alter_column`` type changes with concrete object names and
    full operation paths.  Type narrowing is decided by a pluggable dialect
    type policy and an optional user callback; unknown conversions are
    reported as an explicit ``unknown`` severity rather than being treated
    as safe.  Custom operations may register their own checkers, checker
    exceptions are collected separately from findings, and a report-only
    mode leaves migration output unchanged.  See :ref:`migration_audit`.

