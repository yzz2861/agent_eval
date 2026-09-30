.. change::
    :tags: feature, commands

    Added a structured migration planning facility.  The new
    :func:`.plan.build_plan` API computes, for a given target
    revision and set of current heads, the ordered list of migration steps
    Alembic would run along with the version table changes each step would
    perform, without executing any ``upgrade()`` /
    ``downgrade()`` functions.  The new
    ``alembic plan`` command renders this plan on the
    command line, either reading the current heads from the database with a
    read-only query (never creating the version table) or using explicitly
    supplied heads via ``--current-heads`` for fully
    offline planning.  Planning failures are reported using the new
    distinguishable exceptions :class:`.AmbiguousTargetError`,
    :class:`.RevisionNotFoundError` and
    :class:`.UnreachableRangeError`.
