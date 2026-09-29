.. change::
    :tags: feature, sql

    Added composable JSON path modification expressions,
    :meth:`_types.JSON.Comparator.json_set` and
    :meth:`_types.JSON.Comparator.json_delete`, to the
    :class:`_types.JSON` datatype.  These build new JSON documents with a
    value set at, or a key/element removed from, a path of string keys and
    integer array indexes, where the path and all values are rendered as
    bound parameters.  The expressions may be used in UPDATE statements,
    SELECT lists, or nested within each other.  The SQLite dialect renders
    ``JSON_SET`` / ``JSON_REMOVE`` and the PostgreSQL dialect renders
    ``jsonb_set()`` / the ``#-`` operator; other backends raise
    :class:`_exc.UnsupportedCompilationError` when the expression is
    compiled.

