.. change::
    :tags: feature, sql

    Added composable JSON path update expressions to the
    :class:`_types.JSON` datatype:
    :meth:`_types.JSON.Comparator.set_path` and
    :meth:`_types.JSON.Comparator.remove_path` produce expressions
    that set or delete the value at a path of string keys and integer
    array indexes.  Paths and values are always sent as bound parameters,
    and the expressions can be used in UPDATE statements, embedded in
    SELECT statements, or nested inside each other.  The expressions are
    implemented for SQLite (via ``JSON_SET`` /
    ``JSON_REMOVE``) and PostgreSQL (via
    ``jsonb_set`` / ``#-``); other
    dialects raise :class:`_exc.UnsupportedCompilationError`.
