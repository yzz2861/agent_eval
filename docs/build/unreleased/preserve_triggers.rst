.. change::
    :tags: feature, sqlite

    Added a new parameter
    :paramref:`.Operations.batch_alter_table.preserve_triggers` which
    preserves triggers defined on a table across a batch "move and
    copy" table recreate, rather than silently dropping them along
    with the original table.  Trigger definitions are read before the
    original table is dropped, are adjusted for column and table
    renames applied by the batch operation (including OLD/NEW
    references, UPDATE OF column lists and WHEN clauses, without
    touching string literals, comments or similarly named
    identifiers), and are replayed once the new table is in place.
    Triggers that reference a column being dropped, or whose
    definition cannot be reliably interpreted, raise an error before
    any DDL is emitted.

    Additionally, :meth:`.BatchOperations.rename_table` is now
    supported, allowing a table rename to be included in a batch
    operation; previously this raised NotImplementedError when the
    table was recreated.
