.. change::
    :tags: feature, operations, autogenerate

    Added formal support for managing database views. The new operations
    :meth:`.Operations.create_view`, :meth:`.Operations.drop_view`, and
    :meth:`.Operations.replace_view` emit portable CREATE VIEW / DROP VIEW
    DDL that works for both online migrations and offline (``--sql``) SQL
    generation, including custom schemas and forced identifier quoting.
    Views are declared to autogenerate through the new :class:`.View` and
    :class:`.ViewRegistry` constructs passed as ``target_views`` (or
    attached to ``MetaData.info['views']``). View interdependencies are
    analyzed so creates run dependency-first and drops dependents-first;
    modifying a view that other views depend on produces an explicit,
    reviewable drop-then-rebuild plan, while a dependency cycle raises an
    error naming the views involved. Definitions are compared with a
    conservative tokenizer that ignores only whitespace, comments and
    unquoted-identifier case, keeping literals, quoted identifiers, and
    keyword/column order significant.
