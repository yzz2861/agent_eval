Saving query descriptions
=========================

The ``playhouse.query_description`` module stores SELECT queries as a
versioned JSON description. Use it to persist configured Peewee queries without
pickle or arbitrary SQL.

Models, fields and explicit tables are resolved through ``QueryRegistry``
using stable identifiers. Literal parameters are stored separately from
expression nodes. Function names, casts and collations must be whitelisted.
The decoder only constructs query objects; it never imports modules,
evaluates strings or executes SQL.

.. code-block:: python

    registry = QueryRegistry()
    registry.register_model(User, "identity.user")
    registry.register_model(Tweet, "identity.tweet")

    description = dumps_query(query, registry)
    restored = loads_query(description, registry)

The JSON document does not contain database connection information. Pass
``bind_database=False`` to leave the restored query unbound. The root model
database is used by default.

Custom functions must be registered before encoding:

.. code-block:: python

    registry.register_function("APP_LEX", "lex")

Version 1 supports projections, WHERE and HAVING expressions, ordering,
joins, scalar and derived-table subqueries, CTEs, compound SELECT queries,
aliases, CASE and CAST expressions, and whitelisted functions. Unsupported
nodes report the invalid description path.
