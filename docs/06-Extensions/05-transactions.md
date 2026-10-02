---
id: transactions
title: Transactions
---

Ariadne provides an optional `TransactionExtension` that wraps the execution of mutations in an application-provided transaction. If any of the mutation's resolvers raises an exception, the transaction is rolled back, so changes made by other top-level mutation fields are not persisted.

The extension is ORM-agnostic: the application provides a transaction factory and Ariadne only calls `commit()` or `rollback()` on the transaction object it returns.


## Enabling transactions

Initialize `TransactionExtension` with a transaction factory and add it to the `extensions` option of your GraphQL server:

```python
from functools import partial

from ariadne import TransactionExtension
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler

from .schema import schema
from .database import create_transaction


app = GraphQL(
    schema,
    http_handler=GraphQLHTTPHandler(
        extensions=[partial(TransactionExtension, create_transaction)],
    ),
)
```

The transaction factory is called with the GraphQL context value at the start of a mutation's execution and should return a transaction object:

```python
def create_transaction(context):
    return context["db_connection"]
```

The transaction object is expected to define `commit()` and `rollback()` methods. Both methods may be synchronous or asynchronous, but asynchronous variants require the asynchronous `graphql` query executor (used by the ASGI server). Asynchronous factories are supported in the same way.

For example, a `sqlite3.Connection` already implements this interface, so it can be returned from the factory as-is. For SQLAlchemy, the factory could return `session.begin_nested()`'s transaction or a small wrapper calling `session.commit()` and `session.rollback()`.


## Transaction lifecycle

The transaction is started after the operation was parsed and validated, and only if the executed operation is a mutation. Queries and subscriptions are executed without a transaction.

After the mutation finishes executing:

- If the result contains no errors, the transaction is committed.
- If the result contains errors, the transaction is rolled back. Note that GraphQL collects resolver exceptions into the `errors` list of the response, which may still be returned with a success HTTP status code. The transaction is rolled back in this case too.
- If the execution raises an exception or is cancelled, the transaction is rolled back and the exception is re-raised.

If the commit itself fails, the error is converted to a `GraphQLError` and returned to the client in the response's `errors` list.

If multiple `TransactionExtension` instances are enabled, their transactions are started in order and rolled back in reverse order.
