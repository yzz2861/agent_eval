---
id: transactions
title: Mutation transactions
---

Ariadne provides optional `TransactionExtension` that wraps mutation operations in transactions. When any of the mutation's fields fails, all the changes made by other fields are rolled back, even though GraphQL still returns HTTP 200 response with errors in the `errors` key.

The extension is ORM-agnostic: the application provides a transaction factory and Ariadne only calls `commit()` or `rollback()` on the transaction object it returns.


## Enabling transactions

Pass `TransactionExtension` initialized with a transaction factory to the `extensions` option:

```python
from ariadne import TransactionExtension
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLHTTPHandler

from .schema import schema


def transaction_factory(context):
    return context["db_session"]  # object with commit() and rollback()


app = GraphQL(
    schema,
    http_handler=GraphQLHTTPHandler(
        extensions=[lambda: TransactionExtension(transaction_factory)],
    ),
)
```

The transaction factory is a callable that takes the GraphQL context value and returns a transaction object. In asynchronous servers the factory may also be an `async` function (or return an awaitable), and `commit()`/`rollback()` may be async as well.


## Transaction lifecycle

- Transaction is started after the query is parsed and validated, just before the mutation execution begins.
- Only mutations are wrapped in transactions. Queries and subscriptions never start a transaction.
- Transaction is committed only when the whole mutation executes without errors.
- Transaction is rolled back when any resolver raises an error, even if other fields resolved successfully and the response still contains partial data.
- Transaction is also rolled back when the execution is interrupted, eg. when the request task is cancelled.
- When the commit itself fails, the error is returned to the client as a GraphQL error in the `errors` key.


## Custom transaction objects

Transaction object only needs to implement the `Transaction` protocol with `commit()` and `rollback()` methods:

```python
class SavepointTransaction:
    def __init__(self, connection):
        self.connection = connection

    async def commit(self):
        await self.connection.execute("RELEASE SAVEPOINT ariadne")

    async def rollback(self):
        await self.connection.execute("ROLLBACK TO SAVEPOINT ariadne")


async def transaction_factory(context):
    connection = context["db_connection"]
    await connection.execute("SAVEPOINT ariadne")
    return SavepointTransaction(connection)
```
