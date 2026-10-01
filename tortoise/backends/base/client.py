from __future__ import annotations

import abc
import asyncio
import contextlib
import inspect
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Generic, TypeAlias, TypeVar, cast

from pypika_tortoise import Query

from tortoise.backends.base.executor import BaseExecutor
from tortoise.backends.base.schema_generator import BaseSchemaGenerator
from tortoise.connection import get_connections
from tortoise.exceptions import TransactionManagementError
from tortoise.log import db_client_logger

T_conn = TypeVar("T_conn")  # Instance of client connection, such as: asyncpg.Connection()

#: Async context manager that yields an open :class:`BaseStreamingCursor`.
StreamContext: TypeAlias = "contextlib.AbstractAsyncContextManager[BaseStreamingCursor[Any]]"

#: A callable returning a password, awaited first if it returns an awaitable.
PasswordFactory: TypeAlias = Callable[[], "str | Awaitable[str]"]
PasswordType: TypeAlias = "str | PasswordFactory | None"


async def resolve_password(password: PasswordType) -> str | None:
    """
    Resolve a password that may be supplied as a plain string or as a callable.

    Callables are invoked once per connection attempt, which allows short-lived
    credentials (AWS RDS IAM tokens, Azure Entra ID tokens, Vault leases, ...) to be
    refreshed transparently without recreating the client.

    :param password: A string, ``None``, or a sync/async callable returning a string.
    """
    if callable(password):
        resolved = password()
        if inspect.isawaitable(resolved):
            resolved = await resolved
        return resolved
    return password


class Capabilities:
    """
    DB Client Capabilities indicates the supported feature-set,
    and is also used to note common workarounds to deficiencies.

    Defaults are set with the following standard:

    * Deficiencies: assume it is working right.
    * Features: assume it doesn't have it.

    :param dialect: Dialect name of the DB Client driver.
    :param daemon: Is the DB an external Daemon we connect to?
    :param requires_limit:  Indicates that this DB requires a ``LIMIT`` statement for
        an ``OFFSET`` statement to work.
    :param inline_comment: Indicates that comments should be rendered in line with the
        DDL statement, and not as a separate statement.
    :param supports_transactions: Indicates that this DB supports transactions.
    :param support_for_update: Indicates that this DB supports SELECT ... FOR UPDATE SQL statement.
    :param support_for_update_no_key: Indicates that this DB supports SELECT ... FOR NO KEY UPDATE SQL statement.
    :param support_index_hint: Support force index or use index.
    :param support_update_limit_order_by: support update/delete with limit and order by.
    :param support_for_posix_regex_queries: indicated if the db supports posix regex queries
    :param support_json_attributes: indicated if the db supports accessing json attributes
    :param can_rollback_ddl: Whether the database supports transactional DDL.
        Used to determine if migrations can be run atomically.
    :param support_returning: Indicates that this DB supports INSERT ... RETURNING.
    """

    def __init__(
        self,
        dialect: str,
        *,
        # Is the connection a Daemon?
        daemon: bool = True,
        # Deficiencies to work around:
        requires_limit: bool = False,
        inline_comment: bool = False,
        supports_transactions: bool = True,
        support_for_update: bool = True,
        support_for_no_key_update: bool = False,
        # Support force index or use index?
        support_index_hint: bool = False,
        # support update/delete with limit and order by
        support_update_limit_order_by: bool = True,
        support_for_posix_regex_queries: bool = False,
        support_json_attributes: bool = False,
        can_rollback_ddl: bool = False,
        support_returning: bool = False,
    ) -> None:
        super().__setattr__("_mutable", True)

        self.dialect = dialect
        self.daemon = daemon
        self.requires_limit = requires_limit
        self.inline_comment = inline_comment
        self.supports_transactions = supports_transactions
        self.support_for_update = support_for_update
        self.support_for_no_key_update = support_for_no_key_update
        self.support_index_hint = support_index_hint
        self.support_update_limit_order_by = support_update_limit_order_by
        self.support_for_posix_regex_queries = support_for_posix_regex_queries
        self.support_json_attributes = support_json_attributes
        self.can_rollback_ddl = can_rollback_ddl
        self.support_returning = support_returning
        super().__setattr__("_mutable", False)

    def __setattr__(self, attr: str, value: Any) -> None:
        if not getattr(self, "_mutable", False):
            raise AttributeError(attr)
        super().__setattr__(attr, value)

    def __str__(self) -> str:
        return str(self.__dict__)


class BaseDBAsyncClient(abc.ABC):
    """
    Base class for containing a DB connection.

    Parameters get passed as kwargs, and is mostly driver specific.

    .. attribute:: query_class
        :annotation: type[pypika_tortoise.Query]

        The PyPika Query dialect (low level dialect)

    .. attribute:: executor_class
        :annotation: type[BaseExecutor]

        The executor dialect class (high level dialect)

    .. attribute:: schema_generator
        :annotation: type[BaseSchemaGenerator]

        The DDL schema generator

    .. attribute:: capabilities
        :annotation: Capabilities

        Contains the connection capabilities
    """

    _connection: Any
    _parent: BaseDBAsyncClient
    _pool: Any
    _bound_loop: asyncio.AbstractEventLoop | None = None
    connection_name: str
    query_class: type[Query] = Query
    executor_class: type[BaseExecutor] = BaseExecutor
    schema_generator: type[BaseSchemaGenerator] = BaseSchemaGenerator
    capabilities: Capabilities = Capabilities("")

    def __init__(self, connection_name: str, fetch_inserted: bool = True, **kwargs: Any) -> None:
        self.log = db_client_logger
        self.connection_name = connection_name
        self.fetch_inserted = fetch_inserted

    def _check_loop(self) -> bool:
        """Check if the current event loop matches the one this client was created on."""
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            return True  # No running loop — can't validate
        if self._bound_loop is None:
            return True  # Not yet bound (pool not created yet)
        return self._bound_loop is current

    async def _post_connect(self) -> None:
        """Called after pool/connection is created. Records the bound loop."""
        self._bound_loop = asyncio.get_running_loop()

    async def create_connection(self, with_db: bool) -> None:
        """
        Establish a DB connection.

        :param with_db: If True, then select the DB to use, else use default.
            Use case for this is to create/drop a database.
        """
        raise NotImplementedError()  # pragma: nocoverage

    async def close(self) -> None:
        """
        Closes the DB connection.
        """
        raise NotImplementedError()  # pragma: nocoverage

    async def db_create(self) -> None:
        """
        Created the database in the server. Typically only called by the test runner.

        Need to have called ``create_connection()``` with parameter ``with_db=False`` set to
        use the default connection instead of the configured one, else you would get errors
        indicating the database doesn't exist.
        """
        raise NotImplementedError()  # pragma: nocoverage

    async def db_delete(self) -> None:
        """
        Delete the database from the Server. Typically only called by the test runner.

        Need to have called ``create_connection()``` with parameter ``with_db=False`` set to
        use the default connection instead of the configured one, else you would get errors
        indicating the database is in use.
        """
        raise NotImplementedError()  # pragma: nocoverage

    def acquire_connection(self) -> ConnectionWrapper | PoolConnectionWrapper:
        """
        Acquires a connection from the pool.
        Will return the current context connection if already in a transaction.
        """
        raise NotImplementedError()  # pragma: nocoverage

    def _in_transaction(self) -> TransactionContext:
        raise NotImplementedError()  # pragma: nocoverage

    async def execute_insert(self, query: str, values: list) -> Any:
        """
        Executes a RAW SQL insert statement, with provided parameters.

        :param query: The SQL string, pre-parametrized for the target DB dialect.
        :param values: A sequence of positional DB parameters.
        :return: The primary key if it is generated by the DB.
            (Currently only integer autonumber PK's)
        """
        raise NotImplementedError()  # pragma: nocoverage

    async def execute_query(
        self, query: str, values: list | None = None
    ) -> tuple[int, Sequence[dict]]:
        """
        Executes a RAW SQL query statement, and returns the resultset.

        :param query: The SQL string, pre-parametrized for the target DB dialect.
        :param values: A sequence of positional DB parameters.
        :return: A tuple of: (The number of rows affected, The resultset)
        """
        raise NotImplementedError()  # pragma: nocoverage

    def execute_query_stream(
        self, query: str, values: list | None = None
    ) -> "StreamContext":
        """
        Open a streaming cursor for a RAW select query.

        Returns an async context manager that yields a
        :class:`BaseStreamingCursor`.  Rows are fetched lazily with
        ``fetchmany``, so the connection stays busy only while the result is
        being consumed; closing the cursor releases the connection (or the
        transaction's lock) immediately.
        """
        raise NotImplementedError()  # pragma: nocoverage

    async def execute_script(self, query: str) -> None:
        """
        Executes a RAW SQL script with multiple statements, and returns nothing.

        :param query: The SQL string, which will be passed on verbatim.
            Semicolons is supported here.
        """
        raise NotImplementedError()  # pragma: nocoverage

    async def execute_many(self, query: str, values: list[list]) -> None:
        """
        Executes a RAW bulk insert statement, like execute_insert, but returns no data.

        :param query: The SQL string, pre-parametrized for the target DB dialect.
        :param values: A sequence of positional DB parameters.
        """
        raise NotImplementedError()  # pragma: nocoverage

    async def execute_query_dict(self, query: str, values: list | None = None) -> list[dict]:
        """
        Executes a RAW SQL query statement, and returns the resultset as a list of dicts.

        :param query: The SQL string, pre-parametrized for the target DB dialect.
        :param values: A sequence of positional DB parameters.
        """
        return (await self.execute_query_dict_with_affected(query, values))[0]

    async def execute_query_dict_with_affected(
        self, query: str, values: list | None = None
    ) -> tuple[list[dict], int]:
        """
        Executes a RAW SQL query statement, and returns the resultset as a list of dicts
        along with the rows affected if available.

        :param query: The SQL string, pre-parametrized for the target DB dialect.
        :param values: A sequence of positional DB parameters.
        """
        rowcount, rows = await self.execute_query(query, values)
        normalized = [dict(row) for row in rows]
        return normalized, rowcount


class TransactionalDBClient(BaseDBAsyncClient, abc.ABC):
    """An interface of the DB client that supports transactions."""

    _finalized: bool = False

    @abc.abstractmethod
    async def begin(self) -> None: ...

    @abc.abstractmethod
    async def savepoint(self) -> None: ...

    @abc.abstractmethod
    async def rollback(self) -> None: ...

    @abc.abstractmethod
    async def savepoint_rollback(self) -> None: ...

    @abc.abstractmethod
    async def commit(self) -> None: ...

    @abc.abstractmethod
    async def release_savepoint(self) -> None: ...


class ConnectionWrapper(Generic[T_conn]):
    """Wraps the connections with a lock to facilitate safe concurrent access when using
    asyncio.gather, TaskGroup, or similar."""

    __slots__ = ("connection", "_lock", "client")

    def __init__(self, lock: asyncio.Lock, client: BaseDBAsyncClient) -> None:
        self._lock: asyncio.Lock = lock
        self.client = client
        self.connection: T_conn = client._connection

    async def ensure_connection(self) -> None:
        if not self.connection:
            await self.client.create_connection(with_db=True)
            self.connection = self.client._connection

    async def __aenter__(self) -> T_conn:
        await self._lock.acquire()
        await self.ensure_connection()
        return self.connection

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._lock.release()


class TransactionContext:
    """A context manager interface for transactions. It is returned from in_transaction
    and _in_transaction."""

    client: TransactionalDBClient

    @abc.abstractmethod
    async def __aenter__(self) -> TransactionalDBClient: ...

    @abc.abstractmethod
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...


class TransactionContextPooled(TransactionContext):
    "A version of TransactionContext that uses a pool to acquire connections."

    __slots__ = ("client", "connection_name", "token", "_pool_init_lock")

    def __init__(self, client: TransactionalDBClient, pool_init_lock: asyncio.Lock) -> None:
        self.client = client
        self.connection_name = client.connection_name
        self._pool_init_lock = pool_init_lock

    async def ensure_connection(self) -> None:
        if not self.client._parent._pool:
            # a safeguard against multiple concurrent tasks trying to initialize the pool
            async with self._pool_init_lock:
                if not self.client._parent._pool:
                    await self.client._parent.create_connection(with_db=True)

    async def __aenter__(self) -> TransactionalDBClient:
        await self.ensure_connection()
        # Acquire connection first to avoid race condition where concurrent tasks
        # see the wrapper via the context before it has a connection.
        self.client._connection = await self.client._parent._pool.acquire()
        # Set the context variable so the current task is always seeing a
        # TransactionWrapper connection.
        self.token = get_connections().set(self.connection_name, self.client)
        await self.client.begin()
        return self.client

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            if not self.client._finalized:
                if exc_type:
                    # Can't rollback a transaction that already failed.
                    if exc_type is not TransactionManagementError:
                        await self.client.rollback()
                else:
                    await self.client.commit()
        finally:
            if self.client._parent._pool:
                await self.client._parent._pool.release(self.client._connection)
            get_connections().reset(self.token)


class NestedTransactionContext(TransactionContext):
    __slots__ = ("client", "connection_name")

    def __init__(self, client: TransactionalDBClient) -> None:
        self.client = client
        self.connection_name = client.connection_name

    async def __aenter__(self) -> TransactionalDBClient:
        await self.client.savepoint()
        return self.client

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if not self.client._finalized:
            if exc_type:
                # Can't rollback a transaction that already failed.
                if exc_type is not TransactionManagementError:
                    await self.client.savepoint_rollback()
            else:
                await self.client.release_savepoint()


class PoolConnectionWrapper(Generic[T_conn]):
    """Class to manage acquiring from and releasing connections to a pool."""

    __slots__ = ("client", "connection", "_pool_init_lock")

    def __init__(self, client: BaseDBAsyncClient, pool_init_lock: asyncio.Lock) -> None:
        self.client = client
        self.connection: T_conn | None = None
        self._pool_init_lock = pool_init_lock

    async def ensure_connection(self) -> None:
        if not self.client._pool:
            # a safeguard against multiple concurrent tasks trying to initialize the pool
            async with self._pool_init_lock:
                if not self.client._pool:
                    await self.client.create_connection(with_db=True)

    async def __aenter__(self) -> T_conn:
        await self.ensure_connection()
        # get first available connection. If none available, wait until one is released
        self.connection = await self.client._pool.acquire()
        return cast(T_conn, self.connection)

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # release the connection back to the pool
        await self.client._pool.release(self.connection)


class HeldConnectionWrapper(Generic[T_conn]):
    """Connection wrapper that hands out a connection that is already held.

    A streaming cursor keeps its connection (and any pool slot or transaction
    lock associated with it) for its whole lifetime.  Queries issued while the
    cursor is open - e.g. the per-batch prefetch queries - must reuse the very
    same physical connection instead of trying to acquire it again, otherwise
    non-reentrant locks would deadlock and pool slots would leak.
    """

    __slots__ = ("connection",)

    def __init__(self, connection: T_conn) -> None:
        self.connection: T_conn = connection

    async def __aenter__(self) -> T_conn:
        return self.connection

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        return None


class BaseStreamingCursor(abc.ABC, Generic[T_conn]):
    """An open server-side (or driver) cursor that yields rows in batches.

    The cursor owns its resources (open driver cursor, acquired connection,
    pool slot/transaction lock) until :meth:`aclose` is called.  ``fetchmany``
    reads at most *size* rows at a time, so a slow consumer never causes rows
    beyond the current batch to be fetched.  ``sibling_client`` is a DB client
    that executes queries on the same held connection and is used by the ORM
    to run the prefetch queries for the current batch.
    """

    connection: T_conn
    cursor: Any
    sibling_client: "BaseDBAsyncClient"
    _closed: bool = False

    @abc.abstractmethod
    async def fetchmany(self, size: int) -> Sequence[dict]:
        """Fetch up to *size* rows without materialising the whole result."""

    @abc.abstractmethod
    async def _close_cursor(self) -> None:
        """Backend-specific cleanup of the driver cursor."""

    def _release_connection(self) -> Any:
        """Release the held connection (pool slot/lock). May return an awaitable."""
        return None

    async def aclose(self) -> None:
        """Close the cursor and release the connection back to the pool/lock."""
        if self._closed:
            return
        self._closed = True
        try:
            await self._close_cursor()
        finally:
            released = self._release_connection()
            if inspect.isawaitable(released):
                await released

    async def __aenter__(self) -> "BaseStreamingCursor[T_conn]":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()


class PooledStreamingCursor(BaseStreamingCursor[T_conn]):
    """Streaming cursor for backends whose connections come from a pool.

    A pool connection is acquired when the stream opens and released back to
    the pool when the cursor closes.  Subclasses implement the driver-specific
    cursor creation/fetch/close primitives.
    """

    def __init__(
        self,
        client: "BaseDBAsyncClient",
        connection: T_conn,
        sibling_client: "BaseDBAsyncClient",
        release_connection: Any = None,
    ) -> None:
        self.client = client
        self.connection = connection
        self.sibling_client = sibling_client
        self._release_callback = release_connection
        self.cursor: Any = None
        self._closed = False

    @abc.abstractmethod
    async def _open_cursor(self, query: str, values: list | None) -> None:
        """Open the driver cursor and execute *query*."""

    async def _release_connection(self) -> Any:
        if self._release_callback is not None:
            return self._release_callback()
        pool_owner = getattr(self.client, "_parent", None) or self.client
        pool = getattr(pool_owner, "_pool", None)
        if pool is not None:
            return pool.release(self.connection)
        return None


class PooledStreamContext(Generic[T_conn]):
    """Opens a :class:`PooledStreamingCursor` subclass over a pooled connection."""

    def __init__(
        self,
        client: "BaseDBAsyncClient",
        cursor_cls: type[PooledStreamingCursor[T_conn]],
        query: str,
        values: list | None,
    ) -> None:
        self._client = client
        self._cursor_cls = cursor_cls
        self._query = query
        self._values = values
        self._stream: PooledStreamingCursor[T_conn] | None = None

    async def __aenter__(self) -> PooledStreamingCursor[T_conn]:
        owner = getattr(self._client, "_parent", None)
        if owner is not None and not isinstance(
            self._client.acquire_connection(), PoolConnectionWrapper
        ):
            # Inside a transaction the wrapper already owns a single
            # connection guarded by its (non-reentrant) lock.  Reuse that
            # connection directly instead of trying to acquire it again.
            # Closing the stream releases the transaction wrapper's lock
            # (but not the physical connection, which the transaction owns).
            connection = self._client._connection
            await self._client._lock.acquire()
            in_transaction = True
        else:
            wrapper = self._client.acquire_connection()
            await wrapper.ensure_connection()
            connection = await wrapper.__aenter__()
            in_transaction = False
        sibling = self._sibling_client(connection)
        release = self._release_transaction_lock if in_transaction else None
        stream = self._cursor_cls(self._client, connection, sibling, release)
        try:
            await stream._open_cursor(self._query, self._values)
        except BaseException:
            await stream.aclose()
            raise
        self._stream = stream
        return stream

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._stream is not None:
            await self._stream.aclose()

    def _sibling_client(self, connection: T_conn) -> "BaseDBAsyncClient":
        """Return a client that executes queries on the already held connection."""
        owner = getattr(self._client, "_parent", None) or self._client
        return _HeldConnectionClient(owner, self._client, connection)

    def _release_transaction_lock(self) -> Any:
        """Release only the transaction wrapper's serialization lock.

        The physical connection belongs to the transaction and is returned to
        the pool when the transaction commits/rolls back, not when the stream
        closes.
        """
        wrapper = self._client.acquire_connection()
        if isinstance(wrapper, ConnectionWrapper):
            wrapper._lock.release()
        return None


class _HeldConnectionClient:
    """Proxy DB client that reuses a connection held by an open stream.

    It delegates everything to *owner* but hands out *connection* from
    ``acquire_connection`` so per-batch prefetch queries participate in the
    same transaction/connection instead of acquiring the pool slot a second
    time.
    """

    __slots__ = ("_owner", "_transaction_client", "_connection")

    def __init__(
        self,
        owner: "BaseDBAsyncClient",
        transaction_client: "BaseDBAsyncClient",
        connection: Any,
    ) -> None:
        self._owner = owner
        self._transaction_client = transaction_client
        self._connection = connection

    @property
    def _parent(self) -> BaseDBAsyncClient:
        return self._owner

    def acquire_connection(self) -> HeldConnectionWrapper:
        return HeldConnectionWrapper(self._connection)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._transaction_client, item)
