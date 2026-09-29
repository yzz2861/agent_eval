# Copyright Amethyst Reese
# Licensed under the MIT license

"""
Core implementation of aiosqlite proxies
"""

import asyncio
import logging
import sqlite3
from collections.abc import AsyncIterator, Generator, Iterable
from contextvars import ContextVar
from functools import partial
from pathlib import Path
from queue import Empty, Queue, SimpleQueue
from threading import Thread
from typing import Any, Callable, Literal, Optional, Union
from warnings import warn

from .context import contextmanager
from .cursor import Cursor

__all__ = ["connect", "Connection", "Cursor", "Transaction"]

AuthorizerCallback = Callable[[int, str, str, str, str], int]

LOG = logging.getLogger("aiosqlite")


IsolationLevel = Optional[Literal["DEFERRED", "IMMEDIATE", "EXCLUSIVE"]]


def set_result(fut: asyncio.Future, result: Any) -> None:
    """Set the result of a future if it hasn't been set already."""
    if not fut.done():
        fut.set_result(result)


def set_exception(fut: asyncio.Future, e: BaseException) -> None:
    """Set the exception of a future if it hasn't been set already."""
    if not fut.done():
        fut.set_exception(e)


_STOP_RUNNING_SENTINEL = object()
_TxQueue = SimpleQueue[tuple[Optional[asyncio.Future], Callable[[], Any]]]


def _connection_worker_thread(tx: _TxQueue):
    """
    Execute function calls on a separate thread.

    :meta private:
    """
    while True:
        # Continues running until all queue items are processed,
        # even after connection is closed (so we can finalize all
        # futures)

        future, function = tx.get()

        try:
            LOG.debug("executing %s", function)
            result = function()

            if future:
                future.get_loop().call_soon_threadsafe(set_result, future, result)
            LOG.debug("operation %s completed", function)

            if result is _STOP_RUNNING_SENTINEL:
                break

        except BaseException as e:  # noqa B036
            LOG.debug("returning exception %s", e)
            if future:
                future.get_loop().call_soon_threadsafe(set_exception, future, e)


class Connection:
    def __init__(
        self,
        connector: Callable[[], sqlite3.Connection],
        iter_chunk_size: int,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._running = True
        self._connection: Optional[sqlite3.Connection] = None
        self._connector = connector
        self._tx: _TxQueue = SimpleQueue()
        self._iter_chunk_size = iter_chunk_size
        self._thread = Thread(target=_connection_worker_thread, args=(self._tx,))
        self._tx_owner: Optional["Transaction"] = None
        self._tx_depth = 0
        self._tx_idle: Optional[asyncio.Event] = None
        self._tx_context: ContextVar[bool] = ContextVar(
            f"aiosqlite_transaction_{id(self)}", default=False
        )

        if loop is not None:
            warn(
                "aiosqlite.Connection no longer uses the `loop` parameter",
                DeprecationWarning,
            )

    @property
    def _tx_idle_event(self) -> asyncio.Event:
        # Created lazily because asyncio.Event binds to the running loop
        # at creation time on older Python versions.
        if self._tx_idle is None:
            self._tx_idle = asyncio.Event()
            self._tx_idle.set()
        return self._tx_idle

    def __del__(self):
        if self._connection is None:
            return

        warn(
            (
                f"{self!r} was deleted before being closed. "
                "Please use 'async with' or '.close()' to close the connection properly."
            ),
            ResourceWarning,
            stacklevel=1,
        )

        # Don't try to be creative here, the event loop may have already been closed.
        # Simply stop the worker thread, and let the underlying sqlite3 connection
        # be finalized by its own __del__.
        self.stop()

    def stop(self) -> Optional[asyncio.Future]:
        """Stop the background thread. Prefer `async with` or `await close()`"""
        self._running = False

        def close_and_stop():
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            return _STOP_RUNNING_SENTINEL

        try:
            future = asyncio.get_event_loop().create_future()
        except Exception:
            future = None

        self._tx.put_nowait((future, close_and_stop))
        return future

    @property
    def _conn(self) -> sqlite3.Connection:
        if self._connection is None:
            raise ValueError("no active connection")

        return self._connection

    def _execute_insert(self, sql: str, parameters: Any) -> Optional[sqlite3.Row]:
        cursor = self._conn.execute(sql, parameters)
        cursor.execute("SELECT last_insert_rowid()")
        return cursor.fetchone()

    def _execute_fetchall(self, sql: str, parameters: Any) -> Iterable[sqlite3.Row]:
        cursor = self._conn.execute(sql, parameters)
        return cursor.fetchall()

    async def _execute_impl(self, fn, *args, **kwargs):
        """Queue a function with the given arguments for execution."""
        if not self._running or not self._connection:
            raise ValueError("Connection closed")

        function = partial(fn, *args, **kwargs)
        future = asyncio.get_event_loop().create_future()

        self._tx.put_nowait((future, function))

        return await future

    async def _execute(self, fn, *args, **kwargs):
        """
        Queue a function for execution, waiting for any active transaction()
        context owned by another task to finish first.
        """
        while self._tx_owner is not None and not self._tx_context.get():
            await self._tx_idle_event.wait()

        # No await between the ownership check above and queueing the
        # function, so a new transaction cannot interleave in between.
        return await self._execute_impl(fn, *args, **kwargs)

    async def _execute_shielded(self, fn, *args, **kwargs):
        """
        Execute a function on the shared thread, guaranteeing that it runs
        to completion even if the awaiting task is cancelled. Used for
        transaction finalization so that commit/rollback always finish
        before the transaction lock is released.
        """
        task = asyncio.ensure_future(self._execute_impl(fn, *args, **kwargs))
        cancelled = False
        while True:
            try:
                result = await asyncio.shield(task)
                break
            except asyncio.CancelledError:
                if task.done():
                    raise
                cancelled = True
        if cancelled:
            raise asyncio.CancelledError
        return result

    async def _connect(self) -> "Connection":
        """Connect to the actual sqlite database."""
        if self._connection is None:
            try:
                future = asyncio.get_event_loop().create_future()
                self._tx.put_nowait((future, self._connector))
                self._connection = await future
            except BaseException:
                self.stop()
                self._connection = None
                raise

        return self

    def __await__(self) -> Generator[Any, None, "Connection"]:
        self._thread.start()
        return self._connect().__await__()

    async def __aenter__(self) -> "Connection":
        return await self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    @contextmanager
    async def cursor(self) -> Cursor:
        """Create an aiosqlite cursor wrapping a sqlite3 cursor object."""
        return Cursor(self, await self._execute(self._conn.cursor))

    async def commit(self) -> None:
        """
        Commit the current transaction.

        Raises ``sqlite3.ProgrammingError`` if called while a
        :meth:`transaction` context is active on this connection; exit the
        context (or use a nested context) to commit instead.
        """
        if self._tx_owner is not None:
            raise sqlite3.ProgrammingError(
                "cannot commit() while a transaction() context is active; "
                "exit the context to commit, or use a nested transaction() "
                "for savepoints"
            )
        await self._execute(self._conn.commit)

    async def rollback(self) -> None:
        """
        Roll back the current transaction.

        Raises ``sqlite3.ProgrammingError`` if called while a
        :meth:`transaction` context is active on this connection; raise an
        exception inside the context to roll back instead.
        """
        if self._tx_owner is not None:
            raise sqlite3.ProgrammingError(
                "cannot rollback() while a transaction() context is active; "
                "raise an exception inside the context to roll back"
            )
        await self._execute(self._conn.rollback)

    def transaction(self) -> "Transaction":
        """
        Create an explicit transaction context manager for this connection.

        The transaction is owned by the current task, including any child
        tasks spawned inside the context. While the transaction is active:

        - Operations (``execute``, ``executemany``, ``cursor``, etc.) issued
          from unrelated tasks wait until the transaction has finished, so
          their statements can never be mixed into the owner's commit scope.
        - Nested ``transaction()`` contexts in the same task use SAVEPOINT;
          an exception in an inner context rolls back only that savepoint.
        - ``commit()`` and ``rollback()`` raise ``sqlite3.ProgrammingError``.
        - ``executescript()`` raises ``sqlite3.ProgrammingError`` when
          called from inside the transaction, because sqlite3 would
          silently commit first.
        - ``close()`` raises ``sqlite3.ProgrammingError`` when called from
          inside the transaction; calls from other tasks wait for the
          transaction to finish first.
        - Cancelling the owning task still completes the rollback and
          releases the transaction before the cancellation propagates.

        On clean exit the transaction is committed; on exception it is
        rolled back. Connections that never use ``transaction()`` behave
        exactly as before.

        Example::

            async with db.transaction():
                await db.execute("insert into foo values (1)")
                async with db.transaction():  # savepoint
                    await db.execute("insert into foo values (2)")
        """
        return Transaction(self)

    def _begin_statement(self) -> str:
        """BEGIN statement honoring the configured isolation level."""
        level = self._conn.isolation_level
        if level in ("IMMEDIATE", "EXCLUSIVE"):
            return f"BEGIN {level}"
        return "BEGIN"

    async def close(self) -> None:
        """
        Complete queued queries/cursors and close the connection.

        If a :meth:`transaction` context is active, calling this from inside
        the transaction raises ``sqlite3.ProgrammingError``; calls from other
        tasks wait until the transaction has finished.
        """

        if self._connection is None:
            return
        if self._tx_context.get():
            raise sqlite3.ProgrammingError(
                "cannot close() from inside an active transaction() context; "
                "exit the context first"
            )

        try:
            await self._execute(self._conn.close)
        except Exception:
            LOG.info("exception occurred while closing connection")
            raise
        finally:
            self._connection = None
            future = self.stop()
            if future:
                await future

    @contextmanager
    async def execute(
        self, sql: str, parameters: Optional[Iterable[Any]] = None
    ) -> Cursor:
        """Helper to create a cursor and execute the given query."""
        if parameters is None:
            parameters = []
        cursor = await self._execute(self._conn.execute, sql, parameters)
        return Cursor(self, cursor)

    @contextmanager
    async def execute_insert(
        self, sql: str, parameters: Optional[Iterable[Any]] = None
    ) -> Optional[sqlite3.Row]:
        """Helper to insert and get the last_insert_rowid."""
        if parameters is None:
            parameters = []
        return await self._execute(self._execute_insert, sql, parameters)

    @contextmanager
    async def execute_fetchall(
        self, sql: str, parameters: Optional[Iterable[Any]] = None
    ) -> Iterable[sqlite3.Row]:
        """Helper to execute a query and return all the data."""
        if parameters is None:
            parameters = []
        return await self._execute(self._execute_fetchall, sql, parameters)

    @contextmanager
    async def executemany(
        self, sql: str, parameters: Iterable[Iterable[Any]]
    ) -> Cursor:
        """Helper to create a cursor and execute the given multiquery."""
        cursor = await self._execute(self._conn.executemany, sql, parameters)
        return Cursor(self, cursor)

    @contextmanager
    async def executescript(self, sql_script: str) -> Cursor:
        """
        Helper to create a cursor and execute a user script.

        sqlite3 implicitly commits any pending transaction before running a
        script, so calling this from inside a :meth:`transaction` context
        raises ``sqlite3.ProgrammingError``. Calls from other tasks wait
        until the active transaction has finished.
        """
        if self._tx_context.get():
            raise sqlite3.ProgrammingError(
                "cannot executescript() inside a transaction() context; "
                "sqlite3 would silently commit the transaction first"
            )
        cursor = await self._execute(self._conn.executescript, sql_script)
        return Cursor(self, cursor)

    async def interrupt(self) -> None:
        """Interrupt pending queries."""
        return self._conn.interrupt()

    async def create_function(
        self, name: str, num_params: int, func: Callable, deterministic: bool = False
    ) -> None:
        """
        Create user-defined function that can be later used
        within SQL statements. Must be run within the same thread
        that query executions take place so instead of executing directly
        against the connection, we defer this to `run` function.

        If ``deterministic`` is true, the created function is marked as deterministic,
        which allows SQLite to perform additional optimizations. This flag is supported
        by SQLite 3.8.3 or higher, ``NotSupportedError`` will be raised if used with
        older versions.
        """
        await self._execute(
            self._conn.create_function,
            name,
            num_params,
            func,
            deterministic=deterministic,
        )

    @property
    def in_transaction(self) -> bool:
        return self._conn.in_transaction

    @property
    def isolation_level(self) -> Optional[str]:
        return self._conn.isolation_level

    @isolation_level.setter
    def isolation_level(self, value: IsolationLevel) -> None:
        self._conn.isolation_level = value

    @property
    def row_factory(self) -> Optional[type]:
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, factory: Optional[type]) -> None:
        self._conn.row_factory = factory

    @property
    def text_factory(self) -> Callable[[bytes], Any]:
        return self._conn.text_factory

    @text_factory.setter
    def text_factory(self, factory: Callable[[bytes], Any]) -> None:
        self._conn.text_factory = factory

    @property
    def total_changes(self) -> int:
        return self._conn.total_changes

    async def enable_load_extension(self, value: bool) -> None:
        await self._execute(self._conn.enable_load_extension, value)  # type: ignore

    async def load_extension(self, path: str):
        await self._execute(self._conn.load_extension, path)  # type: ignore

    async def set_progress_handler(
        self, handler: Callable[[], Optional[int]], n: int
    ) -> None:
        await self._execute(self._conn.set_progress_handler, handler, n)

    async def set_trace_callback(self, handler: Callable) -> None:
        await self._execute(self._conn.set_trace_callback, handler)

    async def set_authorizer(
        self, authorizer_callback: Optional[AuthorizerCallback]
    ) -> None:
        """
        Set an authorizer callback to control database access.

        The authorizer callback is invoked for each SQL statement that is prepared,
        and controls whether specific operations are permitted.

        Example::

            import sqlite3

            def restrict_drops(action_code, arg1, arg2, db_name, trigger_name):
                # Deny all DROP operations
                if action_code == sqlite3.SQLITE_DROP_TABLE:
                    return sqlite3.SQLITE_DENY
                # Allow everything else
                return sqlite3.SQLITE_OK

            await conn.set_authorizer(restrict_drops)

        See ``sqlite3`` documentation for details:
        https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.set_authorizer

        :param authorizer_callback: An optional callable that receives five arguments:

            - ``action_code`` (int): The action to be authorized (e.g., ``SQLITE_READ``)
            - ``arg1`` (str): First argument, meaning depends on ``action_code``
            - ``arg2`` (str): Second argument, meaning depends on ``action_code``
            - ``db_name`` (str): Database name (e.g., ``"main"``, ``"temp"``)
            - ``trigger_name`` (str): Name of trigger or view that is doing the access,
              or ``None``

            The callback should return:

            - ``SQLITE_OK`` (0): Allow the operation
            - ``SQLITE_DENY`` (1): Deny the operation, raise ``sqlite3.DatabaseError``
            - ``SQLITE_IGNORE`` (2): Treat operation as no-op

            Pass ``None`` to remove the authorizer.
        """
        await self._execute(self._conn.set_authorizer, authorizer_callback)

    async def iterdump(self) -> AsyncIterator[str]:
        """
        Return an async iterator to dump the database in SQL text format.

        Example::

            async for line in db.iterdump():
                ...

        """
        dump_queue: Queue = Queue()

        def dumper():
            try:
                for line in self._conn.iterdump():
                    dump_queue.put_nowait(line)
                dump_queue.put_nowait(None)

            except Exception:
                LOG.exception("exception while dumping db")
                dump_queue.put_nowait(None)
                raise

        fut = self._execute(dumper)
        task = asyncio.ensure_future(fut)

        while True:
            try:
                line: Optional[str] = dump_queue.get_nowait()
                if line is None:
                    break
                yield line

            except Empty:
                if task.done():
                    LOG.warning("iterdump completed unexpectedly")
                    break

                await asyncio.sleep(0.01)

        await task

    async def backup(
        self,
        target: Union["Connection", sqlite3.Connection],
        *,
        pages: int = 0,
        progress: Optional[Callable[[int, int, int], None]] = None,
        name: str = "main",
        sleep: float = 0.250,
    ) -> None:
        """
        Make a backup of the current database to the target database.

        Takes either a standard sqlite3 or aiosqlite Connection object as the target.
        """
        if isinstance(target, Connection):
            target = target._conn

        await self._execute(
            self._conn.backup,
            target,
            pages=pages,
            progress=progress,
            name=name,
            sleep=sleep,
        )


class Transaction:
    """
    Async context manager managing an explicit transaction on a
    :class:`Connection`. Returned by :meth:`Connection.transaction`; see
    that method for the full set of rules.

    Entering the context begins a transaction owned by the current task.
    While owned, operations from unrelated tasks wait until the context
    exits. Nested entry from the same task issues a SAVEPOINT instead, so
    an exception in an inner context only rolls back to that savepoint.
    Exiting the outermost context commits on success and rolls back on
    exception; finalization always completes, even if the owning task is
    cancelled while exiting.
    """

    def __init__(self, connection: "Connection") -> None:
        self._connection = connection
        self._savepoint: Optional[str] = None
        self._token: Optional["object"] = None
        self._active = False

    async def __aenter__(self) -> "Transaction":
        connection = self._connection
        if self._active:
            raise RuntimeError("transaction context is already active")

        if connection._tx_context.get():
            # nested inside a transaction owned by this task: use a savepoint
            connection._tx_depth += 1
            savepoint = f"aiosqlite_sp_{connection._tx_depth}"
            try:
                await connection._execute_impl(
                    connection._conn.execute, f"SAVEPOINT {savepoint}"
                )
            except BaseException:
                connection._tx_depth -= 1
                raise
            self._savepoint = savepoint
        else:
            # wait for any transaction owned by another task to finish
            while connection._tx_owner is not None:
                await connection._tx_idle_event.wait()

            # No await between the check above and claiming ownership, so
            # two tasks cannot both acquire the transaction.
            connection._tx_owner = self
            connection._tx_idle_event.clear()
            connection._tx_depth = 1
            self._token = connection._tx_context.set(True)
            try:
                await connection._execute_impl(
                    connection._conn.execute, connection._begin_statement()
                )
            except BaseException:
                connection._tx_context.reset(self._token)
                self._token = None
                connection._tx_owner = None
                connection._tx_depth = 0
                connection._tx_idle_event.set()
                raise
            self._savepoint = None

        self._active = True
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        connection = self._connection
        self._active = False

        if self._savepoint is not None:
            savepoint = self._savepoint
            self._savepoint = None
            try:
                if exc_type is None:
                    await connection._execute_shielded(
                        connection._conn.execute, f"RELEASE SAVEPOINT {savepoint}"
                    )
                else:
                    await connection._execute_shielded(
                        connection._conn.execute,
                        f"ROLLBACK TO SAVEPOINT {savepoint}",
                    )
                    await connection._execute_shielded(
                        connection._conn.execute, f"RELEASE SAVEPOINT {savepoint}"
                    )
            finally:
                connection._tx_depth -= 1
        else:
            try:
                if exc_type is None:
                    await connection._execute_shielded(connection._conn.commit)
                else:
                    await connection._execute_shielded(connection._conn.rollback)
            finally:
                if self._token is not None:
                    connection._tx_context.reset(self._token)
                    self._token = None
                connection._tx_owner = None
                connection._tx_depth = 0
                connection._tx_idle_event.set()

        return None


def connect(
    database: Union[str, Path],
    *,
    iter_chunk_size=64,
    loop: Optional[asyncio.AbstractEventLoop] = None,
    **kwargs: Any,
) -> Connection:
    """Create and return a connection proxy to the sqlite database."""

    if loop is not None:
        warn(
            "aiosqlite.connect() no longer uses the `loop` parameter",
            DeprecationWarning,
        )

    def connector() -> sqlite3.Connection:
        if isinstance(database, str):
            loc = database
        elif isinstance(database, bytes):
            loc = database.decode("utf-8")
        else:
            loc = str(database)

        return sqlite3.connect(loc, **kwargs)

    return Connection(connector, iter_chunk_size)
