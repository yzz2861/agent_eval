from __future__ import annotations

from collections import defaultdict
from collections.abc import (
    AsyncGenerator,
    Callable,
    Iterable,
    Mapping,
    Sequence,
)
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta, timezone
from functools import partial
from inspect import iscoroutine
from logging import Logger
from typing import Any, cast
from uuid import UUID

import anyio
import attrs
import tenacity
from anyio import CapacityLimiter, CancelScope, create_task_group, to_thread
from anyio.abc import TaskGroup
from attr.validators import instance_of, optional
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    Integer,
    Interval,
    LargeBinary,
    MetaData,
    SmallInteger,
    Table,
    TypeDecorator,
    Unicode,
    Uuid,
    and_,
    bindparam,
    create_engine,
    false,
    func,
    or_,
    select,
)
from sqlalchemy.engine import URL, Dialect, Result
from sqlalchemy.exc import (
    CompileError,
    IntegrityError,
    InterfaceError,
    InvalidRequestError,
    ProgrammingError,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.future import Connection, Engine
from sqlalchemy.schema import CreateSchema
from sqlalchemy.sql import Executable
from sqlalchemy.sql.ddl import DropTable
from sqlalchemy.sql.elements import BindParameter, literal
from sqlalchemy.sql.type_api import TypeEngine

from .. import _events
from ..abc import EventBroker, Subscription
from .._enums import CoalescePolicy, ConflictPolicy, JobOutcome
from .._events import (
    DataStoreEvent,
    Event,
    JobAcquired,
    JobAdded,
    JobDeserializationFailed,
    JobReleased,
    ScheduleAdded,
    ScheduleDeserializationFailed,
    ScheduleRemoved,
    ScheduleUpdated,
    TaskAdded,
    TaskRemoved,
    TaskUpdated,
)
from .._exceptions import (
    ConflictingIdError,
    DeserializationError,
    PersistentEventHistoryExpiredError,
    SerializationError,
    TaskLookupError,
)
from .._structures import Job, JobResult, Schedule, ScheduleResult, Task
from .._utils import create_repr, current_async_library
from .base import BaseExternalDataStore


class EmulatedTimestampTZ(TypeDecorator[datetime]):
    impl = Unicode(32)
    cache_ok = True

    def process_bind_param(
        self, value: datetime | None, dialect: Dialect
    ) -> str | None:
        return value.isoformat() if value is not None else None

    def process_result_value(
        self, value: str | None, dialect: Dialect
    ) -> datetime | None:
        return datetime.fromisoformat(value) if value is not None else None


class EmulatedInterval(TypeDecorator[timedelta]):
    impl = BigInteger()
    cache_ok = True

    def process_bind_param(
        self, value: timedelta | None, dialect: Dialect
    ) -> float | None:
        return value.total_seconds() * 1000000 if value is not None else None

    def process_result_value(
        self, value: int | None, dialect: Dialect
    ) -> timedelta | None:
        return timedelta(seconds=value / 1000000) if value is not None else None


def marshal_timestamp(timestamp: datetime | None, key: str) -> Mapping[str, Any]:
    if timestamp is None:
        return {key: None, key + "_utcoffset": None}

    return {
        key: int(timestamp.timestamp() * 1000_000),
        key + "_utcoffset": cast(timedelta, timestamp.utcoffset()).total_seconds()
        // 60,
    }


@attrs.define(eq=False, frozen=True)
class _JobDiscard:
    job_id: UUID
    outcome: JobOutcome
    task_id: str
    schedule_id: str | None
    scheduled_fire_time: datetime | None
    result_expires_at: datetime
    exception: Exception | None = None


@attrs.define(eq=False, frozen=True)
class PersistentEvent:
    """
    An event read from persistent storage.

    :ivar id: the stable monotonic event ID used as the subscription cursor
    :ivar event: the original scheduler or data store event
    """

    id: int
    event: Event


@attrs.define(eq=False)
class SQLAlchemyPersistentEventSubscription(Subscription):
    _store: SQLAlchemyDataStore
    subscription_id: str
    event_types: set[type[Event]] | None
    callback: Callable[[PersistentEvent], Any]
    is_async: bool
    _cursor: int
    _broker_subscription: Subscription | None = attrs.field(
        init=False, default=None
    )
    _stopped: bool = attrs.field(init=False, default=False)
    _error: BaseException | None = attrs.field(init=False, default=None)
    _cancel_scope: CancelScope = attrs.field(init=False, factory=CancelScope)
    _wakeup: anyio.Event = attrs.field(init=False, factory=anyio.Event)
    _finished: anyio.Event = attrs.field(init=False, factory=anyio.Event)

    async def start(self) -> None:
        self._broker_subscription = self._store._event_broker.subscribe(
            self._notify,
            self.event_types,
        )
        self._store._persistent_event_task_group.start_soon(self._run)

    async def __aenter__(self) -> SQLAlchemyPersistentEventSubscription:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.aclose()

    def unsubscribe(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self._cancel_scope.cancel()
        self._wakeup.set()
        if self._broker_subscription is not None:
            self._broker_subscription.unsubscribe()

    async def aclose(self) -> None:
        self.unsubscribe()
        await self._finished.wait()

    async def wait_until_stopped(self) -> None:
        await self._finished.wait()
        if self._error is not None:
            raise self._error

    def _notify(self, event: Event) -> None:
        self._wakeup.set()

    async def _run(self) -> None:
        with self._cancel_scope:
            try:
                while not self._stopped:
                    persistent_events = await self._store._get_persistent_events(
                        self.subscription_id,
                        self._cursor,
                        self._event_type_names(),
                        limit=100,
                    )
                    if not persistent_events:
                        with anyio.move_on_after(0.1):
                            await self._wakeup.wait()
                        self._wakeup = anyio.Event()
                        continue

                    for persistent_event in persistent_events:
                        try:
                            await self._deliver(persistent_event)
                        except Exception:
                            if self._stopped:
                                return

                            self._store._logger.exception(
                                "Error delivering persistent event %d to "
                                "subscription %r",
                                persistent_event.id,
                                self.subscription_id,
                            )
                            with anyio.move_on_after(1):
                                await self._wakeup.wait()
                            self._wakeup = anyio.Event()
                            break
                        else:
                            await self._store._acknowledge_persistent_event(
                                self.subscription_id, persistent_event.id
                            )
                            self._cursor = persistent_event.id
            except Exception as exc:
                self._error = exc
                self.unsubscribe()
            finally:
                self._store._persistent_event_subscribers.pop(
                    self.subscription_id, None
                )
                self._finished.set()

    def _event_type_names(self) -> set[str] | None:
        if self.event_types is None:
            return None

        return {event_type.__name__ for event_type in self.event_types}

    async def _deliver(self, persistent_event: PersistentEvent) -> None:
        if self.is_async:
            retval = self.callback(persistent_event)
            if iscoroutine(retval):
                await retval
        else:
            await to_thread.run_sync(
                self.callback,
                persistent_event,
                limiter=self._store._thread_limiter,
            )


@attrs.define(eq=False, repr=False)
class SQLAlchemyDataStore(BaseExternalDataStore):
    """
    Uses a relational database to store data.

    When started, this data store creates the appropriate tables on the given database
    if they're not already present.

    Operations are retried (in accordance to ``retry_settings``) when an operation
    raises either :exc:`OSError` or :exc:`sqlalchemy.exc.InterfaceError`.

    This store has been tested to work with:

     * PostgreSQL (asyncpg and psycopg drivers)
     * MySQL (asyncmy driver)
     * aiosqlite (not recommended right now, as issues like
       `#1032 <https://github.com/agronholm/apscheduler/issues/1032>`_ exist)

    :param engine_or_url: a SQLAlchemy URL or engine (preferably asynchronous, but can
        be synchronous)
    :param schema: a database schema name to use, if not the default
    :param persistent_events: persist state-change events in the same transactions as
        the corresponding scheduler state (SQLite only)
    :param persistent_event_retention: retain persisted events for at most this
        duration; ``None`` retains them indefinitely

    .. note:: The data store will not manage the life cycle of any engine instance
        passed to it, so you need to close the engine afterwards when you're done with
        it.

    .. warning:: Do not use SQLite when sharing the data store with multiple schedulers,
        as there is an unresolved issue with that
        (`#959 <https://github.com/agronholm/apscheduler/issues/959>`_).
    """

    engine_or_url: str | URL | Engine | AsyncEngine = attrs.field(
        validator=instance_of((str, URL, Engine, AsyncEngine))
    )
    schema: str | None = attrs.field(kw_only=True, default=None)
    persistent_events: bool = attrs.field(kw_only=True, default=False)
    persistent_event_retention: timedelta | None = attrs.field(
        kw_only=True, default=None, validator=optional(instance_of(timedelta))
    )

    _engine: Engine | AsyncEngine = attrs.field(init=False)
    _close_on_exit: bool = attrs.field(init=False, default=False)
    _supports_update_returning: bool = attrs.field(init=False, default=False)
    _supports_tzaware_timestamps: bool = attrs.field(init=False, default=False)
    _supports_native_interval: bool = attrs.field(init=False, default=False)
    _metadata: MetaData = attrs.field(init=False)
    _t_metadata: Table = attrs.field(init=False)
    _t_tasks: Table = attrs.field(init=False)
    _t_schedules: Table = attrs.field(init=False)
    _t_jobs: Table = attrs.field(init=False)
    _t_job_results: Table = attrs.field(init=False)
    _t_persistent_events: Table | None = attrs.field(init=False, default=None)
    _t_persistent_event_subscriptions: Table | None = attrs.field(
        init=False, default=None
    )
    _persistent_event_task_group: TaskGroup = attrs.field(init=False)
    _thread_limiter: CapacityLimiter = attrs.field(init=False)
    _persistent_event_subscribers: dict[
        str, SQLAlchemyPersistentEventSubscription
    ] = attrs.field(init=False, factory=dict)

    def __attrs_post_init__(self) -> None:
        if self.persistent_event_retention is not None and not self.persistent_events:
            raise ValueError(
                "persistent_event_retention requires persistent_events to be enabled"
            )
        if (
            self.persistent_event_retention is not None
            and self.persistent_event_retention < timedelta()
        ):
            raise ValueError("persistent_event_retention must be non-negative")

        if isinstance(self.engine_or_url, (str, URL)):
            try:
                self._engine = create_async_engine(self.engine_or_url)
            except InvalidRequestError:
                self._engine = create_engine(self.engine_or_url)

            self._close_on_exit = True
        else:
            self._engine = self.engine_or_url

        if self.persistent_events and self._engine.dialect.name != "sqlite":
            raise NotImplementedError(
                "Persistent events are currently only supported with SQLite"
            )

        # Generate the table definitions
        prefix = f"{self.schema}." if self.schema else ""
        self._supports_tzaware_timestamps = self._engine.dialect.name in (
            "postgresql",
            "oracle",
        )
        self._supports_native_interval = self._engine.dialect.name == "postgresql"
        self._metadata = self.get_table_definitions()
        self._t_metadata = self._metadata.tables[prefix + "metadata"]
        self._t_tasks = self._metadata.tables[prefix + "tasks"]
        self._t_schedules = self._metadata.tables[prefix + "schedules"]
        self._t_jobs = self._metadata.tables[prefix + "jobs"]
        self._t_job_results = self._metadata.tables[prefix + "job_results"]
        if self.persistent_events:
            self._t_persistent_events = self._metadata.tables[
                prefix + "persistent_events"
            ]
            self._t_persistent_event_subscriptions = self._metadata.tables[
                prefix + "persistent_event_subscriptions"
            ]

    def __repr__(self) -> str:
        return create_repr(self, url=repr(self._engine.url), schema=self.schema)

    def _retry(self) -> tenacity.AsyncRetrying:
        def after_attempt(retry_state: tenacity.RetryCallState) -> None:
            self._logger.warning(
                "Temporary data store error (attempt %d): %s",
                retry_state.attempt_number,
                retry_state.outcome.exception(),
            )

        # OSError is raised by asyncpg if it can't connect
        return tenacity.AsyncRetrying(
            stop=self.retry_settings.stop,
            wait=self.retry_settings.wait,
            retry=tenacity.retry_if_exception_type((InterfaceError, OSError)),
            after=after_attempt,
            sleep=anyio.sleep,
            reraise=True,
        )

    @asynccontextmanager
    async def _begin_transaction(
        self,
    ) -> AsyncGenerator[Connection | AsyncConnection, None]:
        # A shielded cancel scope is injected to the exit stack to allow finalization
        # to occur even when the surrounding cancel scope is cancelled
        async with AsyncExitStack() as exit_stack:
            if isinstance(self._engine, AsyncEngine):
                async_cm = self._engine.begin()
                conn = await async_cm.__aenter__()
                exit_stack.enter_context(CancelScope(shield=True))
                exit_stack.push_async_exit(async_cm.__aexit__)
            else:
                cm = self._engine.begin()
                conn = await to_thread.run_sync(cm.__enter__)
                exit_stack.enter_context(CancelScope(shield=True))
                exit_stack.push_async_exit(partial(to_thread.run_sync, cm.__exit__))

            yield conn

    async def _create_metadata(self, conn: Connection | AsyncConnection) -> None:
        if isinstance(conn, AsyncConnection):
            await conn.run_sync(self._metadata.create_all)
        else:
            await to_thread.run_sync(self._metadata.create_all, conn)

    async def _execute(
        self,
        conn: Connection | AsyncConnection,
        statement: Executable,
        parameters: Sequence | Mapping | None = None,
    ):
        if isinstance(conn, AsyncConnection):
            return await conn.execute(statement, parameters)
        else:
            return await to_thread.run_sync(conn.execute, statement, parameters)

    async def _record_persistent_events(
        self, conn: Connection | AsyncConnection, events: Iterable[Event]
    ) -> None:
        if not self.persistent_events or self._t_persistent_events is None:
            return

        parameters = [
            {
                "event_type": type(event).__name__,
                "payload": self.serializer.serialize(event.marshal()),
                "timestamp": event.timestamp,
            }
            for event in events
        ]
        if parameters:
            await self._execute(conn, self._t_persistent_events.insert(), parameters)

    async def _publish_events(self, events: Iterable[Event]) -> None:
        for event in events:
            await self._event_broker.publish(event)

    async def _get_persistent_events(
        self,
        subscription_id: str,
        cursor: int,
        event_type_names: set[str] | None,
        *,
        limit: int,
    ) -> list[PersistentEvent]:
        if not self.persistent_events or self._t_persistent_events is None:
            raise RuntimeError("Persistent events are not enabled")

        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    if cursor:
                        cursor_event_query = select(
                            self._t_persistent_events.c.id
                        ).where(self._t_persistent_events.c.id == cursor)
                        cursor_event = (
                            await self._execute(conn, cursor_event_query)
                        ).first()
                        if cursor_event is None:
                            oldest_query = select(
                                func.min(self._t_persistent_events.c.id)
                            )
                            oldest_event_id = (
                                await self._execute(conn, oldest_query)
                            ).scalar()
                            raise PersistentEventHistoryExpiredError(
                                subscription_id,
                                cursor,
                                oldest_event_id or cursor + 1,
                            )

                    query = (
                        select(
                            self._t_persistent_events.c.id,
                            self._t_persistent_events.c.event_type,
                            self._t_persistent_events.c.payload,
                        )
                        .where(self._t_persistent_events.c.id > cursor)
                        .order_by(self._t_persistent_events.c.id)
                        .limit(limit)
                    )
                    if event_type_names is not None:
                        query = query.where(
                            self._t_persistent_events.c.event_type.in_(
                                event_type_names
                            )
                        )

                    result = await self._execute(conn, query)
                    persistent_events: list[PersistentEvent] = []
                    for event_id, event_type_name, payload in result:
                        event_class = getattr(_events, event_type_name)
                        payload_data = self.serializer.deserialize(payload)
                        event = event_class.unmarshal(payload_data)
                        persistent_events.append(PersistentEvent(event_id, event))

        return persistent_events

    async def _acknowledge_persistent_event(
        self, subscription_id: str, event_id: int
    ) -> None:
        if (
            not self.persistent_events
            or self._t_persistent_event_subscriptions is None
        ):
            raise RuntimeError("Persistent events are not enabled")

        update = (
            self._t_persistent_event_subscriptions.update()
            .where(
                (self._t_persistent_event_subscriptions.c.id == subscription_id)
                & (self._t_persistent_event_subscriptions.c.last_event_id < event_id)
            )
            .values(
                last_event_id=event_id,
                updated_at=datetime.now(timezone.utc),
            )
        )
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    await self._execute(conn, update)

    async def subscribe_persistent_events(
        self,
        callback: Callable[[PersistentEvent], Any],
        event_types: Iterable[type[Event]] | None = None,
        *,
        subscription_id: str,
        start_from: int | None = None,
        is_async: bool = True,
    ) -> SQLAlchemyPersistentEventSubscription:
        """
        Subscribe to persistent events for the given subscriber ID.

        Callbacks receive events after storage commit and are acknowledged only after
        they return successfully. Delivery is therefore at-least-once; callbacks must
        be idempotent and use :attr:`PersistentEvent.id` to deduplicate events.

        A new subscriber starts after the latest retained event by default. Pass an
        explicit ``start_from`` to replay retained history. Reconnecting subscribers
        resume from the cursor stored for ``subscription_id``.

        :raises PersistentEventHistoryExpiredError: the stored cursor is older than
            the retained history; the caller must resynchronize external state and
            then call :meth:`resynchronize_persistent_subscription`
        """
        if not self.persistent_events or self._t_persistent_event_subscriptions is None:
            raise RuntimeError("Persistent events are not enabled")
        if subscription_id in self._persistent_event_subscribers:
            raise ValueError(
                f"Persistent event subscription {subscription_id!r} is already active"
            )

        types = set(event_types) if event_types is not None else None
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    query = select(
                        self._t_persistent_event_subscriptions.c.last_event_id
                    ).where(
                        self._t_persistent_event_subscriptions.c.id == subscription_id
                    )
                    row = (await self._execute(conn, query)).one_or_none()
                    if row is None:
                        if start_from is None:
                            max_query = select(
                                func.max(self._t_persistent_events.c.id)
                            )
                            max_event_id = (
                                await self._execute(conn, max_query)
                            ).scalar()
                            cursor = max_event_id or 0
                        else:
                            if start_from < 0:
                                raise ValueError("start_from must be non-negative")
                            cursor = start_from

                        insert = self._t_persistent_event_subscriptions.insert().values(
                            id=subscription_id,
                            last_event_id=cursor,
                            updated_at=datetime.now(timezone.utc),
                        )
                        await self._execute(conn, insert)
                    else:
                        cursor = row[0]

                    if cursor:
                        cursor_event_query = select(
                            self._t_persistent_events.c.id
                        ).where(self._t_persistent_events.c.id == cursor)
                        cursor_event = (
                            await self._execute(conn, cursor_event_query)
                        ).first()
                        if cursor_event is None:
                            oldest_query = select(
                                func.min(self._t_persistent_events.c.id)
                            )
                            oldest_event_id = (
                                await self._execute(conn, oldest_query)
                            ).scalar()
                            raise PersistentEventHistoryExpiredError(
                                subscription_id,
                                cursor,
                                oldest_event_id or cursor + 1,
                            )

        subscription = SQLAlchemyPersistentEventSubscription(
            self, subscription_id, types, callback, is_async, cursor
        )
        self._persistent_event_subscribers[subscription_id] = subscription
        await subscription.start()
        return subscription

    async def resynchronize_persistent_subscription(
        self,
        subscription_id: str,
        *,
        start_from: int = 0,
    ) -> None:
        """
        Reset a subscription after the caller has resynchronized its external state.

        ``start_from`` is the ID of the already-handled event. Use ``0`` to replay all
        retained history.

        :raises PersistentEventHistoryExpiredError: ``start_from`` is not available in
            the retained event history
        """
        if not self.persistent_events or self._t_persistent_event_subscriptions is None:
            raise RuntimeError("Persistent events are not enabled")
        if subscription_id in self._persistent_event_subscribers:
            raise ValueError(
                f"Persistent event subscription {subscription_id!r} is still active"
            )
        if start_from < 0:
            raise ValueError("start_from must be non-negative")

        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    if start_from:
                        cursor_exists_query = select(
                            self._t_persistent_events.c.id
                        ).where(self._t_persistent_events.c.id == start_from)
                        if (
                            await self._execute(conn, cursor_exists_query)
                        ).first() is None:
                            oldest_query = select(
                                func.min(self._t_persistent_events.c.id)
                            )
                            oldest_event_id = (
                                await self._execute(conn, oldest_query)
                            ).scalar()
                            raise PersistentEventHistoryExpiredError(
                                subscription_id,
                                start_from,
                                oldest_event_id or start_from + 1,
                            )

                    update = (
                        self._t_persistent_event_subscriptions.update()
                        .where(
                            self._t_persistent_event_subscriptions.c.id
                            == subscription_id
                        )
                        .values(
                            last_event_id=start_from,
                            updated_at=datetime.now(timezone.utc),
                        )
                    )
                    result = await self._execute(conn, update)
                    if result.rowcount == 0:
                        insert = (
                            self._t_persistent_event_subscriptions.insert().values(
                                id=subscription_id,
                                last_event_id=start_from,
                                updated_at=datetime.now(timezone.utc),
                            )
                        )
                        await self._execute(conn, insert)

    @property
    def _temporary_failure_exceptions(self) -> tuple[type[Exception], ...]:
        # SQlite does not use the network, so it doesn't have "temporary" failures
        if self._engine.dialect.name == "sqlite":
            return ()

        return InterfaceError, OSError

    def _convert_incoming_fire_times(self, data: dict[str, Any]) -> dict[str, Any]:
        for field in ("last_fire_time", "next_fire_time"):
            if not self._supports_tzaware_timestamps:
                utcoffset_minutes = data.pop(f"{field}_utcoffset", None)
                if utcoffset_minutes is not None:
                    tz = timezone(timedelta(minutes=utcoffset_minutes))
                    timestamp = data[field] / 1000_000
                    data[field] = datetime.fromtimestamp(timestamp, tz=tz)

        return data

    def _convert_outgoing_fire_times(self, data: dict[str, Any]) -> dict[str, Any]:
        for field in ("last_fire_time", "next_fire_time"):
            if not self._supports_tzaware_timestamps:
                field_value = data[field]
                if field_value is not None:
                    data[field] = int(field_value.timestamp() * 1000_000)
                    data[f"{field}_utcoffset"] = (
                        field_value.utcoffset().total_seconds() // 60
                    )
                else:
                    data[f"{field}_utcoffset"] = None

        return data

    def get_table_definitions(self) -> MetaData:
        if self._supports_tzaware_timestamps:
            timestamp_type: TypeEngine[datetime] = DateTime(timezone=True)
            last_fire_time_tzoffset_columns: tuple[Column, ...] = (
                Column("last_fire_time", timestamp_type),
            )
            next_fire_time_tzoffset_columns: tuple[Column, ...] = (
                Column("next_fire_time", timestamp_type, index=True),
            )
        else:
            timestamp_type = EmulatedTimestampTZ()
            last_fire_time_tzoffset_columns = (
                Column("last_fire_time", BigInteger),
                Column("last_fire_time_utcoffset", SmallInteger),
            )
            next_fire_time_tzoffset_columns = (
                Column("next_fire_time", BigInteger, index=True),
                Column("next_fire_time_utcoffset", SmallInteger),
            )

        if self._supports_native_interval:
            interval_type: TypeDecorator[timedelta] = Interval(second_precision=6)
        else:
            interval_type = EmulatedInterval()

        if self._engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import JSONB

            json_type = JSONB
        else:
            json_type = JSON

        event_id_type = BigInteger().with_variant(Integer(), "sqlite")
        table_kwargs: dict[str, Any] = {}
        if self._engine.dialect.name == "sqlite":
            table_kwargs["sqlite_autoincrement"] = True

        metadata = MetaData(schema=self.schema)
        Table("metadata", metadata, Column("schema_version", Integer, nullable=False))
        Table(
            "tasks",
            metadata,
            Column("id", Unicode(500), primary_key=True),
            Column("func", Unicode(500)),
            Column("job_executor", Unicode(500), nullable=False),
            Column("max_running_jobs", Integer),
            Column("misfire_grace_time", interval_type),
            Column("metadata", json_type, nullable=False),
            Column("running_jobs", Integer, nullable=False, server_default=literal(0)),
        )
        Table(
            "schedules",
            metadata,
            Column("id", Unicode(500), primary_key=True),
            Column("task_id", Unicode(500), nullable=False, index=True),
            Column("trigger", LargeBinary),
            Column("args", LargeBinary),
            Column("kwargs", LargeBinary),
            Column("paused", Boolean, nullable=False, server_default=literal(False)),
            Column("coalesce", Enum(CoalescePolicy, metadata=metadata), nullable=False),
            Column("misfire_grace_time", interval_type),
            Column("max_jitter", interval_type),
            Column("job_executor", Unicode(500), nullable=False),
            Column("job_result_expiration_time", interval_type),
            Column("metadata", json_type, nullable=False),
            *last_fire_time_tzoffset_columns,
            *next_fire_time_tzoffset_columns,
            Column("acquired_by", Unicode(500), index=True),
            Column("acquired_until", timestamp_type),
        )
        Table(
            "jobs",
            metadata,
            Column("id", Uuid, primary_key=True),
            Column("task_id", Unicode(500), nullable=False, index=True),
            Column("args", LargeBinary, nullable=False),
            Column("kwargs", LargeBinary, nullable=False),
            Column("schedule_id", Unicode(500), index=True),
            Column("scheduled_fire_time", timestamp_type),
            Column("executor", Unicode(500), nullable=False),
            Column("jitter", interval_type),
            Column("start_deadline", timestamp_type),
            Column("result_expiration_time", interval_type),
            Column("metadata", json_type, nullable=False),
            Column("created_at", timestamp_type, nullable=False, index=True),
            Column("acquired_by", Unicode(500), index=True),
            Column("acquired_until", timestamp_type),
        )
        Table(
            "job_results",
            metadata,
            Column("job_id", Uuid, primary_key=True),
            Column("outcome", Enum(JobOutcome, metadata=metadata), nullable=False),
            Column("started_at", timestamp_type, index=True),
            Column("finished_at", timestamp_type, nullable=False),
            Column("expires_at", timestamp_type, nullable=False, index=True),
            Column("exception", LargeBinary),
            Column("return_value", LargeBinary),
        )
        if self.persistent_events:
            Table(
                "persistent_events",
                metadata,
                Column(
                    "id",
                    event_id_type,
                    primary_key=True,
                    autoincrement=True,
                ),
                Column("event_type", Unicode(100), nullable=False, index=True),
                Column("payload", LargeBinary, nullable=False),
                Column("timestamp", timestamp_type, nullable=False, index=True),
                **table_kwargs,
            )
            Table(
                "persistent_event_subscriptions",
                metadata,
                Column("id", Unicode(500), primary_key=True),
                Column("last_event_id", BigInteger),
                Column("updated_at", timestamp_type, nullable=False),
            )
        return metadata

    async def start(
        self, exit_stack: AsyncExitStack, event_broker: EventBroker, logger: Logger
    ) -> None:
        if (asynclib := current_async_library()) != "asyncio":
            raise RuntimeError(
                f"This data store requires asyncio; currently running: {asynclib}"
            )

        if self._close_on_exit:
            if isinstance(self._engine, AsyncEngine):
                exit_stack.push_async_callback(self._engine.dispose)
            else:
                exit_stack.callback(self._engine.dispose)

        self._thread_limiter = CapacityLimiter(1)
        task_group_cm = create_task_group()
        self._persistent_event_task_group = await task_group_cm.__aenter__()

        async def close_task_group() -> None:
            for subscription in tuple(self._persistent_event_subscribers.values()):
                await subscription.aclose()
            await task_group_cm.__aexit__(None, None, None)

        exit_stack.push_async_callback(close_task_group)
        await super().start(exit_stack, event_broker, logger)

        # Verify that the schema is in place
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    # Create the schema first if it doesn't exist yet
                    if self.schema:
                        await self._execute(
                            conn, CreateSchema(name=self.schema, if_not_exists=True)
                        )

                    if self.start_from_scratch:
                        for table in self._metadata.sorted_tables:
                            await self._execute(conn, DropTable(table, if_exists=True))

                    await self._create_metadata(conn)
                    query = select(self._t_metadata.c.schema_version)
                    result = await self._execute(conn, query)
                    version = result.scalar()
                    if version is None:
                        await self._execute(
                            conn, self._t_metadata.insert(), {"schema_version": 1}
                        )
                    elif version > 1:
                        raise RuntimeError(
                            f"Unexpected schema version ({version}); "
                            f"only version 1 is supported by this version of "
                            f"APScheduler"
                        )

        # Find out if the dialect supports UPDATE...RETURNING
        async for attempt in self._retry():
            with attempt:
                update = (
                    self._t_metadata.update()
                    .values(schema_version=self._t_metadata.c.schema_version)
                    .returning(self._t_metadata.c.schema_version)
                )
                async with self._begin_transaction() as conn:
                    try:
                        await self._execute(conn, update)
                    except (CompileError, ProgrammingError):
                        pass  # the support flag is False by default
                    else:
                        self._supports_update_returning = True

    async def _deserialize_schedules(self, result: Result) -> list[Schedule]:
        schedules: list[Schedule] = []
        for row in result:
            try:
                schedules.append(
                    Schedule.unmarshal(
                        self.serializer,
                        self._convert_incoming_fire_times(row._asdict()),
                    )
                )
            except SerializationError as exc:
                await self._event_broker.publish(
                    ScheduleDeserializationFailed(schedule_id=row.id, exception=exc)
                )

        return schedules

    async def _deserialize_jobs(self, result: Result) -> list[Job]:
        jobs: list[Job] = []
        for row in result:
            try:
                jobs.append(Job.unmarshal(self.serializer, row._asdict()))
            except SerializationError as exc:
                await self._event_broker.publish(
                    JobDeserializationFailed(job_id=row.id, exception=exc)
                )

        return jobs

    async def add_task(self, task: Task) -> None:
        insert = self._t_tasks.insert().values(
            id=task.id,
            func=task.func,
            job_executor=task.job_executor,
            max_running_jobs=task.max_running_jobs,
            misfire_grace_time=task.misfire_grace_time,
            metadata=task.metadata,
        )
        try:
            async for attempt in self._retry():
                with attempt:
                    async with self._begin_transaction() as conn:
                        await self._execute(conn, insert)
                        await self._record_persistent_events(
                            conn, [TaskAdded(task_id=task.id)]
                        )
        except IntegrityError:
            update = (
                self._t_tasks.update()
                .values(
                    func=task.func,
                    job_executor=task.job_executor,
                    max_running_jobs=task.max_running_jobs,
                    misfire_grace_time=task.misfire_grace_time,
                    metadata=task.metadata,
                )
                .where(self._t_tasks.c.id == task.id)
            )
            async for attempt in self._retry():
                with attempt:
                    async with self._begin_transaction() as conn:
                        await self._execute(conn, update)
                        await self._record_persistent_events(
                            conn, [TaskUpdated(task_id=task.id)]
                        )

            await self._event_broker.publish(TaskUpdated(task_id=task.id))
        else:
            await self._event_broker.publish(TaskAdded(task_id=task.id))

    async def remove_task(self, task_id: str) -> None:
        delete = self._t_tasks.delete().where(self._t_tasks.c.id == task_id)
        removed = False
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    result = await self._execute(conn, delete)
                    if result.rowcount == 0:
                        raise TaskLookupError(task_id)
                    await self._record_persistent_events(
                        conn, [TaskRemoved(task_id=task_id)]
                    )
                    removed = True

        if removed:
            await self._event_broker.publish(TaskRemoved(task_id=task_id))

    async def get_task(self, task_id: str) -> Task:
        query = self._t_tasks.select().where(self._t_tasks.c.id == task_id)
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    result = await self._execute(conn, query)
                    row = result.first()

        if row:
            return Task.unmarshal(self.serializer, row._asdict())
        else:
            raise TaskLookupError(task_id)

    async def get_tasks(self) -> list[Task]:
        query = self._t_tasks.select().order_by(self._t_tasks.c.id)
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    result = await self._execute(conn, query)
                    tasks = [
                        Task.unmarshal(self.serializer, row._asdict()) for row in result
                    ]

        return tasks

    async def add_schedule(
        self, schedule: Schedule, conflict_policy: ConflictPolicy
    ) -> None:
        event: DataStoreEvent
        values = self._convert_outgoing_fire_times(schedule.marshal(self.serializer))
        insert = self._t_schedules.insert().values(**values)
        try:
            async for attempt in self._retry():
                with attempt:
                    async with self._begin_transaction() as conn:
                        await self._execute(conn, insert)
                        await self._record_persistent_events(
                            conn,
                            [
                                ScheduleAdded(
                                    schedule_id=schedule.id,
                                    task_id=schedule.task_id,
                                    next_fire_time=schedule.next_fire_time,
                                )
                            ],
                        )
        except IntegrityError:
            if conflict_policy is ConflictPolicy.exception:
                raise ConflictingIdError(schedule.id) from None
            elif conflict_policy is ConflictPolicy.replace:
                del values["id"]
                update = (
                    self._t_schedules.update()
                    .where(self._t_schedules.c.id == schedule.id)
                    .values(**values)
                )
                async for attempt in self._retry():
                    with attempt:
                        async with self._begin_transaction() as conn:
                            await self._execute(conn, update)
                            await self._record_persistent_events(
                                conn,
                                [
                                    ScheduleUpdated(
                                        schedule_id=schedule.id,
                                        task_id=schedule.task_id,
                                        next_fire_time=schedule.next_fire_time,
                                    )
                                ],
                            )

                event = ScheduleUpdated(
                    schedule_id=schedule.id,
                    task_id=schedule.task_id,
                    next_fire_time=schedule.next_fire_time,
                )
                await self._event_broker.publish(event)
        else:
            event = ScheduleAdded(
                schedule_id=schedule.id,
                task_id=schedule.task_id,
                next_fire_time=schedule.next_fire_time,
            )
            await self._event_broker.publish(event)

    async def remove_schedules(self, ids: Iterable[str]) -> None:
        removed_ids: list[tuple[str, str]] = []
        async for attempt in self._retry():
            removed_ids = []
            with attempt:
                async with self._begin_transaction() as conn:
                    if self._supports_update_returning:
                        delete_returning = (
                            self._t_schedules.delete()
                            .where(self._t_schedules.c.id.in_(ids))
                            .returning(
                                self._t_schedules.c.id, self._t_schedules.c.task_id
                            )
                        )
                        removed_ids = [
                            (row[0], row[1])
                            for row in await self._execute(conn, delete_returning)
                        ]
                    else:
                        query = select(
                            self._t_schedules.c.id, self._t_schedules.c.task_id
                        ).where(self._t_schedules.c.id.in_(ids))
                        ids_to_remove: list[str] = []
                        for schedule_id, task_id in await self._execute(conn, query):
                            ids_to_remove.append(schedule_id)
                            removed_ids.append((schedule_id, task_id))

                        delete = self._t_schedules.delete().where(
                            self._t_schedules.c.id.in_(ids_to_remove)
                        )
                        await self._execute(conn, delete)

                    await self._record_persistent_events(
                        conn,
                        [
                            ScheduleRemoved(
                                schedule_id=schedule_id,
                                task_id=task_id,
                                finished=False,
                            )
                            for schedule_id, task_id in removed_ids
                        ],
                    )

        await self._publish_events(
            [
                ScheduleRemoved(
                    schedule_id=schedule_id, task_id=task_id, finished=False
                )
                for schedule_id, task_id in removed_ids
            ]
        )

    async def get_schedules(self, ids: set[str] | None = None) -> list[Schedule]:
        query = self._t_schedules.select().order_by(self._t_schedules.c.id)
        if ids:
            query = query.where(self._t_schedules.c.id.in_(ids))

        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    result = await self._execute(conn, query)

        return await self._deserialize_schedules(result)

    async def acquire_schedules(
        self, scheduler_id: str, lease_duration: timedelta, limit: int
    ) -> list[Schedule]:
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    now = datetime.now(timezone.utc)
                    acquired_until = now + lease_duration
                    if self._supports_tzaware_timestamps:
                        comparison = self._t_schedules.c.next_fire_time <= now
                    else:
                        comparison = self._t_schedules.c.next_fire_time <= int(
                            now.timestamp() * 1000_000
                        )

                    schedules_cte = (
                        select(self._t_schedules.c.id)
                        .where(
                            and_(
                                self._t_schedules.c.next_fire_time.isnot(None),
                                comparison,
                                self._t_schedules.c.paused == false(),
                                or_(
                                    self._t_schedules.c.acquired_by == scheduler_id,
                                    self._t_schedules.c.acquired_until.is_(None),
                                    self._t_schedules.c.acquired_until < now,
                                ),
                            )
                        )
                        .order_by(self._t_schedules.c.next_fire_time)
                        .limit(limit)
                        .with_for_update(skip_locked=True)
                        .cte()
                    )
                    subselect = select(schedules_cte.c.id)
                    update = (
                        self._t_schedules.update()
                        .where(self._t_schedules.c.id.in_(subselect))
                        .values(acquired_by=scheduler_id, acquired_until=acquired_until)
                    )
                    if self._supports_update_returning:
                        update = update.returning(*self._t_schedules.columns)
                        result = await self._execute(conn, update)
                    else:
                        await self._execute(conn, update)
                        query = self._t_schedules.select().where(
                            and_(self._t_schedules.c.acquired_by == scheduler_id)
                        )
                        result = await self._execute(conn, query)

                    schedules = await self._deserialize_schedules(result)

        return schedules

    async def release_schedules(
        self, scheduler_id: str, results: Sequence[ScheduleResult]
    ) -> None:
        task_ids = {result.schedule_id: result.task_id for result in results}
        next_fire_times = {
            result.schedule_id: result.next_fire_time for result in results
        }
        update_events: list[ScheduleUpdated] = []
        finished_schedule_ids: list[str] = []
        async for attempt in self._retry():
            update_events = []
            finished_schedule_ids = []
            with attempt:
                async with self._begin_transaction() as conn:
                    update_args: list[dict[str, Any]] = []
                    for result in results:
                        try:
                            serialized_trigger = self.serializer.serialize(
                                result.trigger
                            )
                        except SerializationError:
                            self._logger.exception(
                                "Error serializing trigger for schedule %r – "
                                "removing from data store",
                                result.schedule_id,
                            )
                            finished_schedule_ids.append(result.schedule_id)
                            continue

                        if self._supports_tzaware_timestamps:
                            update_args.append(
                                {
                                    "p_id": result.schedule_id,
                                    "p_trigger": serialized_trigger,
                                    "p_last_fire_time": result.last_fire_time,
                                    "p_next_fire_time": result.next_fire_time,
                                }
                            )
                        else:
                            update_args.append(
                                {
                                    "p_id": result.schedule_id,
                                    "p_trigger": serialized_trigger,
                                    **marshal_timestamp(
                                        result.last_fire_time, "p_last_fire_time"
                                    ),
                                    **marshal_timestamp(
                                        result.next_fire_time, "p_next_fire_time"
                                    ),
                                }
                            )

                    # Update schedules
                    if update_args:
                        extra_values: dict[str, BindParameter] = {}
                        p_id: BindParameter = bindparam("p_id")
                        p_trigger: BindParameter = bindparam("p_trigger")
                        p_last_fire_time: BindParameter = bindparam("p_last_fire_time")
                        p_next_fire_time: BindParameter = bindparam("p_next_fire_time")
                        if not self._supports_tzaware_timestamps:
                            extra_values["last_fire_time_utcoffset"] = bindparam(
                                "p_last_fire_time_utcoffset"
                            )
                            extra_values["next_fire_time_utcoffset"] = bindparam(
                                "p_next_fire_time_utcoffset"
                            )

                        update = (
                            self._t_schedules.update()
                            .where(
                                and_(
                                    self._t_schedules.c.id == p_id,
                                    self._t_schedules.c.acquired_by == scheduler_id,
                                )
                            )
                            .values(
                                trigger=p_trigger,
                                last_fire_time=p_last_fire_time,
                                next_fire_time=p_next_fire_time,
                                acquired_by=None,
                                acquired_until=None,
                                **extra_values,
                            )
                        )
                        # TODO: actually check which rows were updated?
                        await self._execute(conn, update, update_args)
                        updated_ids = list(next_fire_times)

                        for schedule_id in updated_ids:
                            event = ScheduleUpdated(
                                schedule_id=schedule_id,
                                task_id=task_ids[schedule_id],
                                next_fire_time=next_fire_times[schedule_id],
                            )
                            update_events.append(event)

                    # Remove schedules that failed to serialize
                    if finished_schedule_ids:
                        delete = self._t_schedules.delete().where(
                            self._t_schedules.c.id.in_(finished_schedule_ids)
                        )
                        await self._execute(conn, delete)

                    await self._record_persistent_events(
                        conn,
                        [
                            *update_events,
                            *(
                                ScheduleRemoved(
                                    schedule_id=schedule_id,
                                    task_id=task_ids[schedule_id],
                                    finished=True,
                                )
                                for schedule_id in finished_schedule_ids
                            ),
                        ],
                    )

        await self._publish_events(update_events)
        await self._publish_events(
            [
                ScheduleRemoved(
                    schedule_id=schedule_id,
                    task_id=task_ids[schedule_id],
                    finished=True,
                )
                for schedule_id in finished_schedule_ids
            ]
        )

    async def get_next_schedule_run_time(self) -> datetime | None:
        columns = [self._t_schedules.c.next_fire_time]
        if not self._supports_tzaware_timestamps:
            columns.append(self._t_schedules.c.next_fire_time_utcoffset)

        statenent = (
            select(*columns)
            .where(
                self._t_schedules.c.next_fire_time.isnot(None),
                self._t_schedules.c.paused == false(),
                self._t_schedules.c.acquired_by.is_(None),
            )
            .order_by(self._t_schedules.c.next_fire_time)
            .limit(1)
        )
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    result = await self._execute(conn, statenent)

        if not self._supports_tzaware_timestamps:
            if row := result.first():
                tz = timezone(timedelta(minutes=row[1]))
                return datetime.fromtimestamp(row[0] / 1000_000, tz=tz)
            else:
                return None

        return result.scalar()

    async def add_job(self, job: Job) -> None:
        marshalled = job.marshal(self.serializer)
        insert = self._t_jobs.insert().values(**marshalled)
        event = JobAdded(
            job_id=job.id,
            task_id=job.task_id,
            schedule_id=job.schedule_id,
        )
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    await self._execute(conn, insert)
                    await self._record_persistent_events(conn, [event])

        await self._event_broker.publish(event)

    async def get_jobs(self, ids: Iterable[UUID] | None = None) -> list[Job]:
        query = self._t_jobs.select().order_by(self._t_jobs.c.id)
        if ids:
            job_ids = list(ids)
            query = query.where(self._t_jobs.c.id.in_(job_ids))

        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    result = await self._execute(conn, query)

        return await self._deserialize_jobs(result)

    async def acquire_jobs(
        self, scheduler_id: str, lease_duration: timedelta, limit: int | None = None
    ) -> list[Job]:
        events: list[JobAcquired | JobReleased] = []
        async for attempt in self._retry():
            events = []
            with attempt:
                async with self._begin_transaction() as conn:
                    now = datetime.now(timezone.utc)
                    acquired_until = now + lease_duration
                    query = (
                        select(
                            self._t_jobs,
                            self._t_tasks.c.max_running_jobs,
                            self._t_tasks.c.running_jobs,
                        )
                        .join(
                            self._t_tasks, self._t_tasks.c.id == self._t_jobs.c.task_id
                        )
                        .where(
                            or_(
                                self._t_jobs.c.acquired_until.is_(None),
                                self._t_jobs.c.acquired_until < now,
                            )
                        )
                        .order_by(self._t_jobs.c.created_at)
                        .with_for_update(
                            skip_locked=True,
                            of=[
                                self._t_tasks.c.running_jobs,
                                self._t_jobs.c.acquired_by,
                                self._t_jobs.c.acquired_until,
                            ],
                        )
                        .limit(limit)
                    )

                    result = await self._execute(conn, query)
                    if not result:
                        return []

                    acquired_jobs: list[Job] = []
                    discarded_jobs: list[_JobDiscard] = []
                    task_job_slots_left: dict[str, float] = defaultdict(
                        lambda: float("inf")
                    )
                    running_job_count_increments: dict[str, int] = defaultdict(
                        lambda: 0
                    )
                    for row in result:
                        job_dict = row._asdict()
                        task_max_running_jobs = job_dict.pop("max_running_jobs")
                        task_running_jobs = job_dict.pop("running_jobs")
                        if task_max_running_jobs is not None:
                            task_job_slots_left.setdefault(
                                row.task_id, task_max_running_jobs - task_running_jobs
                            )

                        # Deserialize the job
                        try:
                            job = Job.unmarshal(self.serializer, job_dict)
                        except DeserializationError as exc:
                            # Deserialization failed, so record the exception as the job
                            # result
                            discarded_jobs.append(
                                _JobDiscard(
                                    job_id=row.id,
                                    outcome=JobOutcome.deserialization_failed,
                                    task_id=row.task_id,
                                    schedule_id=row.schedule_id,
                                    scheduled_fire_time=row.scheduled_fire_time,
                                    result_expires_at=now + row.result_expiration_time,
                                    exception=exc,
                                )
                            )
                            continue

                        # Discard the job if its start deadline has passed
                        if job.start_deadline and job.start_deadline < now:
                            discarded_jobs.append(
                                _JobDiscard(
                                    job_id=row.id,
                                    outcome=JobOutcome.missed_start_deadline,
                                    task_id=row.task_id,
                                    schedule_id=row.schedule_id,
                                    scheduled_fire_time=row.scheduled_fire_time,
                                    result_expires_at=now + row.result_expiration_time,
                                )
                            )
                            continue

                        # Skip the job if no more slots are available
                        if not task_job_slots_left[job.task_id]:
                            self._logger.debug(
                                "Skipping job %s because task %r has the maximum "
                                "number of %d jobs already running",
                                job.id,
                                job.task_id,
                                task_max_running_jobs,
                            )
                            continue

                        task_job_slots_left[job.task_id] -= 1
                        running_job_count_increments[job.task_id] += 1
                        job.acquired_by = scheduler_id
                        job.acquired_until = acquired_until
                        acquired_jobs.append(job)
                        events.append(
                            JobAcquired.from_job(job, scheduler_id=scheduler_id)
                        )

                    if acquired_jobs:
                        # Mark the acquired jobs as acquired by this worker
                        acquired_job_ids = [job.id for job in acquired_jobs]
                        update = (
                            self._t_jobs.update()
                            .values(
                                acquired_by=scheduler_id, acquired_until=acquired_until
                            )
                            .where(self._t_jobs.c.id.in_(acquired_job_ids))
                        )
                        await self._execute(conn, update)

                        # Increment the running job counters on each task
                        p_id: BindParameter = bindparam("p_id")
                        p_increment: BindParameter = bindparam("p_increment")
                        params = [
                            {"p_id": task_id, "p_increment": increment}
                            for task_id, increment in (
                                running_job_count_increments.items()
                            )
                        ]
                        update = (
                            self._t_tasks.update()
                            .values(
                                running_jobs=self._t_tasks.c.running_jobs + p_increment
                            )
                            .where(self._t_tasks.c.id == p_id)
                        )
                        await self._execute(conn, update, params)

                    # Discard the jobs that could not start
                    for discard in discarded_jobs:
                        result = JobResult(
                            job_id=discard.job_id,
                            outcome=discard.outcome,
                            finished_at=now,
                            expires_at=discard.result_expires_at,
                            exception=discard.exception,
                        )
                        events.append(
                            await self._release_job(
                                conn,
                                result,
                                scheduler_id,
                                discard.task_id,
                                discard.schedule_id,
                                discard.scheduled_fire_time,
                                decrement_running_job_count=False,
                            )
                        )

                    await self._record_persistent_events(conn, events)

        # Publish the appropriate events
        await self._publish_events(events)

        return acquired_jobs

    async def _release_job(
        self,
        conn: Connection | AsyncConnection,
        result: JobResult,
        scheduler_id: str,
        task_id: str,
        schedule_id: str | None = None,
        scheduled_fire_time: datetime | None = None,
        *,
        decrement_running_job_count: bool = True,
    ) -> JobReleased:
        # Record the job result
        if result.expires_at > result.finished_at:
            marshalled = result.marshal(self.serializer)
            insert = self._t_job_results.insert().values(**marshalled)
            await self._execute(conn, insert)

        # Decrement the number of running jobs for this task
        if decrement_running_job_count:
            update = (
                self._t_tasks.update()
                .values(running_jobs=self._t_tasks.c.running_jobs - 1)
                .where(self._t_tasks.c.id == task_id)
            )
            await self._execute(conn, update)

        # Delete the job
        delete = self._t_jobs.delete().where(self._t_jobs.c.id == result.job_id)
        await self._execute(conn, delete)

        # Create the event, to be sent after commit
        return JobReleased.from_result(
            result, scheduler_id, task_id, schedule_id, scheduled_fire_time
        )

    async def release_job(self, scheduler_id: str, job: Job, result: JobResult) -> None:
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    event = await self._release_job(
                        conn,
                        result,
                        scheduler_id,
                        job.task_id,
                        job.schedule_id,
                        job.scheduled_fire_time,
                    )
                    await self._record_persistent_events(conn, [event])

        # Notify other schedulers
        await self._event_broker.publish(event)

    async def get_job_result(self, job_id: UUID) -> JobResult | None:
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    # Retrieve the result
                    query = self._t_job_results.select().where(
                        self._t_job_results.c.job_id == job_id
                    )
                    if row := (await self._execute(conn, query)).one_or_none():
                        # Delete the result
                        delete = self._t_job_results.delete().where(
                            self._t_job_results.c.job_id == job_id
                        )
                        await self._execute(conn, delete)

        return JobResult.unmarshal(self.serializer, row._asdict()) if row else None

    async def extend_acquired_schedule_leases(
        self, scheduler_id: str, schedule_ids: set[str], duration: timedelta
    ) -> None:
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    new_acquired_until = datetime.now(timezone.utc) + duration
                    update = (
                        self._t_schedules.update()
                        .values(acquired_until=new_acquired_until)
                        .where(
                            self._t_schedules.c.acquired_by == scheduler_id,
                            self._t_schedules.c.id.in_(schedule_ids),
                        )
                    )
                    await self._execute(conn, update)

    async def extend_acquired_job_leases(
        self, scheduler_id: str, job_ids: set[UUID], duration: timedelta
    ) -> None:
        async for attempt in self._retry():
            with attempt:
                async with self._begin_transaction() as conn:
                    new_acquired_until = datetime.now(timezone.utc) + duration
                    update = (
                        self._t_jobs.update()
                        .values(acquired_until=new_acquired_until)
                        .where(
                            self._t_jobs.c.acquired_by == scheduler_id,
                            self._t_jobs.c.id.in_(job_ids),
                        )
                    )
                    await self._execute(conn, update)

    async def reap_abandoned_jobs(self, scheduler_id: str) -> None:
        query = (
            select(self._t_jobs)
            .where(self._t_jobs.c.acquired_by == scheduler_id)
            .with_for_update()
        )
        events: list[JobReleased] = []
        async for attempt in self._retry():
            events = []
            with attempt:
                async with self._begin_transaction() as conn:
                    if results := await self._execute(conn, query):
                        for row in results:
                            job_dict = self._convert_incoming_fire_times(row._asdict())
                            job = Job.unmarshal(
                                self.serializer, {**job_dict, "args": (), "kwargs": {}}
                            )
                            result = JobResult.from_job(job, JobOutcome.abandoned)
                            event = await self._release_job(
                                conn,
                                result,
                                scheduler_id,
                                job.task_id,
                                job.schedule_id,
                                job.scheduled_fire_time,
                            )
                            events.append(event)
                    await self._record_persistent_events(conn, events)

        await self._publish_events(events)

    async def cleanup(self) -> None:
        events: list[Event] = []
        async for attempt in self._retry():
            events = []
            with attempt:
                async with self._begin_transaction() as conn:
                    if (
                        self.persistent_events
                        and self._t_persistent_events is not None
                        and self.persistent_event_retention is not None
                    ):
                        cutoff = datetime.now(timezone.utc) - (
                            self.persistent_event_retention
                        )
                        cleanup = self._t_persistent_events.delete().where(
                            self._t_persistent_events.c.timestamp <= cutoff
                        )
                        await self._execute(conn, cleanup)

                    # Purge expired job results
                    delete = self._t_job_results.delete().where(
                        self._t_job_results.c.expires_at <= datetime.now(timezone.utc)
                    )
                    await self._execute(conn, delete)

                    # Finish any jobs whose leases have expired
                    now = datetime.now(timezone.utc)
                    query = select(
                        self._t_jobs.c.id,
                        self._t_jobs.c.task_id,
                        self._t_jobs.c.schedule_id,
                        self._t_jobs.c.scheduled_fire_time,
                        self._t_jobs.c.acquired_by,
                        self._t_jobs.c.result_expiration_time,
                    ).where(
                        self._t_jobs.c.acquired_by.isnot(None),
                        self._t_jobs.c.acquired_until < now,
                    )
                    for row in await self._execute(conn, query):
                        result = JobResult(
                            job_id=row.id,
                            outcome=JobOutcome.abandoned,
                            finished_at=now,
                            expires_at=now + row.result_expiration_time,
                        )
                        events.append(
                            await self._release_job(
                                conn,
                                result,
                                row.acquired_by,
                                row.task_id,
                                row.schedule_id,
                                row.scheduled_fire_time,
                            )
                        )

                    # Release any schedules whose leases have expired
                    columns = [
                        self._t_schedules.c.id,
                        self._t_schedules.c.task_id,
                        self._t_schedules.c.next_fire_time,
                    ]
                    if not self._supports_tzaware_timestamps:
                        columns.append(self._t_schedules.c.next_fire_time_utcoffset)

                    query = select(*columns).where(
                        self._t_schedules.c.acquired_by.isnot(None),
                        self._t_schedules.c.acquired_until < now,
                    )
                    expired_schedule_ids: list[str] = []
                    for row in await self._execute(conn, query):
                        schedule_dict = self._convert_incoming_fire_times(row._asdict())
                        expired_schedule_ids.append(schedule_dict["id"])
                        events.append(
                            ScheduleUpdated(
                                schedule_id=schedule_dict["id"],
                                task_id=schedule_dict["task_id"],
                                next_fire_time=schedule_dict["next_fire_time"],
                            )
                        )

                    if expired_schedule_ids:
                        update = (
                            self._t_schedules.update()
                            .where(self._t_schedules.c.id.in_(expired_schedule_ids))
                            .values(acquired_by=None, acquired_until=None)
                        )
                        await self._execute(conn, update)

                    # Clean up finished schedules that have no running jobs
                    query = (
                        select(self._t_schedules.c.id, self._t_schedules.c.task_id)
                        .outerjoin(
                            self._t_jobs,
                            self._t_jobs.c.schedule_id == self._t_schedules.c.id,
                        )
                        .where(
                            self._t_schedules.c.next_fire_time.is_(None),
                            self._t_jobs.c.id.is_(None),
                        )
                    )
                    results = await self._execute(conn, query)
                    if finished_schedule_ids := dict(results.all()):
                        delete = self._t_schedules.delete().where(
                            self._t_schedules.c.id.in_(finished_schedule_ids)
                        )
                        await self._execute(conn, delete)

                    for schedule_id, task_id in finished_schedule_ids.items():
                        events.append(
                            ScheduleRemoved(
                                schedule_id=schedule_id,
                                task_id=task_id,
                                finished=True,
                            )
                        )

                    await self._record_persistent_events(conn, events)

                # Publish any events produced from the operations
                await self._publish_events(events)
