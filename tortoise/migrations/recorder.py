from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from tortoise import fields
from tortoise.exceptions import IntegrityError
from tortoise.migrations.exceptions import (
    MigrationCheckpointError,
    MigrationLockedError,
    MigrationLockLostError,
)
from tortoise.migrations.graph import MigrationKey
from tortoise.models import Model

if TYPE_CHECKING:
    from tortoise.backends.base.client import BaseDBAsyncClient


class MigrationRecorder:
    progress_table_name = "tortoise_migration_progress"

    def __init__(self, connection, *, table_name: str = "tortoise_migrations") -> None:
        self.connection = connection
        self.table_name = table_name
        self.model = self._make_model(table_name)
        self.progress_model = self._make_progress_model(self.progress_table_name)
        if connection is None:
            self._dialect = ""
        else:
            capabilities = getattr(connection, "capabilities", None)
            self._dialect = getattr(capabilities, "dialect", "")

    def _quote(self, name: str) -> str:
        if self._dialect == "mysql":
            return f"`{name}`"
        if self._dialect == "mssql":
            return f"[{name}]"
        return f'"{name}"'

    def _placeholder(self, pos: int) -> str:
        if self._dialect == "mysql":
            return "%s"
        if self._dialect == "postgres":
            return f"${pos}"
        # sqlite, mssql, oracle: ?-style (native or via ODBC)
        return "?"

    def _make_model(self, table_name: str) -> type[Model]:
        class MigrationRecord(Model):
            id = fields.IntField(primary_key=True)
            app = fields.CharField(max_length=255)
            name = fields.CharField(max_length=255)
            applied_at = fields.DatetimeField()

            class Meta:
                table = table_name
                app = "_migrations"
                unique_together = (("app", "name"),)

        return MigrationRecord

    def _make_progress_model(self, table_name: str) -> type[Model]:
        class MigrationProgressRecord(Model):
            id = fields.IntField(primary_key=True)
            app = fields.CharField(max_length=255)
            name = fields.CharField(max_length=255)
            operation_index = fields.IntField()
            checksum = fields.CharField(max_length=64)
            cursor = fields.TextField(null=True)
            status = fields.CharField(max_length=20)
            locked_at = fields.DatetimeField(null=True)
            lock_expires_at = fields.DatetimeField(null=True)
            lock_token = fields.CharField(max_length=64, null=True)
            updated_at = fields.DatetimeField()

            class Meta:
                table = table_name
                app = "_migration_progress"
                unique_together = (("app", "name", "operation_index"),)

        return MigrationProgressRecord

    async def ensure_schema(self, schema_editor) -> None:
        await self._ensure_model_schema(self.model, self.table_name, schema_editor)

    async def ensure_progress_schema(self, schema_editor) -> None:
        await self._ensure_model_schema(
            self.progress_model, self.progress_table_name, schema_editor
        )

    async def _ensure_model_schema(
        self, model: type[Model], table_name: str, schema_editor
    ) -> None:
        statement = schema_editor._get_model_sql_data(model).table_sql
        if schema_editor.DIALECT in {"sqlite", "postgres", "mysql"}:
            statement = statement.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1)
            await schema_editor.client.execute_script(statement)
            return
        if schema_editor.DIALECT == "mssql":
            statement = (
                f"IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = '{table_name}')\n"  # nosec B608
                f"BEGIN\n{statement}\nEND"
            )
            await schema_editor.client.execute_script(statement)
            return
        try:
            await schema_editor.client.execute_script(statement)
        except Exception as exc:  # pragma: nocoverage - best effort for non-IF-NOT-EXISTS backends
            message = str(exc).lower()
            if "already exists" in message or "ora-00955" in message:
                return
            raise

    async def applied_migrations(self) -> list[MigrationKey]:
        query = (
            f"SELECT {self._quote('app')}, {self._quote('name')} "  # nosec B608
            f"FROM {self._quote(self.table_name)} "
            f"ORDER BY {self._quote('applied_at')}, {self._quote('app')}, {self._quote('name')}"
        )
        try:
            _, rows = await self.connection.execute_query(query)
        except Exception:
            return []
        return [MigrationKey(app_label=row["app"], name=row["name"]) for row in rows]

    async def record_applied(self, app: str, name: str) -> None:
        applied_at = datetime.now(timezone.utc)
        query = (
            f"INSERT INTO {self._quote(self.table_name)} "  # nosec B608
            f"({self._quote('app')}, {self._quote('name')}, {self._quote('applied_at')}) "
            f"VALUES ({self._placeholder(1)}, {self._placeholder(2)}, {self._placeholder(3)})"
        )
        await self.connection.execute_insert(query, [app, name, applied_at])

    async def record_unapplied(self, app: str, name: str) -> None:
        query = (
            f"DELETE FROM {self._quote(self.table_name)} "  # nosec B608
            f"WHERE {self._quote('app')} = {self._placeholder(1)} "
            f"AND {self._quote('name')} = {self._placeholder(2)}"
        )
        await self.connection.execute_query(query, [app, name])

    @staticmethod
    def _row_value(row: dict[str, Any], key: str) -> Any:
        if key in row:
            return row[key]
        return row[key.upper()]

    @classmethod
    def _datetime_value(cls, row: dict[str, Any], key: str) -> datetime | None:
        value = cls._row_value(row, key)
        if value is None or isinstance(value, datetime):
            return value
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    @staticmethod
    def encode_cursor(cursor: Any) -> str | None:
        if cursor is None:
            return None
        return json.dumps(cursor, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    @staticmethod
    def decode_cursor(value: str | None) -> Any:
        if value is None:
            return None
        return json.loads(value)

    async def migration_progress(
        self, app: str, name: str, *, connection: BaseDBAsyncClient | None = None
    ) -> list[dict[str, Any]]:
        client = connection or self.connection
        query = (
            f"SELECT * FROM {self._quote(self.progress_table_name)} "  # nosec B608
            f"WHERE {self._quote('app')} = {self._placeholder(1)} "
            f"AND {self._quote('name')} = {self._placeholder(2)} "
            f"ORDER BY {self._quote('operation_index')}"
        )
        _, rows = await client.execute_query(query, [app, name])
        return list(rows)

    async def acquire_migration_lock(
        self,
        app: str,
        name: str,
        checksum: str,
        *,
        lock_timeout: float,
        connection: BaseDBAsyncClient | None = None,
    ) -> str:
        client = connection or self.connection
        token = uuid4().hex
        now = datetime.now(timezone.utc)
        rows = await self.migration_progress(app, name, connection=client)
        if rows:
            for row in rows:
                if self._row_value(row, "checksum") != checksum:
                    raise MigrationCheckpointError(
                        f"Migration {app}.{name} changed since its checkpoint was saved; "
                        "create a new migration instead of reusing the old breakpoint"
                    )
            sentinel = next(
                (row for row in rows if self._row_value(row, "operation_index") == -1),
                None,
            )
            if sentinel is None:
                await self._insert_lock_sentinel(
                    client, app, name, checksum, token, now, lock_timeout
                )
                return token

            current_token = self._row_value(sentinel, "lock_token")
            expires_at = self._datetime_value(sentinel, "lock_expires_at")
            if current_token and expires_at and expires_at > now and current_token != token:
                raise MigrationLockedError(f"Migration {app}.{name} is already running")

            new_expires_at = now + timedelta(seconds=lock_timeout)
            affected = await self._update_lock_sentinel(
                client, app, name, token, now, new_expires_at
            )
            if affected != 1:
                raise MigrationLockedError(f"Migration {app}.{name} is already running")
            current_rows = await self.migration_progress(app, name, connection=client)
            current_sentinel = next(
                row for row in current_rows if self._row_value(row, "operation_index") == -1
            )
            if self._row_value(current_sentinel, "lock_token") != token:
                raise MigrationLockedError(f"Migration {app}.{name} is already running")
            return token

        await self._insert_lock_sentinel(client, app, name, checksum, token, now, lock_timeout)
        return token

    async def _insert_lock_sentinel(
        self,
        client,
        app: str,
        name: str,
        checksum: str,
        token: str,
        now: datetime,
        lock_timeout: float,
    ) -> None:
        query = (
            f"INSERT INTO {self._quote(self.progress_table_name)} "  # nosec B608
            f"({self._quote('app')}, {self._quote('name')}, "
            f"{self._quote('operation_index')}, {self._quote('checksum')}, "
            f"{self._quote('cursor')}, {self._quote('status')}, {self._quote('locked_at')}, "
            f"{self._quote('lock_expires_at')}, {self._quote('lock_token')}, "
            f"{self._quote('updated_at')}) VALUES "
            f"({', '.join(self._placeholder(index) for index in range(1, 11))})"
        )
        expires_at = now + timedelta(seconds=lock_timeout)
        try:
            await client.execute_insert(
                query,
                [
                    app,
                    name,
                    -1,
                    checksum,
                    None,
                    "running",
                    now,
                    expires_at,
                    token,
                    now,
                ],
            )
        except IntegrityError:
            raise MigrationLockedError(f"Migration {app}.{name} is already running") from None

    async def _update_lock_sentinel(
        self,
        client,
        app: str,
        name: str,
        token: str,
        now: datetime,
        expires_at: datetime,
    ) -> int:
        query = (
            f"UPDATE {self._quote(self.progress_table_name)} "  # nosec B608
            f"SET {self._quote('locked_at')} = {self._placeholder(1)}, "
            f"{self._quote('lock_expires_at')} = {self._placeholder(2)}, "
            f"{self._quote('lock_token')} = {self._placeholder(3)}, "
            f"{self._quote('updated_at')} = {self._placeholder(4)} "
            f"WHERE {self._quote('app')} = {self._placeholder(5)} "
            f"AND {self._quote('name')} = {self._placeholder(6)} "
            f"AND {self._quote('operation_index')} = -1 "
            f"AND ({self._quote('lock_expires_at')} <= {self._placeholder(7)} "
            f"OR {self._quote('lock_token')} = {self._placeholder(8)})"
        )
        affected, _ = await client.execute_query(
            query, [now, expires_at, token, now, app, name, now, token]
        )
        return int(affected)

    async def get_operation_progress(
        self,
        app: str,
        name: str,
        operation_index: int,
        connection: BaseDBAsyncClient | None = None,
    ) -> dict[str, Any] | None:
        client = connection or self.connection
        query = (
            f"SELECT * FROM {self._quote(self.progress_table_name)} "  # nosec B608
            f"WHERE {self._quote('app')} = {self._placeholder(1)} "
            f"AND {self._quote('name')} = {self._placeholder(2)} "
            f"AND {self._quote('operation_index')} = {self._placeholder(3)}"
        )
        _, rows = await client.execute_query(query, [app, name, operation_index])
        return dict(rows[0]) if rows else None

    async def save_operation_progress(
        self,
        app: str,
        name: str,
        operation_index: int,
        checksum: str,
        cursor: Any,
        complete: bool,
        token: str,
        lock_timeout: float,
        *,
        client,
    ) -> None:
        now = datetime.now(timezone.utc)
        encoded_cursor = self.encode_cursor(cursor)
        status = "complete" if complete else "running"
        existing = await self.get_operation_progress(app, name, operation_index, connection=client)
        if existing is None:
            query = (
                f"INSERT INTO {self._quote(self.progress_table_name)} "  # nosec B608
                f"({self._quote('app')}, {self._quote('name')}, "
                f"{self._quote('operation_index')}, {self._quote('checksum')}, "
                f"{self._quote('cursor')}, {self._quote('status')}, "
                f"{self._quote('updated_at')}) VALUES "
                f"({', '.join(self._placeholder(index) for index in range(1, 8))})"
            )
            await client.execute_insert(
                query,
                [app, name, operation_index, checksum, encoded_cursor, status, now],
            )
        else:
            query = (
                f"UPDATE {self._quote(self.progress_table_name)} "  # nosec B608
                f"SET {self._quote('checksum')} = {self._placeholder(1)}, "
                f"{self._quote('cursor')} = {self._placeholder(2)}, "
                f"{self._quote('status')} = {self._placeholder(3)}, "
                f"{self._quote('updated_at')} = {self._placeholder(4)} "
                f"WHERE {self._quote('app')} = {self._placeholder(5)} "
                f"AND {self._quote('name')} = {self._placeholder(6)} "
                f"AND {self._quote('operation_index')} = {self._placeholder(7)}"
            )
            await client.execute_query(
                query,
                [checksum, encoded_cursor, status, now, app, name, operation_index],
            )

        expires_at = now + timedelta(seconds=lock_timeout)
        affected = await self._update_lock_sentinel(client, app, name, token, now, expires_at)
        if affected != 1:
            raise MigrationLockLostError(f"Lost lock for migration {app}.{name}")

    async def release_migration_lock(self, app: str, name: str, token: str) -> None:
        now = datetime.now(timezone.utc)
        query = (
            f"UPDATE {self._quote(self.progress_table_name)} "  # nosec B608
            f"SET {self._quote('locked_at')} = NULL, "
            f"{self._quote('lock_expires_at')} = {self._placeholder(1)}, "
            f"{self._quote('updated_at')} = {self._placeholder(2)} "
            f"WHERE {self._quote('app')} = {self._placeholder(3)} "
            f"AND {self._quote('name')} = {self._placeholder(4)} "
            f"AND {self._quote('operation_index')} = {self._placeholder(5)} "
            f"AND {self._quote('lock_token')} = {self._placeholder(6)}"
        )
        await self.connection.execute_query(query, [now, now, app, name, -1, token])

    async def touch_migration_lock(
        self, app: str, name: str, token: str, lock_timeout: float, *, client
    ) -> int:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=lock_timeout)
        return await self._update_lock_sentinel(client, app, name, token, now, expires_at)
