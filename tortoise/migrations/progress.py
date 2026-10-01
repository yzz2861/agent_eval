from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from tortoise import fields
from tortoise.migrations.recorder import MigrationRecorder
from tortoise.models import Model


class MigrationProgressRecorder(MigrationRecorder):
    """Stores resumable batch-migration checkpoints.

    Each row tracks how far one RunPythonBatched operation (identified by
    app/name/op_key) has progressed, which migration definition fingerprint
    it belongs to, and which executor currently holds the locked_by claim.
    """

    def __init__(self, connection, *, table_name: str = "tortoise_migration_progress") -> None:
        super().__init__(connection, table_name=table_name)

    def _make_model(self, table_name: str) -> type[Model]:
        class MigrationProgress(Model):
            id = fields.IntField(primary_key=True)
            app = fields.CharField(max_length=255)
            name = fields.CharField(max_length=255)
            op_key = fields.CharField(max_length=255)
            fingerprint = fields.CharField(max_length=255)
            cursor = fields.TextField(null=True)
            batches_done = fields.IntField(default=0)
            locked_by = fields.CharField(max_length=255, null=True)
            locked_at = fields.DatetimeField(null=True)
            updated_at = fields.DatetimeField()

            class Meta:
                table = table_name
                app = "_migrations"
                unique_together = (("app", "name", "op_key"),)

        return MigrationProgress

    def _where_key(self, start: int = 1) -> str:
        return (
            f"WHERE {self._quote('app')} = {self._placeholder(start)} "
            f"AND {self._quote('name')} = {self._placeholder(start + 1)} "
            f"AND {self._quote('op_key')} = {self._placeholder(start + 2)}"
        )

    async def get_checkpoint(
        self, app: str, name: str, op_key: str, *, client=None
    ) -> dict[str, Any] | None:
        query = (
            f"SELECT {self._quote('fingerprint')}, {self._quote('cursor')}, "
            f"{self._quote('batches_done')}, {self._quote('locked_by')} "
            f"FROM {self._quote(self.table_name)} {self._where_key()}"
        )
        _, rows = await (client or self.connection).execute_query(query, [app, name, op_key])
        if not rows:
            return None
        return rows[0]

    async def create_checkpoint(
        self, app: str, name: str, op_key: str, fingerprint: str, owner: str, *, client=None
    ) -> None:
        now = datetime.now(timezone.utc)
        columns = (
            "app",
            "name",
            "op_key",
            "fingerprint",
            "cursor",
            "batches_done",
            "locked_by",
            "locked_at",
            "updated_at",
        )
        quoted = ", ".join(self._quote(column) for column in columns)
        placeholders = ", ".join(self._placeholder(pos) for pos in range(1, len(columns) + 1))
        query = f"INSERT INTO {self._quote(self.table_name)} ({quoted}) VALUES ({placeholders})"
        await (client or self.connection).execute_insert(
            query, [app, name, op_key, fingerprint, None, 0, owner, now, now]
        )

    async def claim(self, app: str, name: str, op_key: str, owner: str, *, client=None) -> bool:
        """Atomically claim an existing unlocked checkpoint row."""
        now = datetime.now(timezone.utc)
        query = (
            f"UPDATE {self._quote(self.table_name)} "
            f"SET {self._quote('locked_by')} = {self._placeholder(1)}, "
            f"{self._quote('locked_at')} = {self._placeholder(2)} "
            f"{self._where_key(3)} AND {self._quote('locked_by')} IS NULL"
        )
        affected, _ = await (client or self.connection).execute_query(
            query, [owner, now, app, name, op_key]
        )
        return affected > 0

    async def save_progress(
        self,
        app: str,
        name: str,
        op_key: str,
        cursor_json: str,
        batches_done: int,
        *,
        client=None,
    ) -> None:
        """Persist the cursor of a committed batch.

        Must be called with client bound to the same transaction that applied
        the batch, so data and progress commit (or roll back) together.
        """
        now = datetime.now(timezone.utc)
        query = (
            f"UPDATE {self._quote(self.table_name)} "
            f"SET {self._quote('cursor')} = {self._placeholder(1)}, "
            f"{self._quote('batches_done')} = {self._placeholder(2)}, "
            f"{self._quote('updated_at')} = {self._placeholder(3)} "
            f"{self._where_key(4)}"
        )
        await (client or self.connection).execute_query(
            query, [cursor_json, batches_done, now, app, name, op_key]
        )

    async def release(self, app: str, name: str, op_key: str, owner: str, *, client=None) -> None:
        """Release the executor claim, but only if we still own it."""
        query = (
            f"UPDATE {self._quote(self.table_name)} "
            f"SET {self._quote('locked_by')} = NULL, {self._quote('locked_at')} = NULL "
            f"{self._where_key()} AND {self._quote('locked_by')} = {self._placeholder(4)}"
        )
        await (client or self.connection).execute_query(query, [app, name, op_key, owner])

    async def clear(self, app: str, name: str, op_key: str, *, client=None) -> None:
        """Delete the checkpoint row (operation finished or was reversed)."""
        query = f"DELETE FROM {self._quote(self.table_name)} {self._where_key()}"
        await (client or self.connection).execute_query(query, [app, name, op_key])
