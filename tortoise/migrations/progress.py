from __future__ import annotations

from dataclasses import dataclass

from tortoise.migrations.exceptions import MigrationCheckpointError
from tortoise.migrations.graph import MigrationKey
from tortoise.migrations.operations import RunPythonBatched
from tortoise.migrations.recorder import MigrationRecorder
from tortoise.migrations.schema_editor.base import BaseSchemaEditor
from tortoise.migrations.schema_generator.state_apps import StateApps
from tortoise.transactions import in_transaction


@dataclass
class BatchingMigrationContext:
    recorder: MigrationRecorder
    key: MigrationKey
    checksum: str
    lock_token: str
    lock_timeout: float
    operation_index: int = -1

    async def run_batched_operation(
        self,
        operation: RunPythonBatched,
        apps: StateApps,
        schema_editor: BaseSchemaEditor,
    ) -> None:
        connection = schema_editor.client
        row = await self.recorder.get_operation_progress(
            self.key.app_label,
            self.key.name,
            self.operation_index,
            connection=connection,
        )
        if row is not None:
            checksum = self.recorder._row_value(row, "checksum")
            if checksum != self.checksum:
                raise MigrationCheckpointError(
                    f"Migration {self.key} changed since its checkpoint was saved"
                )
            if self.recorder._row_value(row, "status") == "complete":
                return
            cursor = self.recorder.decode_cursor(self.recorder._row_value(row, "cursor"))
        else:
            cursor = operation.initial_cursor

        while True:
            async with in_transaction(connection.connection_name) as transaction_client:
                previous_client = schema_editor.client
                schema_editor.client = transaction_client
                try:
                    lock_affected = await self.recorder.touch_migration_lock(
                        self.key.app_label,
                        self.key.name,
                        self.lock_token,
                        operation.lock_timeout,
                        client=transaction_client,
                    )
                    if lock_affected != 1:
                        raise RuntimeError(f"Lost lock for migration {self.key}")
                    result = operation.code(apps, schema_editor, cursor)
                    if hasattr(result, "__await__"):
                        next_cursor = await result
                    else:
                        next_cursor = result
                finally:
                    schema_editor.client = previous_client

                complete = next_cursor is None
                if not complete and next_cursor == cursor:
                    raise RuntimeError(
                        "RunPythonBatched handler must return a different cursor after each batch"
                    )
                await self.recorder.save_operation_progress(
                    self.key.app_label,
                    self.key.name,
                    self.operation_index,
                    self.checksum,
                    next_cursor,
                    complete,
                    self.lock_token,
                    operation.lock_timeout,
                    client=transaction_client,
                )

            if complete:
                return
            cursor = next_cursor
