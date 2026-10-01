from __future__ import annotations

from pathlib import Path

import pytest

from tortoise.backends.base.client import Capabilities
from tortoise.backends.sqlite.client import SqliteClient
from tortoise.context import TortoiseContext
from tortoise.migrations.exceptions import MigrationCheckpointError, MigrationLockedError
from tortoise.migrations.executor import MigrationExecutor
from tortoise.migrations.migration import Migration
from tortoise.migrations.operations import RunPythonBatched
from tortoise.migrations.schema_generator.state import State
from tortoise.migrations.schema_generator.state_apps import StateApps


def _write_batched_migration(tmp_path: Path, *, fail_once: bool = False) -> tuple[str, str]:
    app_label = f"app_{tmp_path.name.replace('-', '_')}"
    package_dir = tmp_path / app_label
    migrations_dir = package_dir / "migrations"
    migrations_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (migrations_dir / "__init__.py").write_text("", encoding="utf-8")
    (migrations_dir / "0001_batched.py").write_text(
        f"""\
from pathlib import Path
from tortoise import migrations
from tortoise.migrations import operations as ops

FAIL_ONCE = {fail_once!r}
BATCHES = []
FAILURE_MARKER = Path(__file__).parent / "failure-happened"


async def process_batch(apps, schema_editor, cursor):
    last_id = cursor or 0
    _, rows = await schema_editor.client.execute_query(
        "SELECT id FROM item WHERE id > ? ORDER BY id LIMIT 2", [last_id]
    )
    if not rows:
        BATCHES.append(None)
        return None
    ids = [row["id"] for row in rows]
    placeholders = ", ".join("?" for _ in ids)
    await schema_editor.client.execute_query(
        f"UPDATE item SET processed = 1 WHERE id IN ({{placeholders}})", ids
    )
    next_cursor = ids[-1]
    if FAIL_ONCE and next_cursor == 4 and last_id == 2 and not FAILURE_MARKER.exists():
        FAILURE_MARKER.write_text("1")
        raise RuntimeError("interrupted batch")
    BATCHES.append(next_cursor)
    return next_cursor


class Migration(migrations.Migration):
    dependencies = []
    atomic = False

    operations = [
        ops.RunPythonBatched(process_batch, initial_cursor=None, lock_timeout=30),
    ]
""",
        encoding="utf-8",
    )
    return app_label, f"{app_label}.migrations"


async def _start_context(tmp_path: Path) -> tuple[TortoiseContext, SqliteClient, str]:
    db_path = tmp_path / "batched.sqlite3"
    ctx = TortoiseContext()
    await ctx.__aenter__()
    ctx.connections._init_config(
        {
            "default": {
                "engine": "tortoise.backends.sqlite",
                "credentials": {"file_path": str(db_path)},
            }
        }
    )
    connection = ctx.connections.get("default")
    await connection.execute_script(
        "CREATE TABLE item (id INTEGER PRIMARY KEY, processed INTEGER NOT NULL DEFAULT 0)"
    )
    for index in range(1, 6):
        await connection.execute_insert("INSERT INTO item (id) VALUES (?)", [index])
    return ctx, connection, str(db_path)


def _executor(connection: SqliteClient, app_label: str = "app") -> MigrationExecutor:
    return MigrationExecutor(
        connection,
        {
            app_label: {
                "models": [],
                "default_connection": "default",
                "migrations": f"{app_label}.migrations",
            }
        },
    )


@pytest.mark.asyncio
async def test_batched_operation_resumes_after_committed_batches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    app_label, module_path = _write_batched_migration(tmp_path, fail_once=True)
    ctx, connection, _ = await _start_context(tmp_path)
    try:
        executor = _executor(connection, app_label)
        with pytest.raises(RuntimeError, match="interrupted batch"):
            await executor.migrate()

        _, rows = await connection.execute_query("SELECT id FROM item WHERE processed = 1")
        assert [row["id"] for row in rows] == [1, 2]
        _, progress = await connection.execute_query(
            "SELECT cursor, status FROM tortoise_migration_progress WHERE operation_index = 0"
        )
        assert progress[0]["cursor"] == "2"
        assert progress[0]["status"] == "running"

        await executor.migrate()
        _, rows = await connection.execute_query("SELECT id FROM item WHERE processed = 0")
        assert rows == []
        _, progress = await connection.execute_query(
            "SELECT cursor, status FROM tortoise_migration_progress WHERE operation_index = 0"
        )
        assert progress[0]["cursor"] is None
        assert progress[0]["status"] == "complete"
        _, applied = await connection.execute_query("SELECT name FROM tortoise_migrations")
        assert applied[0]["name"] == "0001_batched"

        module = __import__(f"{module_path}.0001_batched", fromlist=["BATCHES"])
        assert module.BATCHES == [2, 4, 5, None]
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_changed_migration_rejects_old_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    app_label, _ = _write_batched_migration(tmp_path, fail_once=True)
    ctx, connection, _ = await _start_context(tmp_path)
    try:
        executor = _executor(connection, app_label)
        with pytest.raises(RuntimeError, match="interrupted batch"):
            await executor.migrate()

        migration_file = tmp_path / app_label / "migrations" / "0001_batched.py"
        content = migration_file.read_text(encoding="utf-8")
        migration_file.write_text("# changed migration definition\n" + content, encoding="utf-8")

        with pytest.raises(MigrationCheckpointError, match="changed since its checkpoint"):
            await executor.migrate()
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_active_lease_blocks_another_executor(tmp_path: Path) -> None:
    ctx, connection, _ = await _start_context(tmp_path)
    try:
        executor = _executor(connection)
        await executor.recorder.ensure_schema(executor._schema_editor(atomic=False))
        await executor.recorder.ensure_progress_schema(executor._schema_editor(atomic=False))
        first = await executor.recorder.acquire_migration_lock(
            "app", "0001_batched", "checksum", lock_timeout=30
        )
        with pytest.raises(MigrationLockedError):
            await executor.recorder.acquire_migration_lock(
                "app", "0001_batched", "checksum", lock_timeout=30
            )
        await connection.execute_query(
            "UPDATE tortoise_migration_progress SET lock_expires_at = ? WHERE operation_index = -1",
            ["2000-01-01 00:00:00+00:00"],
        )
        second = await executor.recorder.acquire_migration_lock(
            "app", "0001_batched", "checksum", lock_timeout=30
        )
        assert first != second
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_batched_operation_is_not_reversible() -> None:
    async def process_batch(apps, schema_editor, cursor):
        return None

    migration = Migration("0001_batched", "app")
    migration.operations = [RunPythonBatched(process_batch)]

    with pytest.raises(ValueError, match="is not reversible"):
        await migration.unapply(State(models={}, apps=StateApps()))


@pytest.mark.asyncio
async def test_batched_operation_requires_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app_label, _ = _write_batched_migration(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))

    class ConnectionWithoutTransactions:
        capabilities = Capabilities("sqlite", supports_transactions=False)
        connection_name = "default"

        async def execute_query(self, query, values=None):
            return 0, []

        async def execute_insert(self, query, values):
            return 1

        async def execute_script(self, query):
            return None

    executor = MigrationExecutor(
        ConnectionWithoutTransactions(),
        {
            app_label: {
                "models": [],
                "default_connection": "default",
                "migrations": f"{app_label}.migrations",
            }
        },
    )
    await executor.recorder.ensure_progress_schema(executor._schema_editor(atomic=False))

    with pytest.raises(RuntimeError, match="requires transactions"):
        await executor.migrate()


def test_batched_migration_must_be_non_atomic() -> None:
    async def process_batch(apps, schema_editor, cursor):
        return None

    class AtomicMigration(Migration):
        atomic = True
        operations = [RunPythonBatched(process_batch)]

    migration = AtomicMigration("0001_batched", "app")
    with pytest.raises(ValueError, match="must set atomic=False"):
        MigrationExecutor._validate_batched_migration(migration, list(migration.operations))
