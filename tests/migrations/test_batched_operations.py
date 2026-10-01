"""Integration tests for the resumable batched data-migration operation.

Covers the guarantees of RunPythonBatched:
- each batch's data changes and its checkpoint commit in one transaction
- an interrupted run resumes from the last committed batch
- a changed migration definition cannot reuse an old checkpoint
- one migration cannot be advanced by two executors at once
- reverse migrations run once, in a single transaction, without resume
"""

from __future__ import annotations

import pytest

from tortoise.migrations.exceptions import (
    CheckpointMismatchError,
    ConcurrentMigrationError,
    TortoiseMigrationError,
)
from tortoise.migrations.executor import MigrationExecutor
from tortoise.migrations.migration import Migration
from tortoise.migrations.operations import RunPythonBatched
from tortoise.migrations.progress import MigrationProgressRecorder
from tortoise.migrations.schema_generator.state import State
from tortoise.migrations.schema_generator.state_apps import StateApps

APP_LABEL = "models"
MIGRATION_NAME = "0002_backfill"
OP_KEY = "backfill-flag"
ROW_COUNT = 5


def _schema_editor(conn, *, atomic: bool = False):
    return MigrationExecutor(conn, {})._schema_editor(atomic=atomic)


def _placeholder(conn, pos: int) -> str:
    dialect = conn.capabilities.dialect
    if dialect == "mysql":
        return "%s"
    if dialect == "postgres":
        return "$" + str(pos)
    return "?"


async def _seed_items(conn, count: int = ROW_COUNT) -> None:
    await conn.execute_script(
        "CREATE TABLE test_item ("
        "id INTEGER PRIMARY KEY, "
        "name VARCHAR(50) NOT NULL, "
        "flag INTEGER NOT NULL DEFAULT 0)"
    )
    ph1 = _placeholder(conn, 1)
    ph2 = _placeholder(conn, 2)
    for item_id in range(1, count + 1):
        await conn.execute_insert(
            f"INSERT INTO test_item (id, name, flag) VALUES ({ph1}, {ph2}, 0)",
            [item_id, f"name{item_id}"],
        )


async def _flags(conn) -> dict[int, int]:
    rows = await conn.execute_query_dict("SELECT id, flag FROM test_item ORDER BY id")
    return {row["id"]: row["flag"] for row in rows}


async def _checkpoints(conn) -> list[dict]:
    return await conn.execute_query_dict(
        "SELECT app, name, op_key, fingerprint, cursor, batches_done, locked_by "
        "FROM tortoise_migration_progress"
    )


def _make_migration(*operations: RunPythonBatched, atomic: bool = False) -> Migration:
    migration = Migration(MIGRATION_NAME, APP_LABEL)
    migration.operations = list(operations)
    migration.atomic = atomic
    return migration


def _empty_state() -> State:
    return State(models={}, apps=StateApps())


def _batch_function(
    conn, *, batch_size: int = 2, calls: list | None = None, fail_at: set | None = None
):
    """Build a process_batch callable that sets flag=1 in id-order batches."""

    async def process_batch(apps, schema_editor, cursor):
        start = cursor if cursor is not None else 0
        if calls is not None:
            calls.append(start)
        rows = await schema_editor.client.execute_query_dict(
            f"SELECT id FROM test_item WHERE id > {start} AND flag = 0 "
            f"ORDER BY id LIMIT {batch_size}"
        )
        if not rows:
            return None
        ids = [row["id"] for row in rows]
        id_list = ", ".join(str(item_id) for item_id in ids)
        await schema_editor.client.execute_query(
            f"UPDATE test_item SET flag = 1 WHERE id IN ({id_list})"
        )
        if fail_at and start in fail_at:
            raise RuntimeError("simulated crash")
        return ids[-1]

    return process_batch


@pytest.mark.asyncio
async def test_forward_completes_and_clears_checkpoint(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    calls: list = []
    op = RunPythonBatched(OP_KEY, _batch_function(conn, calls=calls))

    migration = _make_migration(op)
    await migration.apply(_empty_state(), schema_editor=_schema_editor(conn))

    assert await _flags(conn) == {item_id: 1 for item_id in range(1, ROW_COUNT + 1)}
    # 3 data batches (2+2+1 rows) plus one final call reporting completion
    assert calls == [0, 2, 4, 5]
    assert await _checkpoints(conn) == []


@pytest.mark.asyncio
async def test_interrupted_run_resumes_from_last_committed_batch(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    fail_at = {2}
    op = RunPythonBatched(OP_KEY, _batch_function(conn, fail_at=fail_at))
    migration = _make_migration(op)

    with pytest.raises(RuntimeError, match="simulated crash"):
        await migration.apply(_empty_state(), schema_editor=_schema_editor(conn))

    # First batch committed both its data and its checkpoint.
    assert await _flags(conn) == {1: 1, 2: 1, 3: 0, 4: 0, 5: 0}
    (checkpoint,) = await _checkpoints(conn)
    assert checkpoint["app"] == APP_LABEL
    assert checkpoint["name"] == MIGRATION_NAME
    assert checkpoint["op_key"] == OP_KEY
    assert checkpoint["cursor"] == "2"
    assert checkpoint["batches_done"] == 1
    assert checkpoint["locked_by"] is None  # lock released after the crash

    # Resume with the same definition: only the remaining batches run.
    calls: list = []
    resume_op = RunPythonBatched(OP_KEY, _batch_function(conn, calls=calls))
    await _make_migration(resume_op).apply(_empty_state(), schema_editor=_schema_editor(conn))

    assert calls == [2, 4, 5]
    assert await _flags(conn) == {item_id: 1 for item_id in range(1, ROW_COUNT + 1)}
    assert await _checkpoints(conn) == []


@pytest.mark.asyncio
async def test_failed_batch_rolls_back_data_and_checkpoint_together(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)

    async def process_batch(apps, schema_editor, cursor):
        start = cursor if cursor is not None else 0
        rows = await schema_editor.client.execute_query_dict(
            f"SELECT id FROM test_item WHERE id > {start} AND flag = 0 ORDER BY id LIMIT 2"
        )
        if not rows:
            return None
        ids = [row["id"] for row in rows]
        id_list = ", ".join(str(item_id) for item_id in ids)
        await schema_editor.client.execute_query(
            f"UPDATE test_item SET flag = 1 WHERE id IN ({id_list})"
        )
        if start == 2:
            # Data change already issued, but the batch must not commit.
            raise RuntimeError("crash after data change")
        return ids[-1]

    op = RunPythonBatched(OP_KEY, process_batch)
    with pytest.raises(RuntimeError):
        await _make_migration(op).apply(_empty_state(), schema_editor=_schema_editor(conn))

    # Batch 2's UPDATE rolled back together with its checkpoint update:
    # neither "data committed without progress" nor "progress without data".
    assert await _flags(conn) == {1: 1, 2: 1, 3: 0, 4: 0, 5: 0}
    (checkpoint,) = await _checkpoints(conn)
    assert checkpoint["cursor"] == "2"
    assert checkpoint["batches_done"] == 1


@pytest.mark.asyncio
async def test_changed_definition_cannot_reuse_checkpoint(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    fail_at = {2}
    op = RunPythonBatched(OP_KEY, _batch_function(conn, fail_at=fail_at))
    with pytest.raises(RuntimeError):
        await _make_migration(op).apply(_empty_state(), schema_editor=_schema_editor(conn))

    async def different_process_batch(apps, schema_editor, cursor):
        return None

    changed_op = RunPythonBatched(OP_KEY, different_process_batch)
    with pytest.raises(CheckpointMismatchError):
        await _make_migration(changed_op).apply(_empty_state(), schema_editor=_schema_editor(conn))

    # Deleting the stale checkpoint lets the changed definition start fresh.
    await conn.execute_query("DELETE FROM tortoise_migration_progress")
    fresh_op = RunPythonBatched(OP_KEY, _batch_function(conn))
    await _make_migration(fresh_op).apply(_empty_state(), schema_editor=_schema_editor(conn))
    assert await _flags(conn) == {item_id: 1 for item_id in range(1, ROW_COUNT + 1)}
    assert await _checkpoints(conn) == []


@pytest.mark.asyncio
async def test_explicit_fingerprint_mismatch_rejected(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    fail_at = {2}
    op = RunPythonBatched(OP_KEY, _batch_function(conn, fail_at=fail_at), fingerprint="v1")
    with pytest.raises(RuntimeError):
        await _make_migration(op).apply(_empty_state(), schema_editor=_schema_editor(conn))

    changed = RunPythonBatched(OP_KEY, _batch_function(conn), fingerprint="v2")
    with pytest.raises(CheckpointMismatchError):
        await _make_migration(changed).apply(_empty_state(), schema_editor=_schema_editor(conn))


@pytest.mark.asyncio
async def test_concurrent_executor_rejected(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    op = RunPythonBatched(OP_KEY, _batch_function(conn))

    # Simulate another executor holding the lock on this operation.
    editor = _schema_editor(conn)
    recorder = MigrationProgressRecorder(conn)
    await recorder.ensure_schema(editor)
    await recorder.create_checkpoint(APP_LABEL, MIGRATION_NAME, OP_KEY, op.fingerprint(), "other")

    with pytest.raises(ConcurrentMigrationError):
        await _make_migration(op).apply(_empty_state(), schema_editor=editor)

    # Nothing was applied while locked.
    assert await _flags(conn) == {item_id: 0 for item_id in range(1, ROW_COUNT + 1)}


@pytest.mark.asyncio
async def test_rejected_inside_atomic_migration(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    op = RunPythonBatched(OP_KEY, _batch_function(conn))
    migration = _make_migration(op, atomic=True)

    with pytest.raises(TortoiseMigrationError, match="atomic = False"):
        await migration.apply(_empty_state(), schema_editor=_schema_editor(conn, atomic=True))


@pytest.mark.asyncio
async def test_reverse_runs_once_and_clears_checkpoint(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    reverse_calls: list = []

    async def reverse_code(apps, schema_editor):
        reverse_calls.append(1)
        await schema_editor.client.execute_query("UPDATE test_item SET flag = 0")

    op = RunPythonBatched(OP_KEY, _batch_function(conn), reverse_code=reverse_code)
    assert op.reversible
    migration = _make_migration(op)
    state = _empty_state()
    await migration.apply(state, schema_editor=_schema_editor(conn))
    assert await _flags(conn) == {item_id: 1 for item_id in range(1, ROW_COUNT + 1)}

    await migration.unapply(state, schema_editor=_schema_editor(conn))
    assert reverse_calls == [1]
    assert await _flags(conn) == {item_id: 0 for item_id in range(1, ROW_COUNT + 1)}
    assert await _checkpoints(conn) == []


@pytest.mark.asyncio
async def test_reverse_without_reverse_code_is_irreversible(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    op = RunPythonBatched(OP_KEY, _batch_function(conn))
    assert not op.reversible
    migration = _make_migration(op)
    state = _empty_state()
    await migration.apply(state, schema_editor=_schema_editor(conn))

    with pytest.raises(ValueError, match="not reversible"):
        await migration.unapply(state, schema_editor=_schema_editor(conn))


@pytest.mark.asyncio
async def test_initial_cursor_is_used_on_fresh_run(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    calls: list = []
    op = RunPythonBatched(OP_KEY, _batch_function(conn, calls=calls), initial_cursor=2)

    await _make_migration(op).apply(_empty_state(), schema_editor=_schema_editor(conn))

    assert calls == [2, 4, 5]
    # Rows 1-2 were skipped by the caller-supplied starting cursor.
    assert await _flags(conn) == {1: 0, 2: 0, 3: 1, 4: 1, 5: 1}


def test_fingerprint_stability():
    async def process_batch(apps, schema_editor, cursor):
        return None

    op = RunPythonBatched(OP_KEY, process_batch)
    same = RunPythonBatched(OP_KEY, process_batch)
    assert op.fingerprint() == same.fingerprint()
    assert RunPythonBatched("other-key", process_batch).fingerprint() != op.fingerprint()
    assert (
        RunPythonBatched(OP_KEY, process_batch, initial_cursor=5).fingerprint() != op.fingerprint()
    )
    explicit = RunPythonBatched(OP_KEY, process_batch, fingerprint="v1")
    assert explicit.fingerprint() == "v1"


def test_constructor_validation():
    async def process_batch(apps, schema_editor, cursor):
        return None

    with pytest.raises(ValueError):
        RunPythonBatched("", process_batch)
    with pytest.raises(ValueError):
        RunPythonBatched(OP_KEY, "not-callable")
    with pytest.raises(ValueError):
        RunPythonBatched(OP_KEY, process_batch, initial_cursor=object())
    with pytest.raises(ValueError):
        RunPythonBatched(OP_KEY, process_batch, reverse_code="not-callable")


@pytest.mark.asyncio
async def test_requires_migration_name(db_isolated):
    conn = db_isolated.db()
    await _seed_items(conn)
    op = RunPythonBatched(OP_KEY, _batch_function(conn))
    with pytest.raises(TortoiseMigrationError, match="through a Migration"):
        await op.database_forward(APP_LABEL, _empty_state(), _empty_state(), _schema_editor(conn))
