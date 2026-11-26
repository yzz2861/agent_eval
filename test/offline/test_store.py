import json

import pytest

from pip_audit._offline.model import AdvisoryStatus
from pip_audit._offline.store import SnapshotStore, SnapshotStoreError


def test_save_and_load_roundtrip(tmp_path, first_snapshot):
    store = SnapshotStore(tmp_path)
    path = store.save(first_snapshot)
    assert path.exists()
    assert store.load(first_snapshot.id) == first_snapshot


def test_save_refuses_to_overwrite(tmp_path, first_snapshot):
    store = SnapshotStore(tmp_path)
    store.save(first_snapshot)
    with pytest.raises(SnapshotStoreError, match="refusing to overwrite"):
        store.save(first_snapshot)


def test_load_missing_snapshot_raises(tmp_path):
    store = SnapshotStore(tmp_path)
    with pytest.raises(SnapshotStoreError, match="not found"):
        store.load("does-not-exist")


def test_list_snapshots_is_creation_ordered(tmp_path, second_snapshot, first_snapshot):
    store = SnapshotStore(tmp_path)
    store.save(second_snapshot)
    store.save(first_snapshot)
    ids = [snapshot.id for snapshot in store.list_snapshots()]
    assert ids == ["snap-1", "snap-2"]
    assert store.latest().id == "snap-2"


def test_latest_empty_store_is_none(tmp_path):
    assert SnapshotStore(tmp_path).latest() is None


def test_corrupt_snapshot_raises_store_error(tmp_path, first_snapshot):
    store = SnapshotStore(tmp_path)
    path = store.save(first_snapshot)
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(SnapshotStoreError, match="failed to read"):
        store.load(first_snapshot.id)


def test_snapshot_files_are_plain_json_with_schema(tmp_path, first_snapshot):
    store = SnapshotStore(tmp_path)
    path = store.save(first_snapshot)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["id"] == "snap-1"


def test_record_correction_appends_without_touching_original(
    tmp_path, first_snapshot, corrected_late, timestamps
):
    store = SnapshotStore(tmp_path)
    store.save(first_snapshot)
    successor = store.record_correction(
        first_snapshot,
        [corrected_late],
        new_id="snap-3",
        created_at=timestamps["nov5"],
        description="correction",
    )

    assert successor.id == "snap-3"
    assert successor.advisory_index()["PYSEC-LATE"].status is AdvisoryStatus.Corrected
    # The original file remains the unmodified first snapshot.
    assert store.load("snap-1") == first_snapshot
    assert {snapshot.id for snapshot in store.list_snapshots()} == {"snap-1", "snap-3"}
