"""
Persistent, append-only storage for offline review snapshots.

Each snapshot is written as its own JSON file under a review directory. Files
are never rewritten in place: a historical correction produces a *new*
snapshot file, so the exact inputs behind every past daily report remain
available for later recomputation and dispute resolution.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from pip_audit._offline.model import (
    AdvisoryRecord,
    Snapshot,
    utcnow,
)

SNAPSHOT_SUFFIX = ".snapshot.json"


class SnapshotStoreError(Exception):
    """Raised when a snapshot cannot be read or written."""


class SnapshotStore:
    """
    A directory-backed, append-only collection of `Snapshot` objects.
    """

    def __init__(self, directory: Path):
        """Create a store backed by the given review directory."""
        self._directory = Path(directory)

    @property
    def directory(self) -> Path:
        """The directory in which snapshot files are stored."""
        return self._directory

    def _path_for(self, snapshot_id: str) -> Path:
        """Return the on-disk path used for the given snapshot ID."""
        # Keep IDs filesystem-safe while remaining human readable.
        safe = "".join(char if char.isalnum() or char in ".-_-" else "_" for char in snapshot_id)
        return self._directory / f"{safe}{SNAPSHOT_SUFFIX}"

    def save(self, snapshot: Snapshot) -> Path:
        """
        Persist `snapshot` atomically, refusing to overwrite an existing one.
        """
        self._directory.mkdir(parents=True, exist_ok=True)
        destination = self._path_for(snapshot.id)
        if destination.exists():
            raise SnapshotStoreError(f"refusing to overwrite existing snapshot: {snapshot.id!r}")

        payload = json.dumps(snapshot.to_dict(), indent=2, sort_keys=True)
        with NamedTemporaryFile("w", delete=False, dir=self._directory, suffix=".tmp") as temporary:
            temporary.write(payload)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary.name, destination)
        return destination

    def load(self, snapshot_id: str) -> Snapshot:
        """Load a single snapshot by ID."""
        path = self._path_for(snapshot_id)
        if not path.exists():
            raise SnapshotStoreError(f"snapshot not found: {snapshot_id!r}")
        return self._read(path)

    def load_path(self, path: Path) -> Snapshot:
        """Load a snapshot from an explicit file path."""
        return self._read(Path(path))

    def _read(self, path: Path) -> Snapshot:
        """Read and decode a snapshot file, wrapping failures uniformly."""
        try:
            with path.open("r", encoding="utf-8") as handle:
                return Snapshot.from_dict(json.load(handle))
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
            raise SnapshotStoreError(f"failed to read snapshot {path}: {exc}") from exc

    def list_snapshots(self) -> list[Snapshot]:
        """Return all snapshots ordered by their creation time."""
        if not self._directory.exists():
            return []
        snapshots = [self._read(path) for path in self._directory.glob(f"*{SNAPSHOT_SUFFIX}")]
        snapshots.sort(key=lambda snapshot: (snapshot.created_at, snapshot.id))
        return snapshots

    def latest(self) -> Snapshot | None:
        """Return the most recently created snapshot, if any."""
        snapshots = self.list_snapshots()
        return snapshots[-1] if snapshots else None

    def record_correction(
        self,
        previous: Snapshot,
        corrected_advisories: list[AdvisoryRecord],
        *,
        new_id: str,
        created_at: datetime | None = None,
        description: str = "",
    ) -> Snapshot:
        """
        Persist a new snapshot that supersedes `previous` with corrections.

        The original snapshot file is left untouched; only the new, corrected
        snapshot is appended.
        """
        successor = previous.with_corrections(
            corrected_advisories,
            new_id=new_id,
            created_at=created_at or utcnow(),
            description=description,
        )
        self.save(successor)
        return successor
