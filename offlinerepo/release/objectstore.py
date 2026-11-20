# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""In-memory, content-addressable fake object store.

Models S3/GCS behaviour without network access. Immutable artifacts are
written with :meth:`put_if_absent` so identical content is shared and a partial
write never lands at a visible key; the small set of mutable role pointers is
flipped with compare-and-swap semantics carrying opaque etags.

:meth:`fail_puts` injects transient failures to demonstrate idempotent retry.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from tuf.api.exceptions import DownloadHTTPError

from .errors import StaleRootPlanError, TransientStorageError
from .model import METADATA_PREFIX


@dataclass
class StoredObject:
    """An immutable blob with its bookkeeping metadata."""

    data: bytes
    etag: str


class StorageConditionError(StaleRootPlanError):
    """Raised when a compare-and-swap pointer update loses the race."""


class ObjectStore:
    """Thread-safe content-addressable key/value store."""

    def __init__(self) -> None:
        self._objects: dict[str, StoredObject] = {}
        self._fail_until: dict[str, int] = {}
        self._lock = threading.RLock()

    def fail_puts(self, key: str, times: int = 1) -> None:
        """Make the next ``times`` writes of ``key`` raise a transient error."""
        with self._lock:
            self._fail_until[key] = self._fail_until.get(key, 0) + times

    def _consume_failure(self, key: str) -> None:
        remaining = self._fail_until.get(key, 0)
        if remaining > 0:
            self._fail_until[key] = remaining - 1
            raise TransientStorageError(
                f"simulated transient storage failure for {key}"
            )

    def put_if_absent(self, key: str, data: bytes) -> str:
        """Write immutable ``data`` unless an identical object already exists.

        Returns the etag. A differing object at the same key is a fatal
        content-address collision, never a silent overwrite.
        """
        with self._lock:
            self._consume_failure(key)
            existing = self._objects.get(key)
            if existing is not None:
                if existing.data != data:
                    raise KeyError(
                        f"content-address collision at {key}: refusing to "
                        "overwrite an immutable object"
                    )
                return existing.etag
            etag = self._mint_etag(key)
            self._objects[key] = StoredObject(data=data, etag=etag)
            return etag

    def _mint_etag(self, key: str) -> str:
        return f'"etag-{len(self._objects) + 1}-{key}"'

    def get(self, key: str) -> bytes:
        """Return object bytes or raise a 404-style error."""
        with self._lock:
            try:
                return self._objects[key].data
            except KeyError:
                raise DownloadHTTPError(
                    f"object not found: {key}", status_code=404
                ) from None

    def exists(self, key: str) -> bool:
        """Return whether an object currently exists."""
        with self._lock:
            return key in self._objects

    def etag(self, key: str) -> str | None:
        """Return the current etag of an object, or None."""
        with self._lock:
            obj = self._objects.get(key)
            return None if obj is None else obj.etag

    def put_pointer(
        self,
        pointer: str,
        content_key: str,
        expected_etag: str | None,
    ) -> str:
        """Atomically point ``pointer`` at ``content_key`` if the etag matches.

        ``expected_etag=None`` means the pointer must not exist yet. A mismatch
        means another writer won the race and the caller's root plan is stale.
        """
        with self._lock:
            self._consume_failure(pointer)
            current = self._objects.get(pointer)
            current_etag = None if current is None else current.etag
            if current_etag != expected_etag:
                raise StorageConditionError(
                    f"pointer {pointer} changed since planning: expected "
                    f"etag {expected_etag!r}, found {current_etag!r}"
                )
            if not self.exists(content_key):
                raise KeyError(
                    f"cannot point {pointer} at absent object {content_key}"
                )
            record = StoredObject(
                data=content_key.encode("utf-8"),
                etag=self._mint_etag(pointer),
            )
            self._objects[pointer] = record
            return record.etag

    def resolve_pointer(self, pointer: str) -> str:
        """Return the content key a pointer currently references."""
        return self.get(pointer).decode("utf-8")

    def list_keys(self) -> list[str]:
        """Return all stored object keys in sorted order."""
        with self._lock:
            return sorted(self._objects)

    def snapshot_etags(self) -> dict[str, str]:
        """Return a read-only ``key -> etag`` view for plan generation."""
        with self._lock:
            return {key: obj.etag for key, obj in self._objects.items()}

    @staticmethod
    def is_pointer(key: str) -> bool:
        """Return whether ``key`` is a non-versioned role pointer.

        Pointers live under ``metadata/`` with a bare role name (e.g.
        ``metadata/timestamp.json``); versioned objects start with a digit
        (e.g. ``metadata/3.timestamp.json``).
        """
        if not key.startswith(METADATA_PREFIX) or not key.endswith(".json"):
            return False
        stem = key.removeprefix(METADATA_PREFIX).removesuffix(".json")
        return not stem[:1].isdigit()
