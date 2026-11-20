# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import threading

import pytest

from release.errors import TransientStorageError
from release.objectstore import ObjectStore, StorageConditionError


def test_put_if_absent_shares_identical_content(store: ObjectStore) -> None:
    etag_one = store.put_if_absent("content/a", b"same")
    etag_two = store.put_if_absent("content/a", b"same")
    assert etag_one == etag_two


def test_content_collision_is_refused(store: ObjectStore) -> None:
    store.put_if_absent("content/a", b"first")
    with pytest.raises(KeyError):
        store.put_if_absent("content/a", b"different")


def test_cas_pointer_rejects_stale_etag(store: ObjectStore) -> None:
    store.put_if_absent("metadata/1.root.json", b"v1")
    etag = store.put_pointer(
        "metadata/root.json", "metadata/1.root.json", expected_etag=None
    )
    store.put_if_absent("metadata/2.root.json", b"v2")
    store.put_pointer(
        "metadata/root.json", "metadata/2.root.json", expected_etag=etag
    )
    # The original etag is now stale and must be rejected.
    with pytest.raises(StorageConditionError):
        store.put_pointer(
            "metadata/root.json",
            "metadata/1.root.json",
            expected_etag=etag,
        )


def test_failure_injection_then_retry_succeeds(store: ObjectStore) -> None:
    store.fail_puts("content/a", times=2)
    for _ in range(2):
        with pytest.raises(TransientStorageError):
            store.put_if_absent("content/a", b"data")
    assert store.put_if_absent("content/a", b"data")
    assert store.get("content/a") == b"data"


def test_concurrent_cas_only_one_wins(store: ObjectStore) -> None:
    store.put_if_absent("metadata/1.timestamp.json", b"v1")
    outcomes: list[str] = []

    def flip() -> None:
        try:
            store.put_pointer(
                "metadata/timestamp.json",
                "metadata/1.timestamp.json",
                expected_etag=None,
            )
            outcomes.append("won")
        except StorageConditionError:
            outcomes.append("lost")

    threads = [threading.Thread(target=flip) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("won") == 1
    assert outcomes.count("lost") == 7
