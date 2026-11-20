# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Client-side verification against the in-memory fake object store.

A FetcherInterface maps TUF URLs back to object-store keys. The real
``tuf.ngclient.Updater`` then runs the full verification flow with no network.

Under consistent snapshots a client only ever observes a repository through
the non-versioned ``timestamp.json`` pointer. The earlier role-pointer flips in
a release are therefore *internal* steps; the timestamp flip is the single
client-visible publication point. :class:`SwitchPointAuditor` models both:
it asserts structural invariants at internal steps and runs a full client
refresh plus target download at every client-visible point.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .objectstore import ObjectStore

from tuf.api.exceptions import DownloadHTTPError
from tuf.ngclient import Updater
from tuf.ngclient.fetcher import FetcherInterface

from .model import METADATA_PREFIX, TARGETS_PREFIX, metadata_pointer_key

METADATA_URL = "mem://repo/metadata/"
TARGET_URL = "mem://repo/targets/"
TOP_LEVEL = ("root", "targets", "snapshot", "timestamp")


class StoreFetcher(FetcherInterface):
    """Serve TUF metadata and targets from a fake object store."""

    def __init__(self, store: ObjectStore) -> None:
        self._store = store

    def _key_for(self, url: str) -> str:
        if url.startswith(METADATA_URL):
            return METADATA_PREFIX + url[len(METADATA_URL):]
        if url.startswith(TARGET_URL):
            return TARGETS_PREFIX + url[len(TARGET_URL):]
        raise DownloadHTTPError(f"unknown base url {url}", 404)

    def _fetch(self, url: str) -> Iterator[bytes]:
        key = self._key_for(url)
        if not self._store.exists(key):
            raise DownloadHTTPError(f"missing object {key}", 404)
        # Non-versioned role pointers store the referenced content key; follow
        # the indirection so the client reads the actual signed JSON/target.
        if self._store.is_pointer(key):
            yield self._store.get(self._store.resolve_pointer(key))
        else:
            yield self._store.get(key)


def verify_mirror_with_client(
    store: ObjectStore,
    bootstrap_root: bytes,
    target_paths: list[str],
) -> dict[str, bytes]:
    """Run a real Updater end-to-end and return downloaded target bytes.

    Proves that at a client-visible point an existing client can refresh
    metadata and fetch every requested target, fully verifying hashes and
    signatures.
    """
    with tempfile.TemporaryDirectory() as tmp:
        updater = Updater(
            metadata_dir=f"{tmp}/metadata",
            metadata_base_url=METADATA_URL,
            target_dir=f"{tmp}/targets",
            target_base_url=TARGET_URL,
            fetcher=StoreFetcher(store),
            bootstrap=bootstrap_root,
        )
        updater.refresh()
        downloaded: dict[str, bytes] = {}
        for path in target_paths:
            info = updater.get_targetinfo(path)
            if info is None:
                msg = f"client could not find target {path}"
                raise AssertionError(msg)
            local = updater.download_target(info)
            downloaded[path] = Path(local).read_bytes()
        return downloaded


class SwitchPointAuditor:
    """Audit each switch; run the full client at every client-visible point."""

    def __init__(
        self, bootstrap_root: bytes, target_paths: list[str]
    ) -> None:
        self._bootstrap = bootstrap_root
        self._targets = target_paths
        self.client_checks: list[str] = []
        self.invariant_checks: list[str] = []

    def _all_pointers_present(self, store: ObjectStore) -> bool:
        return all(
            store.exists(metadata_pointer_key(role)) for role in TOP_LEVEL
        )

    def _assert_pointer_targets_present(self, store: ObjectStore) -> None:
        for role in TOP_LEVEL:
            pointer = metadata_pointer_key(role)
            if store.exists(pointer):
                target = store.resolve_pointer(pointer)
                if not store.exists(target):
                    msg = f"pointer {pointer} dangles at {target}"
                    raise AssertionError(msg)

    def __call__(self, store: ObjectStore, switch_point: object) -> None:
        """Audit one switch: invariants always, full client when live."""
        self._assert_pointer_targets_present(store)
        name = getattr(switch_point, "name", "switch")
        if self._all_pointers_present(store):
            result = verify_mirror_with_client(
                store, self._bootstrap, self._targets
            )
            if len(result) != len(self._targets):
                msg = "client did not return every requested target"
                raise AssertionError(msg)
            self.client_checks.append(name)
        else:
            self.invariant_checks.append(name)
