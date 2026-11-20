# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from tuf.api.metadata import Metadata

from release.errors import ManualInterventionRequired
from release.executor import PublishExecutor
from release.model import metadata_pointer_key
from release.objectstore import ObjectStore
from release.planner import build_plan
from release.signing import ReleaseBuilder


def _plan(builder: ReleaseBuilder, store: ObjectStore):
    staged = builder.build_release({"project/app.bin": b"v1"})
    return staged, build_plan(staged, store, plan_id="r1")


def test_tampered_targets_metadata_is_blocked(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged, _ = _plan(builder, store)
    # Keep the JSON valid but mutate the signed payload without re-signing:
    # the root signature threshold check must now reject the metadata.
    targets = Metadata.from_bytes(staged.metadata["targets"])
    targets.signed.unrecognized_fields["x-tamper"] = "forged"
    staged.metadata["targets"] = targets.to_bytes()
    plan = build_plan(staged, store, plan_id="bad")
    with pytest.raises(ManualInterventionRequired):
        PublishExecutor(store).execute(plan)
    # Blocked before any visibility change.
    assert not store.exists(metadata_pointer_key("timestamp"))


def test_expired_metadata_is_blocked(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged, _ = _plan(builder, store)
    timestamp = Metadata.from_bytes(staged.metadata["timestamp"])
    timestamp.signed.expires = datetime.now(UTC) - timedelta(days=1)
    staged.metadata["timestamp"] = timestamp.to_bytes()
    plan = build_plan(staged, store, plan_id="expired")
    with pytest.raises(ManualInterventionRequired):
        PublishExecutor(store).execute(plan)


def test_bad_snapshot_reference_is_blocked(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged, _ = _plan(builder, store)
    snapshot = Metadata.from_bytes(staged.metadata["snapshot"])
    snapshot.signed.meta["targets.json"].version = 999
    staged.metadata["snapshot"] = snapshot.to_bytes()
    with pytest.raises(ManualInterventionRequired):
        build_plan(staged, store, plan_id="badref")


def test_missing_target_payload_is_blocked(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged, _ = _plan(builder, store)
    del staged.targets["project/app.bin"]
    with pytest.raises(ManualInterventionRequired):
        build_plan(staged, store, plan_id="missing")
