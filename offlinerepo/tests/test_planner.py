# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import pytest

from release.errors import PlanValidationError
from release.model import (
    metadata_object_key,
    metadata_pointer_key,
    target_object_key,
)
from release.objectstore import ObjectStore
from release.planner import build_plan
from release.signing import ReleaseBuilder


def test_uploads_are_topologically_ordered(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release(
        {"project/app.bin": b"x", "index.txt": b"i"}
    )
    plan = build_plan(staged, store, plan_id="p")

    keys = [obj.key for obj in plan.uploads]
    # A target object must be uploaded before the metadata that references it.
    targets_md = plan.role_object("targets").key
    index_key = next(k for k in keys if k.endswith("index.txt"))
    assert keys.index(index_key) < keys.index(targets_md)

    # Snapshot is uploaded after the targets roles it pins.
    snapshot_key = plan.role_object("snapshot").key
    project_key = plan.role_object("project").key
    assert keys.index(project_key) < keys.index(snapshot_key)

    # Timestamp is uploaded after the snapshot it references.
    timestamp_key = plan.role_object("timestamp").key
    assert keys.index(snapshot_key) < keys.index(timestamp_key)


def test_switch_order_ends_with_timestamp(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release({"project/app.bin": b"x"})
    plan = build_plan(staged, store, plan_id="p")
    names = [point.name for point in plan.switch_order]
    assert names[0] == "switch:root"
    assert names[-1] == "switch:timestamp"
    assert names == [
        "switch:root",
        "switch:targets",
        "switch:project",
        "switch:snapshot",
        "switch:timestamp",
    ]


def test_object_keys_are_versioned_and_content_addressed(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release({"project/app.bin": b"abc"})
    plan = build_plan(staged, store, plan_id="p")
    assert plan.role_object("timestamp").key == metadata_object_key(
        "timestamp", 1
    )
    target = next(
        obj for obj in plan.uploads if obj.target_path == "project/app.bin"
    )
    assert target.key == target_object_key("project/app.bin", target.digest)


def test_missing_role_is_rejected_before_execution(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release({"project/app.bin": b"x"})
    del staged.metadata["snapshot"]
    with pytest.raises(PlanValidationError):
        build_plan(staged, store, plan_id="broken")


def test_expected_etags_are_none_for_fresh_repo(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release({"project/app.bin": b"x"})
    plan = build_plan(staged, store, plan_id="p")
    assert all(etag is None for etag in plan.expected_etags.values())
    assert metadata_pointer_key("timestamp") in plan.expected_etags
