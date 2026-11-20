# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import pytest

from release.errors import StaleRootPlanError, TransientStorageError
from release.executor import PublishExecutor
from release.objectstore import ObjectStore
from release.planner import build_plan
from release.signing import ReleaseBuilder
from release.verifier import verify_mirror_with_client


def test_stale_root_plan_is_rejected_before_any_switch(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    first = builder.build_release({"a.txt": b"one"})
    PublishExecutor(store).execute(build_plan(first, store, plan_id="r1"))

    stale = build_plan(
        builder.build_release({"a.txt": b"two"}), store, plan_id="stale"
    )
    concurrent = builder.build_release(
        {"a.txt": b"two"}, bump_root=True
    )
    PublishExecutor(store).execute(
        build_plan(concurrent, store, plan_id="concurrent")
    )

    with pytest.raises(StaleRootPlanError):
        PublishExecutor(store).execute(stale)


def test_transient_partial_writes_are_retried(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release({"project/app.bin": b"hello"})
    plan = build_plan(staged, store, plan_id="r1")
    for obj in plan.uploads[:2]:
        store.fail_puts(obj.key, times=1)

    report = PublishExecutor(store, max_attempts=3).execute(plan)
    retried = [u for u in report.uploads if u.attempts == 2]
    assert len(retried) == 2
    fetched = verify_mirror_with_client(
        store, staged.metadata["root"], ["project/app.bin"]
    )
    assert fetched["project/app.bin"] == b"hello"


def test_retry_gives_up_after_max_attempts(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release({"project/app.bin": b"hello"})
    plan = build_plan(staged, store, plan_id="r1")
    target = plan.uploads[0]
    store.fail_puts(target.key, times=5)
    with pytest.raises(TransientStorageError):
        PublishExecutor(store, max_attempts=2).execute(plan)
    # No pointer moved because content staging failed first.
    assert not store.exists("metadata/timestamp.json")


def test_removed_target_becomes_garbage_but_is_not_deleted(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    one = builder.build_release(
        {"project/app-1.0.0.bin": b"one", "index.txt": b"idx"}
    )
    PublishExecutor(store).execute(build_plan(one, store, plan_id="r1"))
    two = builder.build_release({"project/app-2.0.0.bin": b"two"})
    PublishExecutor(store).execute(build_plan(two, store, plan_id="r2"))
    three = builder.build_release(
        {"project/app-2.0.0.bin": b"two"},
        removed_paths=frozenset({"project/app-1.0.0.bin"}),
    )
    PublishExecutor(store).execute(build_plan(three, store, plan_id="r3"))
    post = build_plan(three, store, plan_id="post")

    assert [k for k in post.garbage_keys if "app-1.0.0" in k]
    assert all(store.exists(k) for k in post.garbage_keys)
    versioned = [
        k for k in store.list_keys()
        if k.startswith("metadata/") and k[9:10].isdigit()
    ]
    assert versioned  # old metadata retained for rollback
