# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""End-to-end demonstration of the offline TUF release planner/executor.

Run from this directory:

    python demo_offline_release.py

Everything runs in memory against a fake object store; the real
``tuf.ngclient.Updater`` is used as the "existing client" so no network or
manual step is involved.
"""

from __future__ import annotations

from release.errors import StaleRootPlanError
from release.executor import PublishExecutor
from release.model import metadata_pointer_key
from release.objectstore import ObjectStore
from release.planner import build_plan
from release.signing import ReleaseBuilder, RepoKeyring
from release.verifier import SwitchPointAuditor, verify_mirror_with_client


def heading(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> None:
    store = ObjectStore()
    builder = ReleaseBuilder(RepoKeyring.generate())

    heading("1. First offline release, verified at every visibility point")
    first = builder.build_release(
        {"project/app-1.0.0.bin": b"release-one", "index.txt": b"index-v1"}
    )
    plan = build_plan(first, store, plan_id="release-1")
    auditor = SwitchPointAuditor(
        first.metadata["root"],
        ["project/app-1.0.0.bin", "index.txt"],
    )
    report = PublishExecutor(store).execute(plan, verify_callback=auditor)
    print("switch order:", report.switches)
    print("internal invariant checks:", auditor.invariant_checks)
    print("full client refresh+download at:", auditor.client_checks)

    heading("2. Second release keeps the old target version reachable")
    second = builder.build_release({"project/app-2.0.0.bin": b"release-two"})
    plan2 = build_plan(second, store, plan_id="release-2")
    report2 = PublishExecutor(store).execute(plan2)
    fetched = verify_mirror_with_client(
        store,
        second.metadata["root"],
        [
            "project/app-1.0.0.bin",
            "project/app-2.0.0.bin",
            "index.txt",
        ],
    )
    print("client can still read old and new targets:")
    for path, data in fetched.items():
        print(f"  {path} -> {data.decode()}")
    print("objects reused without rewrite:", report2.reused)

    heading("3. Concurrent publish rejects a plan built on a stale root")
    stale_plan = build_plan(
        builder.build_release({"project/app-2.0.0.bin": b"concurrent-a"}),
        store,
        plan_id="stale",
    )
    concurrent = builder.build_release(
        {"project/app-2.0.0.bin": b"concurrent-b"}, bump_root=True
    )
    PublishExecutor(store).execute(
        build_plan(concurrent, store, plan_id="concurrent")
    )
    try:
        PublishExecutor(store).execute(stale_plan)
    except StaleRootPlanError as exc:
        print("stale plan refused before any pointer move:")
        print(" ", str(exc).split(";")[0])

    heading("4. Partial object writes are retried idempotently")
    retry_store = ObjectStore()
    retry_builder = ReleaseBuilder(RepoKeyring.generate())
    retry_release = retry_builder.build_release({"project/app.bin": b"hello"})
    retry_plan = build_plan(retry_release, retry_store, plan_id="retry")
    for obj in retry_plan.uploads[:2]:
        retry_store.fail_puts(obj.key, times=1)
    retry_report = PublishExecutor(retry_store, max_attempts=3).execute(
        retry_plan
    )
    retried = [u for u in retry_report.uploads if u.attempts > 1]
    print("recovered after transient failures:")
    for record in retried:
        print(f"  {record.key} attempts={record.attempts}")
    verify_mirror_with_client(
        retry_store, retry_release.metadata["root"], ["project/app.bin"]
    )
    print("client read succeeded after retries")

    heading("5. No content change reuses existing objects")
    reuse_release = retry_builder.build_release({"project/app.bin": b"hello"})
    reuse_plan = build_plan(reuse_release, retry_store, plan_id="reuse")
    reuse_report = PublishExecutor(retry_store).execute(reuse_plan)
    print("reused:", reuse_report.reused)
    print("freshly written metadata:", reuse_report.uploaded)

    heading("6. Retention: old versions stay until explicitly collected")
    retention_store = ObjectStore()
    retention_builder = ReleaseBuilder(RepoKeyring.generate())
    rel_one = retention_builder.build_release(
        {"project/app-1.0.0.bin": b"one", "index.txt": b"idx"}
    )
    PublishExecutor(retention_store).execute(
        build_plan(rel_one, retention_store, plan_id="retention-1")
    )
    rel_two = retention_builder.build_release(
        {"project/app-2.0.0.bin": b"two"}
    )
    PublishExecutor(retention_store).execute(
        build_plan(rel_two, retention_store, plan_id="retention-2")
    )
    rel_three = retention_builder.build_release(
        {"project/app-2.0.0.bin": b"two"},
        removed_paths=frozenset({"project/app-1.0.0.bin"}),
    )
    PublishExecutor(retention_store).execute(
        build_plan(rel_three, retention_store, plan_id="retention-3")
    )
    post = build_plan(rel_three, retention_store, plan_id="post-remove")
    print("garbage reported (never auto-deleted):", sorted(post.garbage_keys))
    print("all garbage still physically present:",
          all(retention_store.exists(k) for k in post.garbage_keys))
    versioned = [
        key for key in retention_store.list_keys()
        if key.startswith("metadata/") and key[9:10].isdigit()
    ]
    print(
        "versioned metadata retained for rollback:",
        len(versioned),
        "objects",
    )
    print("live timestamp pointer:",
          retention_store.resolve_pointer(metadata_pointer_key("timestamp")))


if __name__ == "__main__":
    main()
