# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

from release.executor import PublishExecutor
from release.objectstore import ObjectStore
from release.planner import build_plan
from release.signing import ReleaseBuilder
from release.verifier import SwitchPointAuditor, verify_mirror_with_client


def _publish(
    builder: ReleaseBuilder,
    store: ObjectStore,
    targets: dict[str, bytes],
    plan_id: str,
    **kwargs: object,
):
    staged = builder.build_release(targets, **kwargs)  # type: ignore[arg-type]
    return staged, PublishExecutor(store).execute(
        build_plan(staged, store, plan_id=plan_id)
    )


def test_client_reads_full_release_after_timestamp_switch(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    staged = builder.build_release(
        {"project/app.bin": b"v1", "index.txt": b"idx"}
    )
    plan = build_plan(staged, store, plan_id="r1")
    auditor = SwitchPointAuditor(
        staged.metadata["root"], ["project/app.bin", "index.txt"]
    )
    PublishExecutor(store).execute(plan, verify_callback=auditor)
    assert auditor.invariant_checks == [
        "switch:root",
        "switch:targets",
        "switch:project",
        "switch:snapshot",
    ]
    assert auditor.client_checks == ["switch:timestamp"]


def test_old_target_version_remains_readable(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    first, _ = _publish(
        builder, store,
        {"project/app-1.0.0.bin": b"one", "index.txt": b"idx"},
        "r1",
    )
    second, _ = _publish(
        builder, store, {"project/app-2.0.0.bin": b"two"}, "r2"
    )
    fetched = verify_mirror_with_client(
        store,
        second.metadata["root"],
        [
            "project/app-1.0.0.bin",
            "project/app-2.0.0.bin",
            "index.txt",
        ],
    )
    assert fetched["project/app-1.0.0.bin"] == b"one"
    assert fetched["project/app-2.0.0.bin"] == b"two"
    assert first.metadata["root"]  # bootstrap remains valid


def test_identical_content_is_reused_not_rewritten(
    builder: ReleaseBuilder, store: ObjectStore
) -> None:
    _publish(builder, store, {"project/app.bin": b"same"}, "r1")
    _, report_two = _publish(
        builder, store, {"project/app.bin": b"same"}, "r2"
    )
    assert any(k.endswith("app.bin") for k in report_two.reused)
    # Only metadata is rewritten on a content-identical re-release.
    assert all(k.startswith("metadata/") for k in report_two.uploaded)
