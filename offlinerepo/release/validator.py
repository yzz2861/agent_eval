# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pre-flight validation run before any visibility switch.

Every condition that could need a human is detected from the immutable plan and
the current store generation, before a single pointer is touched. Checks cover
expiry, positive versions, signature thresholds via the bundled root, delegation
thresholds, cross-metadata references (timestamp -> snapshot -> targets), and
the presence of every object a switch could expose.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import Metadata

from .errors import PlanValidationError, StaleRootPlanError
from .model import ArtifactKind, ReleasePlan

if TYPE_CHECKING:
    from .objectstore import ObjectStore

TOP_LEVEL = ("root", "targets", "snapshot", "timestamp")


def _roles(plan: ReleasePlan) -> dict[str, Metadata]:
    roles: dict[str, Metadata] = {}
    for obj in plan.uploads:
        if obj.kind is ArtifactKind.METADATA and obj.role:
            roles[obj.role] = Metadata.from_bytes(obj.data)
    return roles


def _check_expiry(roles: dict[str, Metadata]) -> None:
    now = datetime.now(UTC)
    expired = [name for name, md in roles.items() if md.signed.expires <= now]
    if expired:
        raise PlanValidationError(
            "metadata already expired; re-sign before release: "
            + ", ".join(sorted(expired))
        )


def _check_versions(roles: dict[str, Metadata]) -> None:
    for name, md in roles.items():
        if md.signed.version <= 0:
            raise PlanValidationError(
                f"role {name!r} has non-positive version"
            )


def _check_top_level_signatures(roles: dict[str, Metadata]) -> None:
    root = roles["root"]
    for name in TOP_LEVEL:
        try:
            root.verify_delegate(name, roles[name])
        except UnsignedMetadataError as exc:
            raise PlanValidationError(
                f"role {name!r} fails root signature threshold: {exc}"
            ) from exc


def _check_delegation_signatures(roles: dict[str, Metadata]) -> None:
    delegated = [name for name in roles if name not in TOP_LEVEL]
    targets = roles["targets"]
    for name in delegated:
        try:
            targets.verify_delegate(name, roles[name])
        except UnsignedMetadataError as exc:
            raise PlanValidationError(
                f"delegated role {name!r} fails targets threshold: {exc}"
            ) from exc


def _check_snapshot(roles: dict[str, Metadata]) -> None:
    snapshot = roles["snapshot"].signed
    for name, md in roles.items():
        if name in {"root", "snapshot", "timestamp"}:
            continue
        ref = snapshot.meta.get(f"{name}.json")
        if ref is None or ref.version != md.signed.version:
            raise PlanValidationError(
                f"snapshot does not pin the bundled {name!r} version"
            )


def _check_timestamp(roles: dict[str, Metadata]) -> None:
    timestamp = roles["timestamp"].signed
    snapshot_version = roles["snapshot"].signed.version
    if timestamp.snapshot_meta.version != snapshot_version:
        raise PlanValidationError(
            "timestamp does not reference the bundled snapshot version"
        )


def _check_targets_present(plan: ReleasePlan) -> None:
    available = {obj.key for obj in plan.uploads}
    roles = _roles(plan)
    for name, md in roles.items():
        if md.signed.type != "targets":
            continue
        for target in md.signed.targets.values():
            for prefixed in target.get_prefixed_paths():
                key = f"targets/{prefixed}"
                if key not in available:
                    raise PlanValidationError(
                        f"targets role {name!r} references absent object {key}"
                    )


def _check_switch_targets_exist(
    plan: ReleasePlan, store: ObjectStore
) -> None:
    """Every pointer target must be staged or already in the store."""
    for point in plan.switch_order:
        if not store.exists(point.content_key) and not any(
            obj.key == point.content_key for obj in plan.uploads
        ):
            raise PlanValidationError(
                f"switch {point.name!r} points at missing object "
                f"{point.content_key}"
            )


def _check_store_generation(plan: ReleasePlan, store: ObjectStore) -> None:
    """Fail closed if a pointer moved after the plan was generated."""
    current = store.snapshot_etags()
    for pointer, expected in plan.expected_etags.items():
        if current.get(pointer) != expected:
            raise StaleRootPlanError(
                f"repository generation changed for {pointer!r} after "
                "planning; rebuild the plan from the current root"
            )


def validate_plan(plan: ReleasePlan, store: ObjectStore) -> None:
    """Run every offline, pre-switch check; raise on the first blocker."""
    roles = _roles(plan)
    for required in TOP_LEVEL:
        if required not in roles:
            raise PlanValidationError(
                f"bundle is missing top-level role {required!r}"
            )
    _check_expiry(roles)
    _check_versions(roles)
    _check_top_level_signatures(roles)
    _check_delegation_signatures(roles)
    _check_snapshot(roles)
    _check_timestamp(roles)
    _check_targets_present(plan)
    _check_switch_targets_exist(plan, store)
    _check_store_generation(plan, store)
