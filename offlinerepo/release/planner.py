# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline release planning for a consistent-snapshot TUF repository.

The planner reads already-signed metadata plus target payloads and the current
object-store generation, then produces an immutable :class:`ReleasePlan`:

1. Objects -- every payload reduced to a content-addressable, versioned key.
   Identical bytes always map to the same key, which is what enables reuse.
2. Dependencies -- the cross references (targets -> target objects, snapshot ->
   targets/delegations, timestamp -> snapshot) that define upload ordering.
3. Visibility -- pointer flips ordered so every prefix is a usable repository.
4. Retention -- objects still referenced by the live release are retained;
   unreferenced objects are reported as garbage but never auto-deleted.
"""

from __future__ import annotations

from tuf.api.metadata import Metadata, Root
from tuf.api.serialization import DeserializationError

from .errors import PlanValidationError
from .model import (
    METADATA_PREFIX,
    TARGETS_PREFIX,
    ArtifactKind,
    ContentObject,
    ReleasePlan,
    StagedRelease,
    SwitchPoint,
    metadata_object_key,
    metadata_pointer_key,
    sha256_digest,
    target_object_key,
)
from .objectstore import ObjectStore

TOP_LEVEL_ROLES = ("root", "targets", "snapshot", "timestamp")


class _PlanBuilder:
    def __init__(
        self, staged: StagedRelease, store: ObjectStore, plan_id: str
    ) -> None:
        self._staged = staged
        self._store = store
        self._plan_id = plan_id
        self._objects: dict[str, ContentObject] = {}
        self._deps: dict[str, set[str]] = {}
        self._role_keys: dict[str, str] = {}
        self._parsed: dict[str, Metadata] = {}

    def build(self) -> ReleasePlan:
        self._parse_and_check_roles()
        self._collect_metadata_objects()
        self._collect_target_objects()
        self._wire_dependencies()
        uploads = self._topological_uploads()
        switches = self._build_switches()
        return ReleasePlan(
            plan_id=self._plan_id,
            base_root_version=self._parsed["root"].signed.version,
            uploads=tuple(uploads),
            switch_order=tuple(switches),
            expected_etags=self._expected_etags(switches),
            retained_keys=self._retained_keys(),
            garbage_keys=self._garbage_keys(),
        )

    def _parse_and_check_roles(self) -> None:
        for role in TOP_LEVEL_ROLES:
            if role not in self._staged.metadata:
                msg = f"staged release missing required role {role!r}"
                raise PlanValidationError(msg)
        for role, data in self._staged.metadata.items():
            md = Metadata.from_bytes(data)
            expected = "targets" if role not in TOP_LEVEL_ROLES else role
            if md.signed.type != expected:
                msg = (
                    f"role name {role!r} does not match signed type "
                    f"{md.signed.type!r}"
                )
                raise PlanValidationError(msg)
            self._parsed[role] = md

    def _add_object(self, obj: ContentObject) -> None:
        existing = self._objects.get(obj.key)
        if existing is not None and existing.data != obj.data:
            msg = f"object key collision with differing content: {obj.key}"
            raise PlanValidationError(msg)
        if existing is None:
            self._objects[obj.key] = obj
            self._deps.setdefault(obj.key, set())

    def _collect_metadata_objects(self) -> None:
        for role, data in self._staged.metadata.items():
            version = self._parsed[role].signed.version
            key = metadata_object_key(role, version)
            obj = ContentObject(
                key=key,
                data=data,
                digest=sha256_digest(data),
                length=len(data),
                role=role,
                version=version,
                kind=ArtifactKind.METADATA,
            )
            self._add_object(obj)
            self._role_keys[role] = key

    def _collect_target_objects(self) -> None:
        for path, data in self._staged.targets.items():
            digest = sha256_digest(data)
            key = target_object_key(path, digest)
            self._add_object(
                ContentObject(
                    key=key,
                    data=data,
                    digest=digest,
                    length=len(data),
                    target_path=path,
                    kind=ArtifactKind.TARGET,
                )
            )

    def _add_dependency(self, dependent: str, required: str) -> None:
        if dependent != required:
            self._deps.setdefault(dependent, set()).add(required)
            self._deps.setdefault(required, set())

    def _wire_dependencies(self) -> None:
        for role, md in self._parsed.items():
            role_key = self._role_keys[role]
            signed = md.signed
            if signed.type == "targets":
                self._wire_targets(role, role_key, signed)
            elif signed.type == "snapshot":
                self._wire_snapshot(role_key, signed)
            elif signed.type == "timestamp":
                self._wire_timestamp(role_key, signed)
            elif signed.type == "root":
                self._wire_root(role_key, signed)

    def _wire_targets(self, role: str, role_key: str, signed: object) -> None:
        for path, target_file in signed.targets.items():  # type: ignore[attr-defined]
            digest = target_file.hashes["sha256"]
            target_key = target_object_key(path, digest)
            if target_key not in self._objects:
                msg = (
                    f"{role} references target {path!r} absent from the "
                    "staged release"
                )
                raise PlanValidationError(msg)
            self._add_dependency(role_key, target_key)

    def _wire_snapshot(self, role_key: str, snapshot: object) -> None:
        for meta_name, metafile in snapshot.meta.items():  # type: ignore[attr-defined]
            referenced_role = meta_name.removesuffix(".json")
            ref_key = self._role_keys.get(referenced_role)
            if ref_key is None:
                msg = (
                    "snapshot references metadata not in release: "
                    f"{meta_name}"
                )
                raise PlanValidationError(msg)
            ref_version = self._objects[ref_key].version
            if ref_version != metafile.version:
                msg = (
                    f"snapshot pins {meta_name} v{metafile.version} but "
                    f"staged version is {ref_version}"
                )
                raise PlanValidationError(msg)
            self._add_dependency(role_key, ref_key)

    def _wire_timestamp(self, role_key: str, timestamp: object) -> None:
        snapshot_meta = timestamp.snapshot_meta  # type: ignore[attr-defined]
        snapshot_key = self._role_keys["snapshot"]
        if self._objects[snapshot_key].version != snapshot_meta.version:
            msg = "timestamp snapshot version does not match staged snapshot"
            raise PlanValidationError(msg)
        self._add_dependency(role_key, snapshot_key)

    def _wire_root(self, role_key: str, root: Root) -> None:
        for role in root.roles:
            ref_key = self._role_keys.get(role)
            if ref_key is None:
                msg = f"root lists role {role!r} not present in the release"
                raise PlanValidationError(msg)
            self._add_dependency(role_key, ref_key)

    def _topological_uploads(self) -> list[ContentObject]:
        resolved: list[ContentObject] = []
        permanent: set[str] = set()
        temporary: set[str] = set()

        def visit(node: str, trail: tuple[str, ...]) -> None:
            if node in permanent:
                return
            if node in temporary:
                cycle = " -> ".join([*trail, node])
                raise PlanValidationError(f"dependency cycle: {cycle}")
            temporary.add(node)
            for required in sorted(self._deps[node]):
                visit(required, (*trail, node))
            temporary.remove(node)
            permanent.add(node)
            resolved.append(self._objects[node])

        for key in sorted(self._objects):
            visit(key, ())
        return resolved

    def _delegated_roles(self) -> list[str]:
        return [
            role
            for role in self._staged.metadata
            if role not in TOP_LEVEL_ROLES
        ]

    def _build_switches(self) -> list[SwitchPoint]:
        order = ["root", "targets", *self._delegated_roles(), "snapshot"]
        points = [
            SwitchPoint(
                name=f"switch:{role}",
                pointer_key=metadata_pointer_key(role),
                content_key=self._role_keys[role],
            )
            for role in order
        ]
        points.append(
            SwitchPoint(
                name="switch:timestamp",
                pointer_key=metadata_pointer_key("timestamp"),
                content_key=self._role_keys["timestamp"],
            )
        )
        return points

    def _expected_etags(
        self, switches: list[SwitchPoint]
    ) -> dict[str, str]:
        current = self._store.snapshot_etags()
        return {
            point.pointer_key: current.get(point.pointer_key)
            for point in switches
        }

    def _role_pointer_names(self) -> list[str]:
        return [*TOP_LEVEL_ROLES, *self._delegated_roles()]

    def _parse_stored(self, key: str) -> Metadata | None:
        """Parse stored metadata; return None if it is not metadata bytes."""
        try:
            return Metadata.from_bytes(self._store.get(key))
        except DeserializationError:
            return None

    def _expand_metadata(
        self, signed: object, live: set[str], frontier: list[str]
    ) -> None:
        if signed.type == "snapshot":
            for name, metafile in signed.meta.items():  # type: ignore[attr-defined]
                role_key = metadata_object_key(
                    name.removesuffix(".json"), metafile.version
                )
                if role_key not in live:
                    frontier.append(role_key)
        elif signed.type == "timestamp":
            snap_key = metadata_object_key(
                "snapshot", signed.snapshot_meta.version  # type: ignore[attr-defined]
            )
            if snap_key not in live:
                frontier.append(snap_key)

    def _live_metadata_closure(self) -> set[str]:
        """Metadata objects reachable from the current role pointers.

        Expansion follows timestamp -> snapshot -> the exact targets/
        delegated versions the snapshot pins. Older metadata versions are not
        part of this set (they are retained separately for rollback).
        """
        live: set[str] = set()
        frontier: list[str] = []
        for role in self._role_pointer_names():
            pointer = metadata_pointer_key(role)
            if self._store.exists(pointer):
                target = self._store.resolve_pointer(pointer)
                live.add(target)
                frontier.append(target)

        while frontier:
            key = frontier.pop()
            if not self._store.exists(key) or key in live:
                continue
            live.add(key)
            md = self._parse_stored(key)
            if md is not None:
                self._expand_metadata(md.signed, live, frontier)
        return live

    def _live_closure(self) -> set[str]:
        """Live metadata plus the target objects the current release uses.

        Only the *current* targets/delegated versions contribute target
        references: a target removed from the current release is not kept
        alive merely because an old, retained metadata version listed it.
        """
        live = self._live_metadata_closure()
        for key in list(live):
            md = self._parse_stored(key)
            if md is None or md.signed.type != "targets":
                continue
            for target_file in md.signed.targets.values():
                for path in target_file.get_prefixed_paths():
                    live.add(f"targets/{path}")
        return live

    def _retained_keys(self) -> frozenset[str]:
        """Everything that must survive the release.

        All versioned metadata is retained for rollback and audit even once a
        pointer moves on. A target object is retained while any live targets
        metadata still references it (the live closure).
        """
        live = self._live_closure()
        retained = {
            key
            for key in self._store.list_keys()
            if (
                key.startswith(METADATA_PREFIX)
                and not ObjectStore.is_pointer(key)
            )
        }
        retained.update(key for key in live if key.startswith(TARGETS_PREFIX))
        return frozenset(retained)

    def _garbage_keys(self) -> frozenset[str]:
        """Target objects no longer referenced by any live metadata.

        Only target content can become garbage here. Versioned metadata is
        intentionally retained, and nothing is deleted automatically: garbage
        collection is a separate, explicit operator action.
        """
        live = self._live_closure()
        return frozenset(
            key
            for key in self._store.list_keys()
            if key.startswith(TARGETS_PREFIX) and key not in live
        )


def build_plan(
    staged: StagedRelease, store: ObjectStore, *, plan_id: str
) -> ReleasePlan:
    """Build an immutable, content-addressed release plan."""
    return _PlanBuilder(staged, store, plan_id).build()
