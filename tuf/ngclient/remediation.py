# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline firmware remediation planning for verified TUF metadata.

The module turns TUF verified ``TargetFile`` descriptions into per-device
install or rollback plans. It is intended for the controlled case where a
device cannot reach the online repository and support staff must apply a
known target from local, already verified metadata.

Two inputs are intentionally separate:

* TUF metadata is loaded into :class:`VerifiedTargetView` instances. Each view
  is a closed, self-consistent repository state: snapshot metadata pins the
  version and hashes of the targets roles it contains. Targets from an
  archived view and delegated roles from a newer view cannot be mixed.
* Caller supplied :class:`CompatibilityTable` data describes which target is
  acceptable for which device group, installed version and use. Signed target
  metadata may restrict those uses further. It is never widened by the
  compatibility table.

Example::

    current = VerifiedTargetView.from_directory(
        "current", "repo/current", kind="current"
    )
    archive = VerifiedTargetView.from_directory(
        "archive", "repo/archive", kind="archive", allow_expired=True
    )
    planner = RemediationPlanner(
        [current, archive],
        CompatibilityTable.from_json_file("compatibility.json"),
    )
    plan = planner.plan(devices)
    print(plan.render())

``plan.render()`` shows, for the same installed version, the different routes
that each device group is allowed to take.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast
from urllib import parse

from tuf.api.metadata import MetaFile, Snapshot, TargetFile, Targets
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

INSTALL = "install"
ROLLBACK = "rollback"
APPROVED = "approved"
PENDING = "pending"

_USES = frozenset({INSTALL, ROLLBACK})
_REVIEW_STATUSES = frozenset({APPROVED, PENDING})

ViewKind = Literal["current", "archive"]


class RemediationError(ValueError):
    """Raised when remediation inputs are invalid or inconsistent."""


@dataclass(frozen=True)
class VerifiedTarget:
    """A target description and the verified view it came from.

    ``role`` is the targets role that contained the target path and
    ``parent_role`` is the role that delegated to it. The target is only
    returned when the delegation graph in the same view authorizes ``role``
    for the target path.
    """

    target: TargetFile
    role: str
    parent_role: str
    view: str
    view_kind: ViewKind
    snapshot_version: int

    @property
    def path(self) -> str:
        """Return the target path."""
        return self.target.path


@dataclass(frozen=True)
class CompatibilityRule:
    """Caller supplied compatibility constraints for one target.

    Args:
        target: Target path the rule applies to.
        installed_versions: Installed versions from which the target may be
            applied. The special value ``"*"`` matches any installed version.
        uses: Uses (``"install"`` and/or ``"rollback"``) allowed for the
            target. Signed target metadata can only reduce this set.
        version: Optional target version fallback. Used only when the verified
            target description does not carry a ``custom.version`` field.
        review_status: Optional caller review state. A pending state from
            either the caller or signed metadata wins.
        withdrawn: Set to ``True`` when the target must not be installed and
            may only be used for rollback with explicit caller approval.
        allow_pending: Optional per-target override for pending review
            material.
    """

    target: str
    installed_versions: frozenset[str]
    uses: frozenset[str]
    version: str | None = None
    review_status: str | None = None
    withdrawn: bool = False
    allow_pending: bool | None = None

    @classmethod
    def from_dict(
        cls, target: str, data: Mapping[str, object]
    ) -> CompatibilityRule:
        """Create a rule from its JSON compatible representation."""
        allowed = {
            "from",
            "installed_versions",
            "uses",
            "version",
            "review_status",
            "withdrawn",
            "allow_pending",
        }
        unknown = set(data) - allowed
        if unknown:
            raise RemediationError(
                f"unknown compatibility rule fields for {target!r}: "
                f"{sorted(unknown)}"
            )
        if "from" in data and "installed_versions" in data:
            raise RemediationError(
                f"rule for {target!r} must use either 'from' or "
                "'installed_versions', not both"
            )

        from_value = data.get("from", data.get("installed_versions"))
        installed_versions = _string_set(
            from_value, f"compatibility rule for {target!r} 'from'"
        )
        uses = _string_set(
            data.get("uses"), f"compatibility rule for {target!r} 'uses'"
        )
        unknown_uses = uses - _USES
        if unknown_uses:
            raise RemediationError(
                f"unknown uses for {target!r}: {sorted(unknown_uses)}"
            )

        version = _optional_string(
            data.get("version"), f"compatibility rule for {target!r} 'version'"
        )
        review_status = _optional_string(
            data.get("review_status"),
            f"compatibility rule for {target!r} 'review_status'",
        )
        if (
            review_status is not None
            and review_status not in _REVIEW_STATUSES
        ):
            raise RemediationError(
                f"unknown review status for {target!r}: {review_status!r}"
            )

        withdrawn = data.get("withdrawn", False)
        if not isinstance(withdrawn, bool):
            raise RemediationError(
                f"compatibility rule for {target!r} 'withdrawn' must be bool"
            )

        allow_pending = data.get("allow_pending")
        if allow_pending is not None and not isinstance(allow_pending, bool):
            raise RemediationError(
                f"compatibility rule for {target!r} 'allow_pending' "
                "must be bool"
            )

        return cls(
            target=target,
            installed_versions=installed_versions,
            uses=uses,
            version=version,
            review_status=review_status,
            withdrawn=withdrawn,
            allow_pending=allow_pending,
        )


@dataclass(frozen=True)
class CompatibilityTable:
    """Target compatibility rules grouped by device group."""

    device_groups: Mapping[str, Mapping[str, CompatibilityRule]]
    allow_pending: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> CompatibilityTable:
        """Create a table from its JSON compatible representation."""
        allowed = {"schema_version", "allow_pending", "device_groups"}
        unknown = set(data) - allowed
        if unknown:
            raise RemediationError(
                f"unknown compatibility table fields: {sorted(unknown)}"
            )

        schema_version = data.get("schema_version", 1)
        if schema_version != 1:
            raise RemediationError(
                f"unsupported compatibility table schema: {schema_version!r}"
            )

        allow_pending = data.get("allow_pending", False)
        if not isinstance(allow_pending, bool):
            raise RemediationError("'allow_pending' must be bool")

        groups = _expect_dict(
            data.get("device_groups"), "compatibility 'device_groups'"
        )
        parsed_groups: dict[str, dict[str, CompatibilityRule]] = {}
        for group, rules_value in groups.items():
            if not isinstance(group, str) or not group:
                raise RemediationError("device group names must be strings")
            rules = _expect_dict(
                rules_value, f"compatibility rules for group {group!r}"
            )
            parsed_rules: dict[str, CompatibilityRule] = {}
            for target, rule_value in rules.items():
                if not isinstance(target, str) or not target:
                    raise RemediationError(
                        f"target paths for group {group!r} must be strings"
                    )
                parsed_rules[target] = CompatibilityRule.from_dict(
                    target,
                    _expect_dict(
                        rule_value,
                        f"compatibility rule for {group!r}/{target!r}",
                    ),
                )
            if not parsed_rules:
                raise RemediationError(
                    f"device group {group!r} has no compatibility rules"
                )
            parsed_groups[group] = parsed_rules

        if not parsed_groups:
            raise RemediationError("compatibility table has no device groups")

        return cls(parsed_groups, allow_pending)

    @classmethod
    def from_json_file(cls, path: str | Path) -> CompatibilityTable:
        """Load a compatibility table from a JSON file."""
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(_expect_dict(raw, "compatibility table"))

    def rules_for(
        self, group: str
    ) -> Mapping[str, CompatibilityRule] | None:
        """Return the rules for ``group`` or ``None`` if it is unknown."""
        return self.device_groups.get(group)


@dataclass(frozen=True)
class Device:
    """One field device to plan remediation for."""

    device_id: str
    group: str
    installed_version: str

    def __post_init__(self) -> None:
        for name, value in (
            ("device_id", self.device_id),
            ("group", self.group),
            ("installed_version", self.installed_version),
        ):
            if not isinstance(value, str) or not value:
                raise RemediationError(f"device {name} must be a string")


class VerifiedTargetView:
    """A closed, verified repository view used for offline planning.

    A view is loaded from local metadata bytes and verified with
    ``TrustedMetadataSet``. Unlike the online updater, it does not download
    anything: the trusted root, timestamp, snapshot and all reachable
    delegated targets roles must be supplied by the caller.

    By default every targets role referenced by the view must be pinned by a
    hash in snapshot metadata. This prevents a caller from pairing an old
    snapshot with a newer delegated roles file that has the same version
    number but different content. Pass ``require_pinned=False`` only for
    repositories that cannot provide hashes.
    """

    def __init__(
        self,
        name: str,
        kind: ViewKind,
        snapshot_version: int,
        targets: Iterable[VerifiedTarget],
        *,
        stale: bool = False,
    ) -> None:
        if not isinstance(name, str) or not name:
            raise RemediationError("view name must be a non-empty string")
        if kind not in ("current", "archive"):
            raise RemediationError(f"unknown view kind: {kind!r}")
        self.name = name
        self.kind = kind
        self.snapshot_version = snapshot_version
        self.targets = tuple(targets)
        self.stale = stale

    @classmethod
    def load(
        cls,
        name: str,
        metadata: Mapping[str, bytes],
        *,
        kind: ViewKind = "current",
        trusted_root: bytes | None = None,
        reference_time: datetime | None = None,
        allow_expired: bool = False,
        require_pinned: bool = True,
    ) -> VerifiedTargetView:
        """Verify and load a view from in-memory metadata.

        Args:
            name: Human readable view name, used in plans.
            metadata: Mapping of role name to signed metadata bytes. Role
                names may include the ``.json`` suffix.
            kind: ``"current"`` for the active repository, ``"archive"`` for
                a retained repository state.
            trusted_root: Trusted root bytes for this view. If omitted,
                ``metadata["root"]`` is used.
            reference_time: Time to use for metadata expiry checks. This is
                useful when validating an archived view as it existed.
            allow_expired: If true, expiry checks are performed against
                1970-01-01 so that retained, signed material can still be
                planned. The view is then marked as stale.
            require_pinned: Require hashes in snapshot metadata for every
                targets role that is used.

        Raises:
            RemediationError: Metadata is missing or internally inconsistent.
            tuf.api.exceptions.RepositoryError: TUF verification failed.
        """
        files = _normalize_metadata(metadata)
        for required_role in ("timestamp", "snapshot", "targets"):
            if required_role not in files:
                raise RemediationError(
                    f"view {name!r} is missing {required_role!r} metadata"
                )

        if trusted_root is None:
            trusted_root = files.get("root")
        if trusted_root is None:
            raise RemediationError(
                f"view {name!r} needs a trusted root or root metadata"
            )
        if allow_expired and reference_time is not None:
            raise RemediationError(
                "allow_expired and reference_time cannot be used together"
            )

        if allow_expired:
            check_time = datetime(1970, 1, 1, tzinfo=UTC)
        else:
            check_time = reference_time or datetime.now(UTC)

        trusted = TrustedMetadataSet(trusted_root, EnvelopeType.METADATA)
        trusted.reference_time = check_time
        trusted.update_timestamp(files["timestamp"])
        trusted.update_snapshot(files["snapshot"])

        if require_pinned:
            _require_pinned(
                trusted.timestamp.snapshot_meta, "snapshot metadata"
            )
            _require_pinned(
                trusted.snapshot.meta.get(f"{Targets.type}.json"),
                f"{Targets.type} metadata",
            )

        trusted.update_targets(files["targets"])

        loaded = cls._load_delegations(
            trusted, files, require_pinned=require_pinned
        )
        verified_targets = cls._collect_targets(
            name, kind, trusted.snapshot, loaded
        )
        stale = allow_expired or (
            trusted.timestamp.is_expired(datetime.now(UTC))
            or trusted.snapshot.is_expired(datetime.now(UTC))
        )

        return cls(
            name,
            kind,
            trusted.snapshot.version,
            verified_targets,
            stale=stale,
        )

    @classmethod
    def from_directory(
        cls,
        name: str,
        directory: str | Path,
        *,
        kind: ViewKind = "current",
        trusted_root: bytes | None = None,
        reference_time: datetime | None = None,
        allow_expired: bool = False,
        require_pinned: bool = True,
    ) -> VerifiedTargetView:
        """Load a view from a directory of local ``*.json`` metadata files."""
        base = Path(directory)
        metadata: dict[str, bytes] = {}
        for path in sorted(base.glob("*.json")):
            role = parse.unquote(path.stem)
            metadata[role] = path.read_bytes()
        return cls.load(
            name,
            metadata,
            kind=kind,
            trusted_root=trusted_root,
            reference_time=reference_time,
            allow_expired=allow_expired,
            require_pinned=require_pinned,
        )

    @staticmethod
    def _load_delegations(
        trusted: TrustedMetadataSet,
        files: Mapping[str, bytes],
        *,
        require_pinned: bool,
    ) -> dict[tuple[str, str], Targets]:
        loaded: dict[tuple[str, str], Targets] = {
            (Targets.type, "root"): trusted.targets
        }
        pending: list[tuple[str, str]] = [(Targets.type, "root")]
        visited: set[tuple[str, str]] = set()

        while pending:
            role_name, parent_name = pending.pop()
            if (role_name, parent_name) in visited:
                continue
            visited.add((role_name, parent_name))

            role = loaded[(role_name, parent_name)]
            if role.delegations is None:
                continue

            children: list[str] = []
            if role.delegations.roles is not None:
                children.extend(role.delegations.roles)
            if role.delegations.succinct_roles is not None:
                succinct = role.delegations.succinct_roles
                for filename in trusted.snapshot.meta:
                    if not filename.endswith(".json"):
                        continue
                    candidate = filename[: -len(".json")]
                    if succinct.is_delegated_role(candidate):
                        children.append(candidate)

            for child_name in dict.fromkeys(children):
                child_key = (child_name, role_name)
                if child_key in loaded:
                    pending.append(child_key)
                    continue
                data = files.get(child_name)
                if data is None:
                    raise RemediationError(
                        f"missing delegated metadata for {child_name!r} "
                        f"delegated by {role_name!r}"
                    )
                if require_pinned:
                    _require_pinned(
                        trusted.snapshot.meta.get(f"{child_name}.json"),
                        f"{child_name} metadata",
                    )
                loaded[child_key] = trusted.update_delegated_targets(
                    data, child_name, role_name
                )
                pending.append(child_key)

        return loaded

    @staticmethod
    def _collect_targets(
        view_name: str,
        kind: ViewKind,
        snapshot: Snapshot,
        loaded: Mapping[tuple[str, str], Targets],
    ) -> tuple[VerifiedTarget, ...]:
        paths = {
            path for targets in loaded.values() for path in targets.targets
        }
        collected: list[VerifiedTarget] = []
        for path in sorted(paths):
            found = _lookup_target(path, loaded)
            if found is None:
                continue
            role_name, parent_name, target = found
            collected.append(
                VerifiedTarget(
                    target=target,
                    role=role_name,
                    parent_role=parent_name,
                    view=view_name,
                    view_kind=kind,
                    snapshot_version=snapshot.version,
                )
            )
        return tuple(collected)


@dataclass(frozen=True)
class PlannedAction:
    """One verified and caller approved remediation route for a device."""

    device: Device
    use: str
    source: VerifiedTarget
    target_version: str
    review_status: str
    withdrawn: bool
    stale: bool
    controlled: bool
    requires_approval: bool
    reason: str

    @property
    def target(self) -> TargetFile:
        """Return the verified target description."""
        return self.source.target

    def to_dict(self) -> dict[str, object]:
        """Return a JSON compatible representation."""
        return {
            "device_id": self.device.device_id,
            "group": self.device.group,
            "installed_version": self.device.installed_version,
            "use": self.use,
            "target": self.source.target.path,
            "target_version": self.target_version,
            "length": self.source.target.length,
            "hashes": self.source.target.hashes,
            "view": self.source.view,
            "view_kind": self.source.view_kind,
            "snapshot_version": self.source.snapshot_version,
            "review_status": self.review_status,
            "withdrawn": self.withdrawn,
            "stale": self.stale,
            "controlled": self.controlled,
            "requires_approval": self.requires_approval,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DevicePlan:
    """Available routes and the recommended route for one device."""

    device: Device
    available: tuple[PlannedAction, ...]
    recommended: PlannedAction | None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RemediationPlan:
    """A complete, reviewable offline remediation plan."""

    plans: tuple[DevicePlan, ...]
    withdrawn_targets: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON compatible representation."""
        return {
            "withdrawn_targets": list(self.withdrawn_targets),
            "devices": [
                {
                    "device_id": plan.device.device_id,
                    "group": plan.device.group,
                    "installed_version": plan.device.installed_version,
                    "recommended": (
                        plan.recommended.to_dict()
                        if plan.recommended is not None
                        else None
                    ),
                    "available": [
                        action.to_dict() for action in plan.available
                    ],
                    "notes": list(plan.notes),
                }
                for plan in self.plans
            ],
        }

    def render(self) -> str:
        """Render a compact text table suitable for a support runbook."""
        rows: list[tuple[str, ...]] = []
        notes: list[str] = []
        for plan in self.plans:
            label = f"{plan.device.group}/{plan.device.device_id}"
            if plan.available:
                for action in plan.available:
                    rows.append(
                        (
                            label,
                            plan.device.installed_version,
                            action.use.upper(),
                            action.source.target.path,
                            action.target_version,
                            f"{action.source.view}"
                            f"@{action.source.snapshot_version}",
                            _action_flags(action),
                        )
                    )
            else:
                rows.append(
                    (
                        label,
                        plan.device.installed_version,
                        "NONE",
                        "-",
                        "-",
                        "-",
                        "no eligible route",
                    )
                )
            for note in plan.notes:
                notes.append(f"{label}: {note}")

        headers = (
            "group/device",
            "installed",
            "action",
            "target",
            "version",
            "view",
            "flags",
        )
        widths = [
            max([len(headers[index]), *(len(row[index]) for row in rows)])
            for index in range(len(headers))
        ]
        lines = []
        if self.withdrawn_targets:
            lines.append(
                "Withdrawn targets (rollback-only): "
                + ", ".join(self.withdrawn_targets)
            )
            lines.append("")
        lines.append(_format_row(headers, widths))
        lines.extend(_format_row(row, widths) for row in rows)
        if notes:
            lines.append("")
            lines.append("Notes:")
            lines.extend(f"- {note}" for note in notes)
        return "\n".join(lines)


class RemediationPlanner:
    """Plan offline installs and rollbacks against verified views."""

    def __init__(
        self,
        views: Iterable[VerifiedTargetView],
        compatibility: CompatibilityTable,
        *,
        allow_pending: bool | None = None,
    ) -> None:
        self._views = tuple(views)
        if not self._views:
            raise RemediationError("at least one verified view is required")
        view_names = [view.name for view in self._views]
        if len(view_names) != len(set(view_names)):
            raise RemediationError("verified view names must be unique")
        self._compatibility = compatibility
        self._allow_pending = (
            compatibility.allow_pending
            if allow_pending is None
            else allow_pending
        )
        self._withdrawn_targets = self._collect_withdrawn_targets()

    def plan(self, devices: Iterable[Device]) -> RemediationPlan:
        """Return a plan for every device in ``devices``."""
        return RemediationPlan(
            tuple(self._plan_device(device) for device in devices),
            self._withdrawn_targets,
        )

    def _plan_device(self, device: Device) -> DevicePlan:
        notes: list[str] = []
        rules = self._compatibility.rules_for(device.group)
        if rules is None:
            return DevicePlan(
                device,
                (),
                None,
                (f"group {device.group!r} has no compatibility rules",),
            )

        actions: list[PlannedAction] = []
        for view in self._views:
            for source in view.targets:
                rule = rules.get(source.path)
                if rule is None:
                    continue
                action = self._evaluate(device, view, source, rule, notes)
                if action is not None:
                    actions.extend(action)

        actions = _deduplicate(actions)
        actions.sort(
            key=lambda action: _version_key(action.target_version),
            reverse=True,
        )
        actions.sort(
            key=lambda action: (
                action.requires_approval,
                action.controlled,
                0 if action.use == INSTALL else 1,
            )
        )

        recommended = actions[0] if actions else None
        if recommended is None:
            notes.append("no target matches group, installed version and uses")
        withdrawn_note = self._installed_withdrawn_note(device)
        if withdrawn_note is not None:
            notes.append(withdrawn_note)

        return DevicePlan(device, tuple(actions), recommended, tuple(notes))

    def _installed_withdrawn_note(self, device: Device) -> str | None:
        for view in self._views:
            for source in view.targets:
                if not _signed_withdrawn(source.target):
                    continue
                if _signed_version(source.target) == device.installed_version:
                    return (
                        f"installed version {device.installed_version!r} is "
                        f"withdrawn target {source.path!r}; reinstall is not "
                        "offered"
                    )
        return None

    def _evaluate(  # noqa: C901, PLR0917
        self,
        device: Device,
        view: VerifiedTargetView,
        source: VerifiedTarget,
        rule: CompatibilityRule,
        notes: list[str],
    ) -> list[PlannedAction]:
        target = source.target
        signed_version = _signed_version(target)
        if (
            signed_version is not None
            and rule.version is not None
            and signed_version != rule.version
        ):
            raise RemediationError(
                f"version conflict for {source.path!r}: signed metadata has "
                f"{signed_version!r}, compatibility table has "
                f"{rule.version!r}"
            )
        target_version = signed_version or rule.version
        if target_version is None:
            notes.append(
                f"skipped {source.path!r}: target version is unavailable"
            )
            return []

        if not _installed_version_matches(rule, device.installed_version):
            return []

        target_groups = _signed_groups(target)
        if (
            target_groups is not None
            and "*" not in target_groups
            and device.group not in target_groups
        ):
            return []

        review_status = _review_status(target, rule)
        allow_pending = (
            rule.allow_pending
            if rule.allow_pending is not None
            else self._allow_pending
        )
        if review_status == PENDING and not allow_pending:
            notes.append(
                f"skipped pending-review target {source.path!r} "
                "(pending material is disabled)"
            )
            return []

        withdrawn = _signed_withdrawn(target) or rule.withdrawn
        uses = set(rule.uses)
        signed_uses = _signed_uses(target)
        if signed_uses is not None:
            uses &= signed_uses
        if withdrawn:
            uses &= {ROLLBACK}

        comparison = _compare_versions(
            target_version, device.installed_version
        )
        actions: list[PlannedAction] = []
        for use in sorted(uses):
            if use == INSTALL and comparison <= 0:
                continue
            if use == ROLLBACK and comparison >= 0:
                continue
            actions.append(
                PlannedAction(
                    device=device,
                    use=use,
                    source=source,
                    target_version=target_version,
                    review_status=review_status,
                    withdrawn=withdrawn,
                    stale=view.stale,
                    controlled=(
                        source.view_kind == "archive"
                        or view.stale
                        or withdrawn
                        or review_status == PENDING
                    ),
                    requires_approval=review_status == PENDING,
                    reason=_reason(use, source, withdrawn, review_status),
                )
            )
        return actions

    def _collect_withdrawn_targets(self) -> tuple[str, ...]:
        paths: set[str] = set()
        for view in self._views:
            for source in view.targets:
                if _signed_withdrawn(source.target):
                    paths.add(source.path)
        for rules in self._compatibility.device_groups.values():
            for path, rule in rules.items():
                if rule.withdrawn:
                    paths.add(path)
        return tuple(sorted(paths))


def _normalize_metadata(metadata: Mapping[str, bytes]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for key, data in metadata.items():
        role = key[: -len(".json")] if key.endswith(".json") else key
        if not role:
            raise RemediationError("metadata role names must not be empty")
        if role in files:
            raise RemediationError(f"duplicate metadata role: {role!r}")
        if not isinstance(data, bytes):
            raise RemediationError(
                f"metadata for {role!r} must be bytes, not "
                f"{type(data).__name__}"
            )
        files[role] = data
    return files


def _require_pinned(meta: MetaFile | None, label: str) -> None:
    if meta is None:
        raise RemediationError(f"snapshot does not pin {label}")
    if not meta.hashes:
        raise RemediationError(f"snapshot does not pin hashes for {label}")


def _lookup_target(
    path: str, loaded: Mapping[tuple[str, str], Targets]
) -> tuple[str, str, TargetFile] | None:
    pending: list[tuple[str, str]] = [(Targets.type, "root")]
    visited: set[str] = set()

    while pending:
        role_name, parent_name = pending.pop()
        if role_name in visited:
            continue
        targets = loaded.get((role_name, parent_name))
        if targets is None:
            continue

        target = targets.targets.get(path)
        if target is not None:
            return role_name, parent_name, target

        visited.add(role_name)
        if targets.delegations is None:
            continue

        children: list[tuple[str, str]] = []
        for child_name, terminating in (
            targets.delegations.get_roles_for_target(path)
        ):
            if (child_name, role_name) in loaded:
                children.append((child_name, role_name))
            if terminating:
                pending = []
                break
        pending.extend(reversed(children))

    return None


def _expect_dict(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise RemediationError(f"{label} must be an object")
    return cast("Mapping[str, object]", value)


def _string_set(value: object, label: str) -> frozenset[str]:
    if isinstance(value, str):
        items: list[object] = [value]
    elif isinstance(value, list):
        items = list(value)
    else:
        raise RemediationError(f"{label} must be a string or a list")

    result: set[str] = set()
    for item in items:
        if not isinstance(item, str) or not item:
            raise RemediationError(f"{label} must contain non-empty strings")
        result.add(item)
    if not result:
        raise RemediationError(f"{label} must not be empty")
    return frozenset(result)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise RemediationError(f"{label} must be a non-empty string")
    return value


def _custom(target: TargetFile) -> Mapping[str, object]:
    custom = target.custom
    if not isinstance(custom, dict):
        return {}
    return cast("Mapping[str, object]", custom)


def _signed_version(target: TargetFile) -> str | None:
    value = _custom(target).get("version")
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str) or not value:
        raise RemediationError(
            f"custom.version for {target.path!r} must be a string or integer"
        )
    return value


def _signed_uses(target: TargetFile) -> frozenset[str] | None:
    value = _custom(target).get("uses")
    if value is None:
        return None
    uses = _string_set(value, f"custom.uses for {target.path!r}")
    unknown = uses - _USES
    if unknown:
        raise RemediationError(
            f"unknown custom.uses for {target.path!r}: {sorted(unknown)}"
        )
    return uses


def _signed_review_status(target: TargetFile) -> str | None:
    value = _custom(target).get("review_status")
    if value is None:
        return None
    if not isinstance(value, str) or value not in _REVIEW_STATUSES:
        raise RemediationError(
            f"custom.review_status for {target.path!r} must be "
            f"one of {sorted(_REVIEW_STATUSES)}"
        )
    return value


def _signed_withdrawn(target: TargetFile) -> bool:
    value = _custom(target).get("withdrawn", False)
    if not isinstance(value, bool):
        raise RemediationError(
            f"custom.withdrawn for {target.path!r} must be bool"
        )
    return value


def _signed_groups(target: TargetFile) -> frozenset[str] | None:
    value = _custom(target).get("groups")
    if value is None:
        return None
    return _string_set(value, f"custom.groups for {target.path!r}")


def _review_status(
    target: TargetFile, rule: CompatibilityRule
) -> str:
    statuses = {
        status
        for status in (_signed_review_status(target), rule.review_status)
        if status is not None
    }
    return PENDING if PENDING in statuses else APPROVED


def _installed_version_matches(
    rule: CompatibilityRule, installed_version: str
) -> bool:
    return (
        "*" in rule.installed_versions
        or installed_version in rule.installed_versions
    )


def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    parts = re.split(r"[.\-+_]", version)
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part) for part in parts
    )


def _compare_versions(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _reason(
    use: str,
    source: VerifiedTarget,
    withdrawn: bool,
    review_status: str,
) -> str:
    parts = [use]
    parts.append(
        "from archived snapshot"
        if source.view_kind == "archive"
        else "from current snapshot"
    )
    if withdrawn:
        parts.append("withdrawn target is rollback-only")
    if review_status == PENDING:
        parts.append("pending review requires approval")
    return "; ".join(parts)


def _deduplicate(actions: list[PlannedAction]) -> list[PlannedAction]:
    best: dict[tuple[object, ...], PlannedAction] = {}
    for action in actions:
        key = (
            action.use,
            action.source.path,
            action.target_version,
            tuple(sorted(action.source.target.hashes.items())),
        )
        previous = best.get(key)
        if previous is None or _view_preference(action) > _view_preference(
            previous
        ):
            best[key] = action
    return list(best.values())


def _view_preference(
    action: PlannedAction,
) -> tuple[bool, int, bool]:
    return (
        action.source.view_kind == "current",
        action.source.snapshot_version,
        not action.controlled,
    )


def _action_flags(action: PlannedAction) -> str:
    flags = []
    if action.withdrawn:
        flags.append("withdrawn")
    if action.source.view_kind == "archive":
        flags.append("archived")
    if action.stale:
        flags.append("stale")
    if action.controlled:
        flags.append("controlled")
    if action.review_status == PENDING:
        flags.append("pending-review")
    if action.requires_approval:
        flags.append("requires-approval")
    return ", ".join(flags) if flags else "-"


def _format_row(row: tuple[str, ...], widths: list[int]) -> str:
    return "  ".join(
        value.ljust(width) for value, width in zip(row, widths, strict=True)
    ).rstrip()


def plan_remediation(
    devices: Iterable[Device],
    views: Iterable[VerifiedTargetView],
    compatibility: CompatibilityTable,
    *,
    allow_pending: bool | None = None,
) -> RemediationPlan:
    """Convenience wrapper for a single offline planning pass.

    Args:
        devices: Devices to plan remediation for.
        views: Verified current and archived repository views.
        compatibility: Caller supplied group compatibility table.
        allow_pending: Optional override for whether pending-review targets
            may be used. By default the compatibility table decides.
    """
    planner = RemediationPlanner(
        views, compatibility, allow_pending=allow_pending
    )
    return planner.plan(devices)
