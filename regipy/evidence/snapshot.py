"""In-memory snapshots of registry hive contents and change-set derivation.

A :class:`HiveSnapshot` is a path-indexed, JSON-serializable view of a hive at
a point in time. Comparing two snapshots yields a :class:`ChangeSet`, the
single input the evidence staleness machinery needs to decide which previously
recorded findings still hold after supplemental evidence ("buchuan") arrives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from regipy.evidence.model import (
    EvidenceKind,
    EvidenceRef,
    normalize_path,
    path_is_within,
)


@dataclass
class ValueState:
    """The state of a single registry value."""

    name: str
    value: Any
    value_type: Optional[str] = None
    is_corrupted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value_type": self.value_type,
            "value": self.value,
            "is_corrupted": self.is_corrupted,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ValueState":
        return cls(
            name=data["name"],
            value_type=data.get("value_type"),
            value=data.get("value"),
            is_corrupted=bool(data.get("is_corrupted", False)),
        )


@dataclass
class KeyState:
    """The state of a single registry key."""

    path: str
    timestamp: Optional[str]
    values: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "timestamp": self.timestamp,
            "values": {name: state.to_dict() for name, state in sorted(self.values.items())},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyState":
        return cls(
            path=data["path"],
            timestamp=data.get("timestamp"),
            values={name: ValueState.from_dict(v) for name, v in data.get("values", {}).items()},
        )


@dataclass
class Change:
    """A single observed difference between two hive snapshots."""

    kind: str
    key_path: str
    value_name: Optional[str] = None
    old: Any = None
    new: Any = None

    @property
    def value_path(self) -> Optional[str]:
        if self.value_name is None:
            return None
        if self.value_name == "":
            return self.key_path
        return f"{self.key_path}\\{self.value_name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "old": self.old,
            "new": self.new,
        }


@dataclass
class ChangeSet:
    """All differences detected when a supplemented hive is compared to a baseline."""

    changes: List[Change] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.changes)

    @property
    def touched_key_paths(self) -> set:
        return {normalize_path(change.key_path) for change in self.changes}

    @property
    def touched_value_paths(self) -> set:
        return {path for change in self.changes if (path := change.value_path) is not None}

    def to_dict(self) -> dict[str, Any]:
        return {"changes": [change.to_dict() for change in self.changes]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChangeSet":
        return cls(
            changes=[
                Change(
                    kind=item["kind"],
                    key_path=item["key_path"],
                    value_name=item.get("value_name"),
                    old=item.get("old"),
                    new=item.get("new"),
                )
                for item in data.get("changes", [])
            ]
        )


class HiveSnapshot:
    """JSON-serializable, path-indexed view of everything a hive held at capture time."""

    def __init__(self, keys=None, hive_type=None):
        self.keys = keys or {}
        self.hive_type = hive_type

    def has_key(self, key_path: str) -> bool:
        return normalize_path(key_path) in self.keys

    def get_key(self, key_path: str) -> KeyState:
        return self.keys[normalize_path(key_path)]

    def has_value(self, key_path: str, value_name: str) -> bool:
        key = self.keys.get(normalize_path(key_path))
        return bool(key and value_name in key.values)

    def get_value(self, key_path: str, value_name: str) -> ValueState:
        return self.get_key(key_path).values[value_name]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hive_type": self.hive_type,
            "keys": {path: key.to_dict() for path, key in sorted(self.keys.items())},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HiveSnapshot":
        return cls(
            hive_type=data.get("hive_type"),
            keys={path: KeyState.from_dict(key) for path, key in data.get("keys", {}).items()},
        )


def build_snapshot(evidence_source: Any, hive_type: Optional[str] = None) -> HiveSnapshot:
    """Recursively capture every key and value exposed by an EvidenceSource."""
    keys = {}
    resolved_hive_type = hive_type if hive_type is not None else getattr(evidence_source, "hive_type", None)
    for key in evidence_source.iter_all_keys():
        path = normalize_path(key["path"])
        values = {
            value["name"]: ValueState(
                name=value["name"],
                value=value.get("value"),
                value_type=value.get("value_type"),
                is_corrupted=bool(value.get("is_corrupted", False)),
            )
            for value in key.get("values", [])
        }
        keys[path] = KeyState(path=path, timestamp=key.get("timestamp"), values=values)
    return HiveSnapshot(keys=keys, hive_type=resolved_hive_type)


def diff_snapshots(baseline: HiveSnapshot, supplemented: HiveSnapshot) -> ChangeSet:
    """Derive the ordered change set describing how ``supplemented`` differs from ``baseline``."""
    changes: List[Change] = []
    baseline_paths = set(baseline.keys)
    supplemented_paths = set(supplemented.keys)

    for path in sorted(baseline_paths - supplemented_paths):
        changes.append(Change(kind="key_deleted", key_path=path))

    for path in sorted(supplemented_paths - baseline_paths):
        changes.append(Change(kind="key_added", key_path=path))

    for path in sorted(baseline_paths & supplemented_paths):
        old_key = baseline.keys[path]
        new_key = supplemented.keys[path]
        if old_key.timestamp != new_key.timestamp:
            changes.append(Change(kind="key_modified", key_path=path, old=old_key.timestamp, new=new_key.timestamp))

        old_values = old_key.values
        new_values = new_key.values
        for name in sorted(set(old_values) - set(new_values)):
            changes.append(
                Change(
                    kind="value_deleted",
                    key_path=path,
                    value_name=name,
                    old=old_values[name].to_dict(),
                )
            )
        for name in sorted(set(new_values) - set(old_values)):
            changes.append(
                Change(
                    kind="value_added",
                    key_path=path,
                    value_name=name,
                    new=new_values[name].to_dict(),
                )
            )
        for name in sorted(set(old_values) & set(new_values)):
            old_state = old_values[name]
            new_state = new_values[name]
            if old_state.to_dict() != new_state.to_dict():
                changes.append(
                    Change(
                        kind="value_modified",
                        key_path=path,
                        value_name=name,
                        old=old_state.to_dict(),
                        new=new_state.to_dict(),
                    )
                )
    return ChangeSet(changes=changes)


def is_ref_stale(ref: EvidenceRef, change_set: ChangeSet) -> bool:
    """Return whether a single evidence reference is invalidated by the change set."""
    ref_path = normalize_path(ref.key_path)
    for change in change_set.changes:
        change_path = normalize_path(change.key_path)
        if ref.kind == EvidenceKind.VALUE or ref.kind == EvidenceKind.MISSING_VALUE:
            if change.value_name == ref.value_name and change_path == ref_path:
                return True
        elif ref.kind == EvidenceKind.KEY:
            if change_path == ref_path:
                return True
        elif ref.kind == EvidenceKind.MISSING_KEY:
            if change.kind == "key_added" and change_path == ref_path:
                return True
        elif ref.kind == EvidenceKind.SUBTREE and path_is_within(change_path, ref_path):
            return True
    return False


def stale_refs(refs: List[EvidenceRef], change_set: ChangeSet) -> List[EvidenceRef]:
    """Filter an evidence list down to the references the change set invalidates."""
    return [ref for ref in refs if is_ref_stale(ref, change_set)]


def is_evidence_fresh(refs: List[EvidenceRef], change_set: ChangeSet) -> bool:
    """Convenience predicate: True when none of the references were invalidated."""
    return not stale_refs(refs, change_set)
