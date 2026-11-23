"""Registry patch modelling, evidence impact analysis and patch-aware hive views."""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any

from regipy.evidence import Evidence, EvidenceKind, normalize_key_path
from regipy.exceptions import RegistryValueNotFoundException
from regipy.registry import NKRecord, RegistryHive, Value


class RegistryPatch:
    """Base class for supplemental registry changes applied on top of an existing hive."""

    def describe(self) -> str:
        raise NotImplementedError

    def impacted_evidence(self, evidence: Sequence[Evidence]) -> list[Evidence]:
        """Return the evidence items whose conclusion must be re-verified."""
        raise NotImplementedError


class ValueChangePatch(RegistryPatch):
    """An existing registry value is changed (or a new value is added under an existing key)."""

    def __init__(self, key_path: str, value_name: str, new_value: Any, value_type: str | None = None):
        self.key_path = normalize_key_path(key_path)
        self.value_name = value_name
        self.new_value = new_value
        self.value_type = value_type

    def describe(self) -> str:
        return f"change value '{self.value_name}' under {self.key_path}"

    def impacted_evidence(self, evidence: Sequence[Evidence]) -> list[Evidence]:
        impacted: list[Evidence] = []
        for item in evidence:
            if item.key_path != self.key_path:
                continue
            same_value = item.value_name is not None and item.value_name.lower() == self.value_name.lower()
            if item.kind == EvidenceKind.KEY_READ or same_value:
                impacted.append(item)
        return impacted


class AddedKeyPatch(RegistryPatch):
    """A previously missing key (optionally with values) is added to the hive."""

    def __init__(
        self,
        key_path: str,
        values: dict[str, Any] | None = None,
        value_types: dict[str, str] | None = None,
        last_modified: dt.datetime | None = None,
    ):
        self.key_path = normalize_key_path(key_path)
        self.values = dict(values or {})
        self.value_types = dict(value_types or {})
        self.last_modified = last_modified or dt.datetime(1970, 1, 1)

    def describe(self) -> str:
        return f"add previously missing key {self.key_path}"

    def _covers(self, evidence_path: str) -> bool:
        return evidence_path == self.key_path or evidence_path.startswith(self.key_path + "\\")

    def impacted_evidence(self, evidence: Sequence[Evidence]) -> list[Evidence]:
        impacted: list[Evidence] = []
        for item in evidence:
            if not self._covers(item.key_path):
                continue
            if item.kind == EvidenceKind.KEY_MISSING or item.kind == EvidenceKind.VALUE_MISSING:
                impacted.append(item)
        return impacted


def analyze_patch_impact(patches: Sequence[RegistryPatch], evidence: Sequence[Evidence]) -> list[Evidence]:
    """Collect the distinct evidence items invalidated by any of the patches."""
    impacted: list[Evidence] = []
    seen: set = set()
    for patch in patches:
        for item in patch.impacted_evidence(evidence):
            if item.id not in seen:
                seen.add(item.id)
                impacted.append(item)
    return impacted


class _AddedKeyRecord:
    """Minimal NKRecord-compatible view for a key supplied by an AddedKeyPatch."""

    def __init__(self, name: str, patch: AddedKeyPatch):
        self.name = name
        self._patch = patch
        self.subkey_count = 0
        self.values_count = len(patch.values)
        self.header = SimpleNamespace(last_modified=patch.last_modified)

    def iter_subkeys(self):
        return None

    def iter_values(self, as_json=False, max_len=None, trim_values=True):
        for name, raw_value in self._patch.values.items():
            yield Value(
                name=name,
                value=raw_value,
                value_type=self._patch.value_types.get(name, "REG_SZ"),
                is_corrupted=False,
            )

    def get_values(self, as_json=False, trim_values=False):
        return list(self.iter_values(as_json=as_json, trim_values=trim_values))

    def get_value(self, value_name="(default)", as_json=False, raise_on_missing=False, case_sensitive=True):
        wanted = value_name if case_sensitive else value_name.lower()
        for value in self.iter_values(as_json=as_json):
            current = value.name if case_sensitive else value.name.lower()
            if current == wanted:
                return value.value
        if raise_on_missing:
            raise RegistryValueNotFoundException(f"Did not find the value {value_name} on subkey {self.name}")
        return None


class PatchedRegistryHive:
    """Read-only RegistryHive overlay that serves supplemental patches without rewriting the hive."""

    def __init__(self, base_hive: RegistryHive, patches: Sequence[RegistryPatch]):
        self._base_hive = base_hive
        self.patches = list(patches)
        self._value_changes: dict[str, dict[str, ValueChangePatch]] = {}
        self._added_keys: dict[str, AddedKeyPatch] = {}
        for patch in self.patches:
            if isinstance(patch, ValueChangePatch):
                self._value_changes.setdefault(patch.key_path, {})[patch.value_name.lower()] = patch
            elif isinstance(patch, AddedKeyPatch):
                self._added_keys[patch.key_path] = patch

        self.partial_hive_path = base_hive.partial_hive_path
        self.hive_type = base_hive.hive_type
        self.header = base_hive.header
        self.root = base_hive.root
        self.name = base_hive.name
        self.CONTROL_SETS = base_hive.CONTROL_SETS

    def _added_record(self, key_path: str) -> _AddedKeyRecord | None:
        patch = self._added_keys.get(key_path)
        if patch is None:
            return None
        return _AddedKeyRecord(key_path.rpartition("\\")[-1], patch)

    def get_key(self, key_path: str):
        normalized = normalize_key_path(key_path)
        if normalized in self._added_keys:
            return self._added_record(normalized)
        base_record = self._base_hive.get_key(key_path)
        overrides = self._value_changes.get(normalized)
        if overrides:
            return _PatchedKeyRecord(base_record, overrides)
        return base_record

    def get_control_sets(self, registry_path: str):
        return self._base_hive.get_control_sets(registry_path)

    def recurse_subkeys(self, *args, **kwargs):
        return self._base_hive.recurse_subkeys(*args, **kwargs)

    def get_value_from_key(self, key_path: str, value_name: str, **kwargs):
        record = self.get_key(key_path)
        return record.get_value(value_name, **kwargs)


class _PatchedKeyRecord:
    """NKRecord wrapper that overlays value changes on an existing key."""

    def __init__(self, base_record: NKRecord, overrides: dict[str, ValueChangePatch]):
        self._base_record = base_record
        self._overrides = overrides
        self.name = base_record.name
        self.header = base_record.header
        self.subkey_count = base_record.subkey_count
        self.values_count = base_record.values_count + sum(
            1 for patch in overrides.values() if not self._base_has_value(patch.value_name)
        )

    def _base_has_value(self, value_name: str) -> bool:
        return any(value.name.lower() == value_name.lower() for value in self._base_record.iter_values())

    def iter_subkeys(self):
        return self._base_record.iter_subkeys()

    def iter_values(self, as_json=False, max_len=None, trim_values=True):
        yielded = set()
        for value in self._base_record.iter_values(as_json=as_json, trim_values=trim_values):
            patch = self._overrides.get(value.name.lower())
            if patch is not None:
                yielded.add(value.name.lower())
                yield Value(
                    name=value.name,
                    value=patch.new_value,
                    value_type=patch.value_type or value.value_type,
                    is_corrupted=value.is_corrupted,
                )
            else:
                yielded.add(value.name.lower())
                yield value
        for patch in self._overrides.values():
            if patch.value_name.lower() in yielded:
                continue
            yield Value(
                name=patch.value_name,
                value=patch.new_value,
                value_type=patch.value_type or "REG_SZ",
                is_corrupted=False,
            )

    def get_values(self, as_json=False, trim_values=False):
        return list(self.iter_values(as_json=as_json, trim_values=trim_values))

    def get_value(self, value_name="(default)", as_json=False, raise_on_missing=False, case_sensitive=True):
        wanted = value_name if case_sensitive else value_name.lower()
        for value in self.iter_values(as_json=as_json):
            current = value.name if case_sensitive else value.name.lower()
            if current == wanted:
                return value.value
        if raise_on_missing:
            raise RegistryValueNotFoundException(f"Did not find the value {value_name} on subkey {self.name}")
        return None
