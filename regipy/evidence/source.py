"""Evidence sources: a read-only registry access layer that can track every
key/value lookup a plugin performs and turn it into evidence references.

Two concrete sources are provided:

* :class:`RegistryEvidenceSource` wraps a real
  :class:`regipy.registry.RegistryHive` and is what production plugins use.
* :class:`DictHive` is an in-memory source used by the incremental
  re-validation example and tests, where a hive cannot be rewritten on disk
  but supplemental material can be applied on top of the captured snapshot.

:class:`TrackingEvidenceSource` decorates either implementation and records
both successful lookups and not-found outcomes on an :class:`EvidenceRecorder`.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Protocol, runtime_checkable

from regipy.evidence.model import (
    KEY,
    KEY_ABSENT,
    SUBTREE,
    VALUE,
    VALUE_ABSENT,
    EvidenceRef,
    normalize_path,
)
from regipy.evidence.recorder import EvidenceRecorder
from regipy.exceptions import (
    RegistryKeyNotFoundException,
    RegistryValueNotFoundException,
)
from regipy.registry import RegistryHive, Value


@runtime_checkable
class EvidenceSource(Protocol):
    """Read-only registry surface used by evidence-aware plugins."""

    hive_type: Optional[str]
    partial_hive_path: Optional[str]

    def key_exists(self, key_path: str) -> bool: ...

    def get_key(self, key_path: str) -> Any: ...

    def get_value(self, key_path: str, value_name: str) -> Any: ...

    def iter_key_values(self, key_path: str) -> Iterable[Any]: ...

    def iter_subkey_names(self, key_path: str) -> Iterable[str]: ...

    def iter_all_keys(self) -> Iterable[dict]: ...


class RegistryEvidenceSource:
    """Adapter exposing a :class:`RegistryHive` through the evidence protocol."""

    def __init__(self, registry_hive: RegistryHive):
        self.registry_hive = registry_hive
        self.hive_type = registry_hive.hive_type
        self.partial_hive_path = registry_hive.partial_hive_path

    def key_exists(self, key_path: str) -> bool:
        try:
            self.registry_hive.get_key(key_path)
        except RegistryKeyNotFoundException:
            return False
        return True

    def get_key(self, key_path: str) -> Any:
        return self.registry_hive.get_key(key_path)

    def get_value(self, key_path: str, value_name: str) -> Any:
        return self.registry_hive.get_key(key_path).get_value(
            value_name=value_name,
            as_json=True,
            raise_on_missing=True,
        )

    def iter_key_values(self, key_path: str) -> Iterable[Value]:
        return self.registry_hive.get_key(key_path).iter_values(as_json=True, trim_values=False)

    def iter_subkey_names(self, key_path: str) -> Iterable[str]:
        subkeys = self.registry_hive.get_key(key_path).iter_subkeys()
        if subkeys is None:
            return ()
        return (subkey.name for subkey in subkeys)

    def iter_all_keys(self) -> Iterable[dict]:
        for subkey in self.registry_hive.recurse_subkeys(as_json=True):
            yield {
                "path": subkey.path,
                "timestamp": subkey.timestamp,
                "values": list(subkey.values),
            }


class TrackingEvidenceSource:
    """Wrap an :class:`EvidenceSource` and record every lookup as evidence.

    Missing keys/values are first-class evidence: a lookup that raises
    :class:`RegistryKeyNotFoundException` (or returns ``None`` for a value)
    records a ``missing_key``/``missing_value`` reference before the exception
    is re-raised, so a plugin negative conclusion can be revoked when the
    supplemental material supplies the previously missing item.
    """

    def __init__(self, delegate: EvidenceSource, recorder: EvidenceRecorder):
        self.delegate = delegate
        self.recorder = recorder
        self.hive_type = getattr(delegate, "hive_type", None)
        self.partial_hive_path = getattr(delegate, "partial_hive_path", None)

    def key_exists(self, key_path: str) -> bool:
        exists = self.delegate.key_exists(key_path)
        self.recorder.record(EvidenceRef(KEY_ABSENT if not exists else KEY, key_path))
        return exists

    def get_key(self, key_path: str) -> Any:
        try:
            key = self.delegate.get_key(key_path)
        except RegistryKeyNotFoundException:
            self.recorder.record(EvidenceRef(KEY_ABSENT, key_path))
            raise
        self.recorder.record(EvidenceRef(KEY, key_path))
        return key

    def get_value(self, key_path: str, value_name: str) -> Any:
        try:
            value = self.delegate.get_value(key_path, value_name)
        except RegistryKeyNotFoundException:
            self.recorder.record(EvidenceRef(KEY_ABSENT, key_path))
            raise
        except RegistryValueNotFoundException:
            self.recorder.record(EvidenceRef(VALUE_ABSENT, key_path, value_name))
            raise
        if value is None:
            self.recorder.record(EvidenceRef(VALUE_ABSENT, key_path, value_name))
        else:
            self.recorder.record(EvidenceRef(VALUE, key_path, value_name, observed=value))
        return value

    def iter_key_values(self, key_path: str) -> Iterable[Any]:
        try:
            iterator = iter(self.delegate.iter_key_values(key_path))
        except RegistryKeyNotFoundException:
            self.recorder.record(EvidenceRef(KEY_ABSENT, key_path))
            raise
        self.recorder.record(EvidenceRef(KEY, key_path))
        for item in iterator:
            name = item.name if isinstance(item, Value) else item[0]
            self.recorder.record(EvidenceRef(VALUE, key_path, name))
            yield item

    def iter_subkey_names(self, key_path: str) -> Iterable[str]:
        try:
            iterator = iter(self.delegate.iter_subkey_names(key_path))
        except RegistryKeyNotFoundException:
            self.recorder.record(EvidenceRef(KEY_ABSENT, key_path))
            raise
        self.recorder.record(EvidenceRef(SUBTREE, key_path))
        yield from iterator

    def iter_all_keys(self) -> Iterable[dict]:
        yield from self.delegate.iter_all_keys()


class DictHive:
    """In-memory evidence source for examples and tests.

    Layout::

        {
            r"\\Path\\To\\Key": {
                "timestamp": "2024-01-01T00:00:00+00:00",
                "values": {"ValueName": {"value": ..., "value_type": "REG_SZ"}},
                "subkeys": ["Child"],
            }
        }
    """

    def __init__(self, keys=None, hive_type=None, partial_hive_path=None):
        self.keys = {normalize_key_path(path): payload for path, payload in (keys or {}).items()}
        self.hive_type = hive_type
        self.partial_hive_path = partial_hive_path

    def _payload(self, key_path: str) -> dict:
        payload = self.keys.get(normalize_key_path(key_path))
        if payload is None:
            raise RegistryKeyNotFoundException(f"Did not find subkey at {key_path}")
        return payload

    def key_exists(self, key_path: str) -> bool:
        return normalize_key_path(key_path) in self.keys

    def get_key(self, key_path: str) -> "DictKey":
        return DictKey(normalize_key_path(key_path), self._payload(key_path))

    def get_value(self, key_path: str, value_name: str) -> Any:
        values = self._payload(key_path).get("values", {})
        if value_name not in values:
            raise RegistryValueNotFoundException(f"Did not find the value {value_name} on subkey {key_path}")
        return values[value_name]["value"]

    def iter_key_values(self, key_path: str) -> List[Value]:
        values = self._payload(key_path).get("values", {})
        return [
            Value(
                name=name,
                value=spec["value"],
                value_type=spec.get("value_type", "REG_SZ"),
            )
            for name, spec in values.items()
        ]

    def iter_subkey_names(self, key_path: str) -> List[str]:
        return list(self._payload(key_path).get("subkeys", ()))

    def iter_all_keys(self) -> Iterable[dict]:
        for path in sorted(self.keys, key=normalize_path):
            payload = self.keys[path]
            yield {
                "path": path,
                "timestamp": payload.get("timestamp"),
                "values": [
                    {
                        "name": name,
                        "value": spec.get("value"),
                        "value_type": spec.get("value_type", "REG_SZ"),
                        "is_corrupted": bool(spec.get("is_corrupted", False)),
                    }
                    for name, spec in payload.get("values", {}).items()
                ],
            }

    def apply_changes(self, value_changes=None, added_keys=None) -> "DictHive":
        """Return a shallow-copied hive with supplemental material applied.

        Existing values are overwritten and previously missing keys are added,
        mirroring the two supplemental-evidence actions in the example.
        """
        merged = {path: dict(payload) for path, payload in self.keys.items()}
        for payload in merged.values():
            if "values" in payload:
                payload["values"] = dict(payload["values"])

        for (key_path, value_name), new_value in (value_changes or {}).items():
            normalized = normalize_key_path(key_path)
            if normalized not in merged:
                raise RegistryKeyNotFoundException(f"Cannot set value on missing key {key_path}")
            spec = merged[normalized].setdefault("values", {})
            if value_name in spec:
                spec[value_name] = dict(spec[value_name], value=new_value)
            else:
                spec[value_name] = {"value": new_value, "value_type": "REG_SZ"}

        for key_path, payload in (added_keys or {}).items():
            merged[normalize_key_path(key_path)] = payload

        return DictHive(merged, hive_type=self.hive_type, partial_hive_path=self.partial_hive_path)


class DictKey:
    """Minimal key object returned by :meth:`DictHive.get_key`."""

    def __init__(self, path: str, payload: dict):
        self.path = path
        self.name = path.rpartition("\\")[2]
        self.timestamp = payload.get("timestamp")
        self._values = payload.get("values", {})
        self.subkey_names = list(payload.get("subkeys", ()))

    def iter_values(self) -> List[Value]:
        return [
            Value(
                name=name,
                value=spec["value"],
                value_type=spec.get("value_type", "REG_SZ"),
            )
            for name, spec in self._values.items()
        ]


def normalize_key_path(key_path: str) -> str:
    """Normalize a registry path (leading backslash; case kept for display)."""
    key_path = key_path.replace("/", "\\")
    if not key_path.startswith("\\"):
        key_path = "\\" + key_path
    return key_path.rstrip("\\") if len(key_path) > 1 else key_path
