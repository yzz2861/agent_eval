"""Evidence dependency tracking for regipy plugins.

Forensic plugins draw conclusions (the entries they emit) from specific
registry evidence: keys they read, values they read, and sometimes from the
*absence* of an expected key or value. When a supplementary registry extract
arrives (a "patch") that changes only a handful of cells, only the conclusions
whose declared evidence intersects the changed cells need to be re-verified.

This module provides:

* :class:`Evidence` - a single, serializable evidence dependency.
* :class:`EvidenceTracker` - collects the evidence a plugin consults while it
  runs and records which evidence backs each emitted entry.
The declarative ``evidence_*`` helpers are exposed directly on
:class:`~regipy.plugins.plugin.Plugin`.

Registry paths and value names are normalized to upper case because the
Windows registry is case-insensitive; this keeps dependency matching exact
without false misses caused by casing differences between runs.
"""

from __future__ import annotations

import contextlib
import datetime as dt
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

# Evidence kind constants. Plugins normally use the Plugin evidence_* helper
# methods instead of building Evidence objects directly.
EVIDENCE_KEY_READ = "key_read"
EVIDENCE_VALUE_READ = "value_read"
EVIDENCE_KEY_MISSING = "key_missing"
EVIDENCE_VALUE_MISSING = "value_missing"


class EvidenceKind:
    """String constants describing the four ways evidence can be consulted."""

    KEY_READ = EVIDENCE_KEY_READ
    VALUE_READ = EVIDENCE_VALUE_READ
    KEY_MISSING = EVIDENCE_KEY_MISSING
    VALUE_MISSING = EVIDENCE_VALUE_MISSING


def normalize_key_path(key_path: str) -> str:
    """Normalize a registry key path for case-insensitive matching.

    A leading backslash is added when missing and redundant backslashes are
    collapsed, so ``"Software\\Run"`` and ``"\\\\Software\\\\Run"`` describe
    the same key.
    """
    parts = [part for part in key_path.replace("/", "\\").split("\\") if part]
    return "\\" + "\\".join(parts).upper() if parts else "\\"


def normalize_value_name(value_name: str | None) -> str:
    """Normalize a registry value name (the default value is ``(default)``)."""
    if value_name is None or value_name == "":
        return "(DEFAULT)"
    return value_name.upper()


@dataclass
class Evidence:
    """A single registry fact that participated in a plugin's conclusion.

    The four kinds mirror the ways evidence can be consulted:

    * ``key_read`` / ``value_read`` - an existing key or value was read;
    * ``key_missing`` / ``value_missing`` - an expected key or value was
      looked up and not found, and that absence participated in the
      conclusion (for example a plugin returning no entries).
    """

    kind: str
    key_path: str
    value_name: str | None = None
    plugin_name: str = ""
    entry_indices: list[int] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        self.key_path = normalize_key_path(self.key_path)
        if self.kind in (EVIDENCE_VALUE_READ, EVIDENCE_VALUE_MISSING):
            self.value_name = normalize_value_name(self.value_name)
        if not self.id:
            value_part = f":{self.value_name}" if self.value_name is not None else ""
            self.id = f"{self.plugin_name}:{self.kind}:{self.key_path}{value_part}".lower()

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "key_path": self.key_path,
            "plugin_name": self.plugin_name,
            "entry_indices": list(self.entry_indices),
        }
        if self.value_name is not None:
            result["value_name"] = self.value_name
        return result


@dataclass
class EvidenceTracker:
    """Collects evidence dependencies while a plugin executes.

    Every piece of evidence is stored once (deduplicated), and each emitted
    entry can be associated with the evidence that produced it via
    :meth:`bind_entry`. Entries that are emitted without an explicit binding
    implicitly depend on all evidence collected up to that point, which is the
    conservative default and preserves deterministic output.
    """

    plugin_name: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    # entry index (in plugin.entries) -> list of evidence indices
    entry_evidence: dict[int, list[int]] = field(default_factory=dict)
    _index: dict[tuple[Any, ...], int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.plugin_name:
            self.plugin_name = "plugin"

    def _add(self, ev: Evidence) -> int:
        ev.plugin_name = self.plugin_name
        ev.__post_init__()
        key = (ev.kind, ev.key_path, ev.value_name)
        existing = self._index.get(key)
        if existing is not None:
            return existing
        new_index = len(self.evidence)
        self.evidence.append(ev)
        self._index[key] = new_index
        return new_index

    def record_key_read(self, key_path: str) -> int:
        return self._add(Evidence(EVIDENCE_KEY_READ, key_path))

    def record_value_read(self, key_path: str, value_name: str) -> int:
        return self._add(Evidence(EVIDENCE_VALUE_READ, key_path, value_name))

    def record_key_missing(self, key_path: str) -> int:
        return self._add(Evidence(EVIDENCE_KEY_MISSING, key_path))

    def record_value_missing(self, key_path: str, value_name: str) -> int:
        return self._add(Evidence(EVIDENCE_VALUE_MISSING, key_path, value_name))

    def bind_entry(self, entry_index: int, evidence_indices: Sequence[int] | None = None) -> None:
        """Associate an emitted entry with the evidence that produced it.

        With no explicit indices, the entry is bound to every piece of
        evidence collected so far (the conservative fallback).
        """
        indices = list(evidence_indices) if evidence_indices is not None else list(range(len(self.evidence)))
        bound = self.entry_evidence.setdefault(entry_index, [])
        for index in indices:
            if index not in bound:
                bound.append(index)
            if entry_index not in self.evidence[index].entry_indices:
                self.evidence[index].entry_indices.append(entry_index)

    @contextlib.contextmanager
    def entry_scope(self) -> Iterator[list[int]]:
        """Context manager collecting evidence consulted for one entry.

        Evidence recorded inside the ``with`` block is returned as a list of
        indices, ready to be passed to :meth:`bind_entry`::

            with self.evidence.entry_scope() as scope:
                value = key.get_value("Foo")
                self.evidence.record_value_read(path, "Foo")
            self.entries.append({...})
            self.evidence.bind_entry(len(self.entries) - 1, scope)
        """
        start = len(self.evidence)
        scope: list[int] = []
        yield scope
        scope.extend(range(start, len(self.evidence)))

    def evidence_for_entry(self, entry_index: int) -> list[Evidence]:
        indices = self.entry_evidence.get(entry_index)
        if indices is None:
            return list(self.evidence)
        return [self.evidence[i] for i in indices]

    def all_evidence_indices(self) -> list[int]:
        return list(range(len(self.evidence)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": [ev.to_dict() for ev in self.evidence],
            "entry_evidence": {str(index): indices for index, indices in self.entry_evidence.items()},
        }


def timestamp_now_iso() -> str:
    """Helper used when serializing re-verification reports."""
    return dt.datetime.now(dt.timezone.utc).isoformat()
