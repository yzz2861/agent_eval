"""Recording of evidence declarations emitted by evidence-aware plugins.

A plugin produces zero or more *entries* (artifacts). Each entry is backed by
evidence references describing which registry keys/values were read, and which
items were observed as missing and therefore participated in the conclusion.

The recorder supports two scopes:

* plugin-level evidence: applies to every entry the plugin emits;
* entry-level evidence: attached to the entry produced inside the
  ``entry_scope(entry_id)`` context manager.

References are deduplicated and stored as immutable :class:`EvidenceRef`
objects, which makes the recorded evidence directly JSON-serializable.
"""

from __future__ import annotations

import contextlib
from typing import Any, Dict, Iterator, List, Optional

from regipy.evidence.model import (
    KEY_ABSENT,
    VALUE_ABSENT,
    EvidenceRef,
)


class EvidenceRecorder:
    """Collects evidence references for a single plugin run."""

    ENTRY_EVIDENCE_ATTR = "_evidence_refs"
    ENTRY_ID_ATTR = "_entry_id"

    def __init__(self, source: Any = None, plugin_name: Optional[str] = None):
        self.source = source
        self.plugin_name = plugin_name
        self._plugin_refs: List[EvidenceRef] = []
        self._entry_refs: Dict[str, List[EvidenceRef]] = {}
        self._current_entry_id: Optional[str] = None

    @staticmethod
    def _same_fact(left: EvidenceRef, right: EvidenceRef) -> bool:
        return left.kind == right.kind and left.key_path == right.key_path and left.value_name == right.value_name

    @classmethod
    def _dedupe(cls, refs: List[EvidenceRef], ref: EvidenceRef) -> None:
        for existing in refs:
            if cls._same_fact(existing, ref):
                if ref.note and not existing.note:
                    refs[refs.index(existing)] = EvidenceRef(
                        kind=existing.kind,
                        key_path=existing.key_path,
                        value_name=existing.value_name,
                        observed=existing.observed,
                        note=ref.note,
                    )
                return
        refs.append(ref)

    def record(self, ref: EvidenceRef) -> EvidenceRef:
        """Record a reference against the active entry, or the plugin scope.

        A repeated declaration of the same fact (same kind/path/value) is
        merged into the existing reference instead of duplicated, so an
        explicit explanatory declaration after an automatic tracked lookup
        yields a single, annotated reference.
        """
        if self._current_entry_id is not None:
            entry_refs = self._entry_refs.setdefault(self._current_entry_id, [])
            self._dedupe(entry_refs, ref)
        else:
            self._dedupe(self._plugin_refs, ref)
        return ref

    def declare_key_read(self, key_path: str, note: Optional[str] = None) -> EvidenceRef:
        return self.record(EvidenceRef.key(key_path, note=note))

    def declare_value_read(
        self,
        key_path: str,
        value_name: str,
        observed: Any = None,
        note: Optional[str] = None,
    ) -> EvidenceRef:
        return self.record(EvidenceRef.value(key_path, value_name, observed=observed, note=note))

    def declare_subtree_read(self, key_path: str, note: Optional[str] = None) -> EvidenceRef:
        return self.record(EvidenceRef.subtree(key_path, note=note))

    def declare_key_absent(self, key_path: str, note: Optional[str] = None) -> EvidenceRef:
        """Negative evidence: a missing key participated in the conclusion."""
        return self.record(EvidenceRef(kind=KEY_ABSENT, key_path=key_path, note=note))

    def declare_value_absent(
        self,
        key_path: str,
        value_name: str,
        note: Optional[str] = None,
    ) -> EvidenceRef:
        """Negative evidence: a missing value participated in the conclusion."""
        return self.record(EvidenceRef(kind=VALUE_ABSENT, key_path=key_path, value_name=value_name, note=note))

    @contextlib.contextmanager
    def entry_scope(self, entry_id: str) -> Iterator[None]:
        """Attach subsequent declarations to the entry identified by ``entry_id``."""
        if self._current_entry_id is not None:
            raise RuntimeError(
                f"Nested entry scopes are not supported: {self._current_entry_id!r} is still active while opening {entry_id!r}"
            )
        self._entry_refs.setdefault(entry_id, [])
        self._current_entry_id = entry_id
        try:
            yield
        finally:
            self._current_entry_id = None

    def evidence_for_entry(self, entry_id: str) -> List[EvidenceRef]:
        """All references backing an entry (plugin-level + entry-level).

        Plugin-level and entry-level declarations of the same fact (same
        kind/path/value) are merged into a single reference, preferring the
        annotated variant when one of them carries a note.
        """
        refs: List[EvidenceRef] = []
        for ref in list(self._plugin_refs) + list(self._entry_refs.get(entry_id, [])):
            for index, existing in enumerate(refs):
                if self._same_fact(existing, ref):
                    if ref.note and not existing.note:
                        refs[index] = EvidenceRef(
                            kind=existing.kind,
                            key_path=existing.key_path,
                            value_name=existing.value_name,
                            observed=existing.observed,
                            note=ref.note,
                        )
                    break
            else:
                refs.append(ref)
        return refs

    def entry_ids(self) -> List[str]:
        return list(self._entry_refs.keys())

    @property
    def all_refs(self) -> List[EvidenceRef]:
        refs: List[EvidenceRef] = list(self._plugin_refs)
        for entry_refs in self._entry_refs.values():
            for ref in entry_refs:
                if ref not in refs:
                    refs.append(ref)
        return refs

    def to_report_dict(self, plugin_name: Optional[str] = None) -> Dict[str, Any]:
        name = plugin_name or self.plugin_name
        return {
            "plugin": name,
            "plugin_level_refs": [ref.to_dict() for ref in self._plugin_refs],
            "entry_refs": {entry_id: [ref.to_dict() for ref in refs] for entry_id, refs in self._entry_refs.items()},
        }

    @classmethod
    def from_report_dict(cls, data: Dict[str, Any]) -> "EvidenceRecorder":
        recorder = cls(plugin_name=data.get("plugin"))
        recorder._plugin_refs = [EvidenceRef.from_dict(item) for item in data.get("plugin_level_refs", [])]
        recorder._entry_refs = {
            entry_id: [EvidenceRef.from_dict(item) for item in refs] for entry_id, refs in data.get("entry_refs", {}).items()
        }
        return recorder
