"""Base class for plugins that declare their evidence dependencies.

An :class:`EvidenceAwarePlugin` extends the regular :class:`~regipy.plugins.plugin.Plugin`
contract without changing it: plugins still populate ``self.entries`` exactly
as before, and hive inputs that are not wrapped in an evidence source keep
working untouched. When an evidence source is supplied (either an
:class:`~regipy.evidence.source.EvidenceSource` directly or a plain
:class:`~regipy.registry.RegistryHive`, which is adapted automatically), every
entry can be enriched with the evidence references that support it.

Two complementary declaration mechanisms are supported:

* explicit declarations from within ``run()`` (see the ``declare_*`` methods),
  including negative evidence such as "the key was not found";
* automatic capture: registry access performed through ``self.tracked`` (a
  :class:`~regipy.evidence.source.TrackingEvidenceSource`) is recorded and
  attached to the currently open entry scope.
"""

from __future__ import annotations

from typing import Any, List, Optional

from regipy.evidence.model import EvidenceRef
from regipy.evidence.recorder import EvidenceRecorder
from regipy.evidence.source import (
    EvidenceSource,
    RegistryEvidenceSource,
    TrackingEvidenceSource,
)
from regipy.plugins.plugin import Plugin


class EvidenceAwarePlugin(Plugin):
    def __init__(self, registry_hive, as_json=False, trim_values=False):
        super().__init__(registry_hive, as_json=as_json, trim_values=trim_values)
        if isinstance(registry_hive, EvidenceSource):
            source = registry_hive
        else:
            source = RegistryEvidenceSource(registry_hive)
        self.evidence = source
        self.recorder = EvidenceRecorder(source=source, plugin_name=self.NAME or self.__class__.__name__)
        self.tracked = TrackingEvidenceSource(source, self.recorder)
        self.plugin_evidence: List[EvidenceRef] = []

    # ------------------------------------------------------------------
    # Explicit declaration API (also covers negative evidence)
    # ------------------------------------------------------------------
    def declare_key_read(self, key_path: str, note: Optional[str] = None) -> EvidenceRef:
        return self.recorder.declare_key_read(key_path, note=note)

    def declare_value_read(
        self,
        key_path: str,
        value_name: str,
        observed: Any = None,
        note: Optional[str] = None,
    ) -> EvidenceRef:
        return self.recorder.declare_value_read(key_path, value_name, observed=observed, note=note)

    def declare_subtree_read(self, key_path: str, note: Optional[str] = None) -> EvidenceRef:
        return self.recorder.declare_subtree_read(key_path, note=note)

    def declare_key_absent(self, key_path: str, note: Optional[str] = None) -> EvidenceRef:
        """Negative evidence: looking up ``key_path`` returned not-found."""
        return self.recorder.declare_key_absent(key_path, note=note)

    def declare_value_absent(
        self,
        key_path: str,
        value_name: str,
        note: Optional[str] = None,
    ) -> EvidenceRef:
        """Negative evidence: ``value_name`` was absent under ``key_path``."""
        return self.recorder.declare_value_absent(key_path, value_name, note=note)

    def declare_plugin_evidence(self, ref: EvidenceRef) -> None:
        """Attach evidence supporting the whole plugin run, not a single entry."""
        if ref not in self.plugin_evidence:
            self.plugin_evidence.append(ref)

    # ------------------------------------------------------------------
    # Entry scope and output helpers
    # ------------------------------------------------------------------
    def entry_scope(self, entry_id: str):
        return self.recorder.entry_scope(entry_id)

    def add_evidenced_entry(self, entry: dict, entry_id: Optional[str] = None) -> str:
        """Append ``entry`` and bind the evidence of the matching entry scope."""
        resolved_id = entry_id or stable_entry_id(self.NAME or self.__class__.__name__, entry)
        entry_evidence = list(self.plugin_evidence)
        for ref in self.recorder.evidence_for_entry(resolved_id):
            if ref not in entry_evidence:
                entry_evidence.append(ref)
        entry[EvidenceRecorder.ENTRY_EVIDENCE_ATTR] = [ref.to_dict() for ref in entry_evidence]
        entry[EvidenceRecorder.ENTRY_ID_ATTR] = resolved_id
        self.entries.append(entry)
        return resolved_id

    def finalize_evidence(self) -> dict:
        """Serialize the full evidence manifest of the run."""
        return self.recorder.to_report_dict(plugin_name=self.NAME or self.__class__.__name__)


def stable_entry_id(plugin_name: str, entry: dict) -> str:
    """Deterministic identifier so a finding can be matched across report runs."""
    parts = [plugin_name]
    for key in sorted(key for key in entry if not key.startswith("_")):
        value = entry[key]
        if isinstance(value, (dict, list)):
            continue
        parts.append(f"{key}={value}")
    return "|".join(parts)
