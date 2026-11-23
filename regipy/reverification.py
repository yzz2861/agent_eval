"""On-demand re-verification of plugin reports after supplemental registry patches.

The workflow:

1. Plugins run against the original hive through ``run_relevant_plugins`` (or
   directly) and declare the evidence their conclusions rely on via the
   :class:`~regipy.evidence.EvidenceTracker` exposed on every plugin.
2. Newly supplied registry data is modelled as
   :class:`~regipy.patching.RegistryPatch` objects.
3. :class:`ReverificationManager` compares the patches against the recorded
   evidence, reruns only the affected plugins on a patched in-memory hive view,
   preserves the previous report and records the exact invalidation scope.
"""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from regipy.evidence import Evidence, EvidenceKind, EvidenceTracker
from regipy.patching import PatchedRegistryHive, RegistryPatch, analyze_patch_impact
from regipy.plugins.plugin import Plugin
from regipy.registry import RegistryHive

logger = logging.getLogger(__name__)


@dataclass
class InvalidationScope:
    """The conclusions that lost validity because of a batch of patches."""

    plugin_name: str
    evidence_ids: list[str] = field(default_factory=list)
    entry_indices: list[int] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def is_whole_plugin(self) -> bool:
        """True when the plugin never bound evidence to individual entries."""
        return not self.entry_indices


@dataclass
class ReverificationResult:
    """Outcome of one on-demand re-verification round."""

    patches: list[str]
    affected_plugins: list[str]
    unaffected_plugins: list[str]
    invalidation_scopes: dict[str, InvalidationScope]
    previous_report: dict[str, Any]
    new_report: dict[str, Any]
    evidence_snapshot: list[dict[str, Any]]

    def save_report_bundle(self, output_path: str) -> None:
        """Persist the old report, the refreshed report and the invalidation scope."""
        bundle = {
            "patches": self.patches,
            "affected_plugins": self.affected_plugins,
            "unaffected_plugins": self.unaffected_plugins,
            "invalidation_scopes": {
                name: {
                    "evidence_ids": scope.evidence_ids,
                    "entry_indices": scope.entry_indices,
                    "reasons": scope.reasons,
                    "whole_plugin": scope.is_whole_plugin,
                }
                for name, scope in self.invalidation_scopes.items()
            },
            "previous_report": self.previous_report,
            "new_report": self.new_report,
            "evidence_snapshot": self.evidence_snapshot,
        }
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as writer:
            json.dump(bundle, writer, indent=2, default=str, ensure_ascii=False)


class ReverificationManager:
    """Coordinates selective re-verification across one or more plugin runs."""

    def __init__(self, registry_hive: RegistryHive, as_json: bool = True):
        self.registry_hive = registry_hive
        self.as_json = as_json
        self._trackers: dict[str, EvidenceTracker] = {}
        self._plugin_classes: dict[str, type] = {}

    def register_plugin(self, plugin: Plugin) -> None:
        """Remember the evidence tracker of a plugin that already ran."""
        if plugin.NAME is None:
            raise ValueError("Cannot register a plugin without a NAME")
        self._trackers[plugin.NAME] = plugin.evidence
        self._plugin_classes[plugin.NAME] = type(plugin)

    def register_run(self, plugins: Sequence[Plugin]) -> None:
        """Register every plugin produced by a single run."""
        for plugin in plugins:
            self.register_plugin(plugin)

    @property
    def recorded_evidence(self) -> list[Evidence]:
        items: list[Evidence] = []
        for tracker in self._trackers.values():
            items.extend(tracker.evidence)
        return items

    def plan_invalidation(self, patches: Sequence[RegistryPatch]) -> dict[str, InvalidationScope]:
        """Compute which plugin conclusions are stale without rerunning anything."""
        impacted = analyze_patch_impact(patches, self.recorded_evidence)
        scopes: dict[str, InvalidationScope] = {}
        for item in impacted:
            scope = scopes.setdefault(item.plugin_name, InvalidationScope(plugin_name=item.plugin_name))
            if item.id not in scope.evidence_ids:
                scope.evidence_ids.append(item.id)
            for index in item.entry_indices:
                if index not in scope.entry_indices:
                    scope.entry_indices.append(index)
            reason = self._reason_for(item)
            if reason not in scope.reasons:
                scope.reasons.append(reason)

        return scopes

    @staticmethod
    def _reason_for(item: Evidence) -> str:
        if item.kind == EvidenceKind.KEY_MISSING:
            return f"previously missing key {item.key_path} may now exist"
        if item.kind == EvidenceKind.VALUE_MISSING:
            return f"previously missing value '{item.value_name}' under {item.key_path} may now exist"
        if item.kind == EvidenceKind.VALUE_READ:
            return f"value '{item.value_name}' under {item.key_path} changed"
        return f"key {item.key_path} changed"

    def reverify(
        self,
        patches: Sequence[RegistryPatch],
        previous_report: dict[str, Any],
        plugin_instances: dict[str, Plugin] | None = None,
    ) -> ReverificationResult:
        """Rerun only the plugins whose recorded evidence intersects the patches."""
        scopes = self.plan_invalidation(patches)
        affected = sorted(scopes)
        unaffected = sorted(name for name in self._trackers if name not in scopes)

        refreshed_hive = PatchedRegistryHive(self.registry_hive, patches)
        new_report = copy.deepcopy(previous_report)

        for plugin_name in affected:
            plugin_class = self._plugin_classes.get(plugin_name)
            if plugin_class is None and plugin_instances is None:
                logger.warning("No plugin class registered for %s; keeping previous output", plugin_name)
                continue
            if plugin_instances is not None and plugin_name in plugin_instances:
                plugin = plugin_instances[plugin_name]
                plugin.registry_hive = refreshed_hive
                plugin.evidence = EvidenceTracker(plugin_name)
            else:
                plugin = plugin_class(refreshed_hive, as_json=self.as_json)  # type: ignore[misc]
            plugin.run()
            new_report[plugin_name] = plugin.entries
            self._trackers[plugin_name] = plugin.evidence
            self._plugin_classes[plugin_name] = type(plugin)

        return ReverificationResult(
            patches=[patch.describe() for patch in patches],
            affected_plugins=affected,
            unaffected_plugins=unaffected,
            invalidation_scopes=scopes,
            previous_report=copy.deepcopy(previous_report),
            new_report=new_report,
            evidence_snapshot=[item.to_dict() for item in self.recorded_evidence],
        )

    def save_evidence_snapshot(self, output_path: str) -> None:
        """Persist all recorded evidence for offline review."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {name: tracker.to_dict() for name, tracker in self._trackers.items()}
        with target.open("w", encoding="utf-8") as writer:
            json.dump(payload, writer, indent=2, default=str, ensure_ascii=False)
