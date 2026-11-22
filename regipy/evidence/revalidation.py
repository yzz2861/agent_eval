"""Evidence-backed reports and targeted revalidation.

The flow is deliberately two-phase, mirroring the forensic workflow:

1. :func:`build_evidence_report` runs evidence-aware plugins once and persists
   a self-contained report: plugin entries, every entry evidence reference, a
   full baseline hive snapshot and the source hash.
2. When supplemental evidence ("buchuan") arrives, :func:`revalidate_report`
   diffs the supplemented source against the embedded baseline snapshot and
   re-runs *only* the plugins whose recorded evidence intersects the change
   set. Individual entries are classified as retained, revoked or refreshed,
   and every prior report version is archived untouched together with the
   exact revocation scope.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from regipy.evidence.model import (
    EvidenceKind,
    EvidenceRef,
    normalize_path,
    path_is_within,
)
from regipy.evidence.recorder import EvidenceRecorder
from regipy.evidence.snapshot import (
    ChangeSet,
    HiveSnapshot,
    build_snapshot,
    diff_snapshots,
    stale_refs,
)
from regipy.evidence.source import EvidenceSource

logger = logging.getLogger(__name__)

REPORT_VERSION = 1
ENTRY_EVIDENCE_KEY = EvidenceRecorder.ENTRY_EVIDENCE_ATTR
ENTRY_ID_KEY = EvidenceRecorder.ENTRY_ID_ATTR


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_file(path: str) -> str:
    digest = hashlib.sha1()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_refs(entry: dict) -> List[EvidenceRef]:
    return [EvidenceRef.from_dict(item) for item in entry.get(ENTRY_EVIDENCE_KEY, [])]


def _entry_id(entry: dict) -> str:
    return entry[ENTRY_ID_KEY]


@dataclass
class RevokedEntry:
    """An old conclusion that no longer holds and why."""

    plugin: str
    entry_id: str
    entry: dict
    stale_refs: List[EvidenceRef] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "plugin": self.plugin,
            "entry_id": self.entry_id,
            "entry": self.entry,
            "stale_refs": [ref.to_dict() for ref in self.stale_refs],
            "reasons": self.reasons,
        }


@dataclass
class PluginRevalidationResult:
    plugin: str
    reran: bool
    retained_entries: List[dict] = field(default_factory=list)
    revoked_entries: List[RevokedEntry] = field(default_factory=list)
    refreshed_entries: List[dict] = field(default_factory=list)
    new_entries: List[dict] = field(default_factory=list)
    stale_refs: List[EvidenceRef] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "plugin": self.plugin,
            "reran": self.reran,
            "retained_entries": self.retained_entries,
            "revoked_entries": [item.to_dict() for item in self.revoked_entries],
            "refreshed_entries": self.refreshed_entries,
            "new_entries": self.new_entries,
            "stale_refs": [ref.to_dict() for ref in self.stale_refs],
        }


@dataclass
class RevalidationResult:
    change_set: ChangeSet
    plugin_results: Dict[str, PluginRevalidationResult]
    report_path: Optional[str]
    archive_path: Optional[str]
    report: dict

    @property
    def affected_plugins(self) -> List[str]:
        return [name for name, result in self.plugin_results.items() if result.reran]

    @property
    def revoked(self) -> List[RevokedEntry]:
        revoked: List[RevokedEntry] = []
        for result in self.plugin_results.values():
            revoked.extend(result.revoked_entries)
        return revoked

    def to_dict(self) -> dict:
        return {
            "change_set": self.change_set.to_dict(),
            "affected_plugins": self.affected_plugins,
            "revocation_scope": [item.to_dict() for item in self.revoked],
            "plugins": {name: result.to_dict() for name, result in self.plugin_results.items()},
            "report_path": self.report_path,
            "archive_path": self.archive_path,
        }


def build_evidence_report(
    source: EvidenceSource, plugin_classes: Sequence[type], source_path: Optional[str] = None, source_hash: Optional[str] = None
) -> dict:
    """Run evidence-aware plugins and assemble a self-contained report."""
    plugins_section: Dict[str, Any] = {}
    for plugin_class in plugin_classes:
        plugin = plugin_class(source)
        if hasattr(plugin, "can_run") and not plugin.can_run():
            continue
        plugin.run()
        entries = list(plugin.entries) if isinstance(plugin.entries, list) else plugin.entries
        evidence_manifest = plugin.finalize_evidence() if hasattr(plugin, "finalize_evidence") else None
        plugins_section[plugin.NAME] = {
            "plugin_class": f"{plugin_class.__module__}.{plugin_class.__name__}",
            "entries": entries,
            "evidence": evidence_manifest,
        }

    snapshot = build_snapshot(source)
    return {
        "report_version": REPORT_VERSION,
        "generated_at": _utc_now_iso(),
        "hive_type": getattr(source, "hive_type", None),
        "source": {
            "path": source_path,
            "sha1": source_hash or (_hash_file(source_path) if source_path and os.path.exists(source_path) else None),
        },
        "baseline_snapshot": snapshot.to_dict(),
        "plugins": plugins_section,
    }


def archive_previous_report(report_path: str) -> str:
    """Move the current report file into an ``archive`` sibling directory."""
    report_path = os.path.abspath(report_path)
    archive_dir = os.path.join(os.path.dirname(report_path), "archive")
    os.makedirs(archive_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    archived_path = os.path.join(archive_dir, f"{timestamp}-{os.path.basename(report_path)}")
    shutil.move(report_path, archived_path)
    return archived_path


def save_report(report: dict, report_path: str) -> str:
    """Persist a report, archiving any previous report at the same path."""
    archive_path = ""
    if os.path.exists(report_path):
        archive_path = archive_previous_report(report_path)
    os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")
    return archive_path


def load_report(report_path: str) -> dict:
    with open(report_path, encoding="utf-8") as handle:
        return json.load(handle)


def _stale_reasons(ref: EvidenceRef, change_set: ChangeSet) -> List[str]:
    reasons: List[str] = []
    ref_path = normalize_path(ref.key_path)
    for change in change_set.changes:
        change_path = normalize_path(change.key_path)
        if ref.kind == EvidenceKind.SUBTREE:
            if not path_is_within(change_path, ref.key_path):
                continue
        elif change_path != ref_path:
            continue
        if ref.kind in (EvidenceKind.VALUE, EvidenceKind.MISSING_VALUE) and change.value_name != ref.value_name:
            continue
        if ref.kind == EvidenceKind.MISSING_KEY and change.kind != "key_added":
            continue
        target = ref.value_name if ref.value_name is not None else ref.key_path
        reasons.append(f"{ref.kind.value} evidence {target!r} invalidated by {change.kind}")
    return reasons


def _is_plugin_affected(plugin_section: dict, change_set: ChangeSet) -> bool:
    if not change_set:
        return False
    for entry in plugin_section.get("entries", []):
        if stale_refs(_entry_refs(entry), change_set):
            return True
    return False


def _rebuild_ref_index(plugin_section: dict) -> Dict[str, List[EvidenceRef]]:
    return {_entry_id(entry): _entry_refs(entry) for entry in plugin_section.get("entries", [])}


def _flatten_revocations(plugin_results: Dict[str, "PluginRevalidationResult"]) -> List[RevokedEntry]:
    flattened: List[RevokedEntry] = []
    for result in plugin_results.values():
        flattened.extend(result.revoked_entries)
    return flattened


def revalidate_report(
    report: dict,
    supplemented_source: EvidenceSource,
    plugin_classes: Sequence[type],
    *,
    source_path: Optional[str] = None,
    source_hash: Optional[str] = None,
    report_path: Optional[str] = None,
) -> RevalidationResult:
    """Re-run only plugins whose evidence intersects the supplemental changes."""
    baseline = HiveSnapshot.from_dict(report["baseline_snapshot"])
    supplemented = build_snapshot(supplemented_source)
    change_set = diff_snapshots(baseline, supplemented)

    plugin_by_name = {plugin_class.NAME: plugin_class for plugin_class in plugin_classes}
    plugin_results: Dict[str, PluginRevalidationResult] = {}
    new_plugins_section: Dict[str, Any] = {}

    for plugin_name, plugin_section in report.get("plugins", {}).items():
        old_entries: List[dict] = list(plugin_section.get("entries", []))
        result = PluginRevalidationResult(plugin=plugin_name, reran=False)

        if not _is_plugin_affected(plugin_section, change_set):
            result.retained_entries = old_entries
            new_plugins_section[plugin_name] = plugin_section
            plugin_results[plugin_name] = result
            continue

        result.reran = True
        affected_ids = set()
        for entry in old_entries:
            invalid = stale_refs(_entry_refs(entry), change_set)
            if not invalid:
                result.retained_entries.append(entry)
                continue
            entry_id = _entry_id(entry)
            affected_ids.add(entry_id)
            for ref in invalid:
                if ref not in result.stale_refs:
                    result.stale_refs.append(ref)
            reasons: List[str] = []
            for ref in invalid:
                reasons.extend(_stale_reasons(ref, change_set))
            result.revoked_entries.append(
                RevokedEntry(
                    plugin=plugin_name,
                    entry_id=entry_id,
                    entry=entry,
                    stale_refs=invalid,
                    reasons=sorted(set(reasons)),
                )
            )

        plugin_class = plugin_by_name.get(plugin_name)
        plugin = None
        fresh_entries: List[dict] = []
        if plugin_class is not None:
            plugin = plugin_class(supplemented_source)
            if hasattr(plugin, "can_run") and not plugin.can_run():
                plugin = None
            else:
                plugin.run()
                fresh_entries = list(plugin.entries) if isinstance(plugin.entries, list) else []
        else:
            logger.warning("No plugin class registered for %s; stale entries stay revoked", plugin_name)

        old_ids = {_entry_id(entry) for entry in old_entries}
        for entry in fresh_entries:
            entry_id = _entry_id(entry)
            if entry_id in affected_ids:
                result.refreshed_entries.append(entry)
            elif entry_id not in old_ids:
                result.new_entries.append(entry)

        refreshed_ids = {_entry_id(entry) for entry in result.refreshed_entries}
        new_ids = {_entry_id(entry) for entry in result.new_entries}
        keep_fresh_ids = refreshed_ids | new_ids
        merged_entries = list(result.retained_entries)
        merged_entries.extend(entry for entry in fresh_entries if _entry_id(entry) in keep_fresh_ids)

        new_section = {
            "plugin_class": plugin_section.get("plugin_class"),
            "entries": merged_entries,
            "evidence": (
                plugin.finalize_evidence()
                if plugin_class is not None and plugin is not None
                else plugin_section.get("evidence")
            ),
        }
        new_plugins_section[plugin_name] = new_section
        plugin_results[plugin_name] = result

    new_report = {
        "report_version": REPORT_VERSION,
        "generated_at": _utc_now_iso(),
        "hive_type": getattr(supplemented_source, "hive_type", report.get("hive_type")),
        "source": {
            "path": source_path,
            "sha1": source_hash or (_hash_file(source_path) if source_path and os.path.exists(source_path) else None),
        },
        "baseline_snapshot": supplemented.to_dict(),
        "previous_source": report.get("source"),
        "plugins": new_plugins_section,
        "revalidation_history": report.get("revalidation_history", [])
        + [
            {
                "revalidated_at": _utc_now_iso(),
                "change_set": change_set.to_dict(),
                "revocation_scope": [item.to_dict() for item in _flatten_revocations(plugin_results)],
                "affected_plugins": [name for name, item in plugin_results.items() if item.reran],
            }
        ],
    }

    archived_path: Optional[str] = None
    if report_path:
        archived_path = save_report(new_report, report_path) or None

    return RevalidationResult(
        change_set=change_set,
        plugin_results=plugin_results,
        report_path=report_path,
        archive_path=archived_path,
        report=new_report,
    )
