"""Evidence dependency declarations and targeted report revalidation.

Public entry points:

* :class:`EvidenceRef` / :class:`EvidenceKind` - the dependency model, including
  negative evidence (missing keys/values participating in a conclusion).
* :class:`EvidenceAwarePlugin` - base class plugins inherit to declare evidence.
* :class:`RegistryEvidenceSource`, :class:`TrackingEvidenceSource`,
  :class:`DictHive` - registry access layer with automatic lookup tracking.
* :class:`HiveSnapshot` / :class:`ChangeSet` - baseline snapshots and diffs.
* :func:`build_evidence_report`, :func:`save_report`,
  :func:`revalidate_report`, :func:`load_report` - the report lifecycle,
  including old-report archiving and per-entry revocation scopes.
"""

from __future__ import annotations

from regipy.evidence.model import (
    EvidenceKind,
    EvidenceRef,
    normalize_path,
    path_is_within,
)
from regipy.evidence.plugin import EvidenceAwarePlugin, stable_entry_id
from regipy.evidence.recorder import EvidenceRecorder
from regipy.evidence.revalidation import (
    PluginRevalidationResult,
    RevalidationResult,
    RevokedEntry,
    archive_previous_report,
    build_evidence_report,
    load_report,
    revalidate_report,
    save_report,
)
from regipy.evidence.snapshot import (
    Change,
    ChangeSet,
    HiveSnapshot,
    KeyState,
    ValueState,
    build_snapshot,
    diff_snapshots,
    is_evidence_fresh,
    is_ref_stale,
    stale_refs,
)
from regipy.evidence.source import (
    DictHive,
    DictKey,
    EvidenceSource,
    RegistryEvidenceSource,
    TrackingEvidenceSource,
)

__all__ = [
    "Change",
    "ChangeSet",
    "DictHive",
    "DictKey",
    "EvidenceAwarePlugin",
    "EvidenceKind",
    "EvidenceRecorder",
    "EvidenceRef",
    "EvidenceSource",
    "HiveSnapshot",
    "KeyState",
    "PluginRevalidationResult",
    "RegistryEvidenceSource",
    "RevalidationResult",
    "RevokedEntry",
    "TrackingEvidenceSource",
    "ValueState",
    "archive_previous_report",
    "build_evidence_report",
    "build_snapshot",
    "diff_snapshots",
    "is_evidence_fresh",
    "is_ref_stale",
    "load_report",
    "normalize_path",
    "path_is_within",
    "revalidate_report",
    "save_report",
    "stable_entry_id",
    "stale_refs",
]
