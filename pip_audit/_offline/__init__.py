"""
Offline, dual-time historical review support for `pip-audit`.

This subpackage is fully offline: snapshots capture advisory effective/received
timestamps, deployment scope (including never-deployed placeholders) and the
dispositions produced under the rules in force at the time, so that any
historical cross-section can be recomputed from both an "as known then" and a
"looking back today" perspective.
"""

from .model import (
    AdvisoryRecord,
    AdvisoryStatus,
    DeploymentRecord,
    DispositionAction,
    DispositionRecord,
    ReviewView,
    Snapshot,
    package_key,
    parse_rfc3339,
    to_rfc3339,
    utcnow,
)
from .postmortem import PostmortemResult, SnapshotChange, compare_reports, trace_snapshots
from .rules import (
    DEFAULT_RULE_VERSION,
    OfflineReviewEngine,
    ReviewFinding,
    ReviewReport,
    affects,
    default_disposition,
    parse_affected_range,
)
from .store import SnapshotStore, SnapshotStoreError

__all__ = [
    "AdvisoryRecord",
    "AdvisoryStatus",
    "DEFAULT_RULE_VERSION",
    "DeploymentRecord",
    "DispositionAction",
    "DispositionRecord",
    "OfflineReviewEngine",
    "PostmortemResult",
    "ReviewFinding",
    "ReviewReport",
    "ReviewView",
    "Snapshot",
    "SnapshotChange",
    "SnapshotStore",
    "SnapshotStoreError",
    "affects",
    "compare_reports",
    "default_disposition",
    "package_key",
    "parse_affected_range",
    "parse_rfc3339",
    "to_rfc3339",
    "trace_snapshots",
    "utcnow",
]
