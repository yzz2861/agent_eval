"""
Postmortem support: explain *which snapshot* changed a historical report.

Given the same historical cutoff, reports can be recomputed against every
snapshot on record. Comparing consecutive snapshots pinpoints the exact
snapshot (and the exact advisory records) responsible for a change in the
headline daily-report counts -- e.g. a bulletin that arrived two days late and
was incorrectly folded into an earlier "known risk" total.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from pip_audit._offline.model import ReviewView, Snapshot
from pip_audit._offline.rules import OfflineReviewEngine, ReviewFinding, ReviewReport


def finding_key(finding: ReviewFinding) -> tuple[str, str]:
    """Stable identity of a finding across recomputations."""
    return (finding.package, finding.advisory_id)


@dataclass(frozen=True)
class SnapshotChange:
    """The delta in a report caused by moving to one new snapshot."""

    previous_snapshot_id: str | None
    snapshot_id: str
    added: list[tuple[str, str]] = field(default_factory=list)
    removed: list[tuple[str, str]] = field(default_factory=list)
    late_attributed: list[tuple[str, str]] = field(default_factory=list)
    corrected_attributed: list[tuple[str, str]] = field(default_factory=list)
    before_count: int = 0
    after_count: int = 0

    @property
    def changed(self) -> bool:
        """Whether moving to this snapshot altered the report in any way."""
        return bool(self.added or self.removed or self.late_attributed or self.corrected_attributed)


@dataclass(frozen=True)
class PostmortemResult:
    """
    The full trace of how a cross-section's report evolved over snapshots.
    """

    cutoff: datetime
    view: ReviewView
    reports: list[ReviewReport]
    changes: list[SnapshotChange]

    def explain(self) -> list[str]:
        """Return human-readable lines attributing each count change."""
        lines: list[str] = []
        for change in self.changes:
            if not change.changed:
                lines.append(
                    f"snapshot {change.snapshot_id}: no change ({change.after_count} findings)"
                )
                continue

            lines.append(
                f"snapshot {change.snapshot_id}: {change.before_count} -> "
                f"{change.after_count} findings"
            )
            for package, advisory_id in change.added:
                lines.append(f"  + {package} / {advisory_id}: newly counted")
            for package, advisory_id in change.removed:
                lines.append(f"  - {package} / {advisory_id}: no longer counted")
            for package, advisory_id in change.late_attributed:
                lines.append(f"  ~ {package} / {advisory_id}: advisory received after the cutoff")
            for package, advisory_id in change.corrected_attributed:
                lines.append(
                    f"  ~ {package} / {advisory_id}: advisory corrected/withdrawn after cutoff"
                )
        return lines

    def first_change(self) -> SnapshotChange | None:
        """Return the first snapshot that actually moved the report counts."""
        return next((change for change in self.changes if change.changed), None)


def compare_reports(
    previous: ReviewReport | None,
    current: ReviewReport,
) -> SnapshotChange:
    """Diff two consecutive reports for the same cross-section."""
    previous_visible = (
        {finding_key(finding) for finding in previous.visible_findings}
        if previous is not None
        else set()
    )
    current_visible = {finding_key(finding) for finding in current.visible_findings}

    current_index = {
        finding_key(finding): finding for finding in current.findings if finding.visible
    }

    added = sorted(current_visible - previous_visible)
    removed = sorted(previous_visible - current_visible)
    late_attributed = sorted(key for key, finding in current_index.items() if finding.late_received)
    corrected_attributed = sorted(
        key for key, finding in current_index.items() if finding.corrected_after_cutoff
    )

    return SnapshotChange(
        previous_snapshot_id=previous.snapshot_id if previous is not None else None,
        snapshot_id=current.snapshot_id,
        added=added,
        removed=removed,
        late_attributed=late_attributed,
        corrected_attributed=corrected_attributed,
        before_count=len(previous_visible),
        after_count=len(current_visible),
    )


def trace_snapshots(
    snapshots: list[Snapshot],
    cutoff: datetime,
    view: ReviewView,
) -> PostmortemResult:
    """
    Recompute one historical cross-section against every snapshot in order.

    The resulting `PostmortemResult` names the precise snapshot at which each
    finding appeared or disappeared, and whether the cause was a late receipt
    or a later correction/withdrawal.
    """
    reports: list[ReviewReport] = []
    changes: list[SnapshotChange] = []
    previous_report: ReviewReport | None = None

    for snapshot in snapshots:
        report = OfflineReviewEngine(snapshot).review(cutoff, view)
        reports.append(report)
        changes.append(compare_reports(previous_report, report))
        previous_report = report

    return PostmortemResult(
        cutoff=cutoff,
        view=view,
        reports=reports,
        changes=changes,
    )
