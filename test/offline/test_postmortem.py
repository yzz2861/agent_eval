from dataclasses import replace

from pip_audit._offline.model import AdvisoryStatus, ReviewView
from pip_audit._offline.postmortem import compare_reports, trace_snapshots
from pip_audit._offline.rules import OfflineReviewEngine


def test_trace_as_of_known_ignores_late_bulletin(first_snapshot, second_snapshot, timestamps):
    result = trace_snapshots(
        [first_snapshot, second_snapshot],
        timestamps["nov2"],
        ReviewView.AsOfKnown,
    )
    counts = [report.summary()["vulnerability_count"] for report in result.reports]
    assert counts == [1, 1]
    assert result.first_change().snapshot_id == "snap-1"
    assert result.changes[1].changed is False


def test_trace_today_attributes_change_to_specific_snapshot(
    first_snapshot, second_snapshot, timestamps
):
    result = trace_snapshots(
        [first_snapshot, second_snapshot],
        timestamps["nov2"],
        ReviewView.Today,
    )
    change = result.changes[1]
    assert change.snapshot_id == "snap-2"
    assert (change.before_count, change.after_count) == (1, 2)
    assert ("foo", "PYSEC-LATE") in change.added
    assert ("foo", "PYSEC-LATE") in change.late_attributed
    assert result.first_change().snapshot_id == "snap-1"
    explanation = "\n".join(result.explain())
    assert "snapshot snap-2: 1 -> 2 findings" in explanation
    assert "received after the cutoff" in explanation


def test_trace_follow_correction_then_withdrawal(
    first_snapshot, second_snapshot, corrected_late, late_advisory, timestamps
):
    corrected_snapshot = second_snapshot.with_corrections(
        [corrected_late], new_id="snap-3", created_at=timestamps["nov5"]
    )
    withdrawn = replace(
        late_advisory,
        status=AdvisoryStatus.Withdrawn,
        withdrawn_at=timestamps["nov5"],
    )
    withdrawn_snapshot = corrected_snapshot.with_corrections(
        [withdrawn], new_id="snap-4", created_at=timestamps["nov5"]
    )

    result = trace_snapshots(
        [first_snapshot, second_snapshot, corrected_snapshot, withdrawn_snapshot],
        timestamps["nov2"],
        ReviewView.Today,
    )
    assert result.changes[2].corrected_attributed == [("foo", "PYSEC-LATE")]
    assert ("foo", "PYSEC-LATE") in result.changes[3].removed
    final_counts = [report.summary()["vulnerability_count"] for report in result.reports]
    assert final_counts == [1, 2, 2, 1]


def test_compare_reports_handles_first_report(second_snapshot, timestamps):
    report = OfflineReviewEngine(second_snapshot).review(timestamps["nov2"], ReviewView.AsOfKnown)
    change = compare_reports(None, report)
    assert change.previous_snapshot_id is None
    assert change.before_count == 0
    assert change.after_count == 1
