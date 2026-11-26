from dataclasses import replace

import pytest
from packaging.version import Version

from pip_audit._offline.model import AdvisoryStatus, ReviewView
from pip_audit._offline.rules import (
    OfflineReviewEngine,
    default_disposition,
    parse_affected_range,
)


def test_parse_affected_range_wildcard_includes_every_version():
    assert Version("9.9.9") in parse_affected_range("")
    assert Version("9.9.9") in parse_affected_range("*")


def test_as_of_known_excludes_late_advisory(second_snapshot, timestamps):
    report = OfflineReviewEngine(second_snapshot).review(timestamps["nov2"], ReviewView.AsOfKnown)
    visible = {finding.advisory_id for finding in report.visible_findings}
    hidden = {finding.advisory_id: finding for finding in report.findings}

    assert visible == {"PYSEC-OLD"}
    assert report.summary()["vulnerability_count"] == 1
    assert hidden["PYSEC-LATE"].visible is False
    assert hidden["PYSEC-LATE"].late_received is True
    assert "not-yet-received-at-cutoff" in hidden["PYSEC-LATE"].reasons


def test_today_view_surfaces_late_advisory_with_attribution(second_snapshot, timestamps):
    report = OfflineReviewEngine(second_snapshot).review(timestamps["nov2"], ReviewView.Today)
    visible = {finding.advisory_id: finding for finding in report.visible_findings}

    assert set(visible) == {"PYSEC-OLD", "PYSEC-LATE"}
    assert report.summary()["vulnerability_count"] == 2
    assert report.summary()["late_count"] == 1
    assert "late-received-after-cutoff" in visible["PYSEC-LATE"].reasons


def test_placeholder_package_is_never_counted(second_snapshot, timestamps):
    report = OfflineReviewEngine(second_snapshot).review(timestamps["nov3"], ReviewView.Today)
    placeholders = report.skipped_placeholders
    assert [deployment.name for deployment in placeholders] == ["ghost-pkg"]
    assert all(not finding.visible for finding in report.findings if finding.placeholder)
    assert report.summary()["placeholder_count"] == 1
    # The placeholder must not inflate either package or vulnerability totals.
    assert report.summary()["vulnerable_package_count"] == 1


def test_corrected_advisory_flagged_in_today_view(second_snapshot, corrected_late, timestamps):
    snapshot = second_snapshot.with_corrections(
        [corrected_late], new_id="snap-3", created_at=timestamps["nov5"]
    )
    report = OfflineReviewEngine(snapshot).review(timestamps["nov2"], ReviewView.Today)
    corrected = next(finding for finding in report.findings if finding.advisory_id == "PYSEC-LATE")
    assert corrected.visible is True
    assert corrected.corrected_after_cutoff is True
    assert report.summary()["corrected_count"] == 1


def test_withdrawn_advisory_hidden_in_today_view(second_snapshot, late_advisory, timestamps):
    withdrawn = replace(
        late_advisory,
        status=AdvisoryStatus.Withdrawn,
        withdrawn_at=timestamps["nov5"],
    )
    snapshot = second_snapshot.with_corrections(
        [withdrawn], new_id="snap-4", created_at=timestamps["nov5"]
    )
    report = OfflineReviewEngine(snapshot).review(timestamps["nov2"], ReviewView.Today)
    visible = {finding.advisory_id for finding in report.visible_findings}
    assert "PYSEC-LATE" not in visible


def test_disposition_is_preserved_on_findings(first_snapshot, timestamps):
    from pip_audit._offline.model import DispositionAction, DispositionRecord

    disposition = DispositionRecord(
        advisory_id="PYSEC-OLD",
        package="foo",
        action=DispositionAction.Upgrade,
        rule_version="rules-1",
        target_version=Version("1.1.0"),
    )
    snapshot = _with_disposition(first_snapshot, disposition)
    report = OfflineReviewEngine(snapshot).review(timestamps["nov2"], ReviewView.AsOfKnown)
    finding = report.visible_findings[0]
    assert finding.disposition == disposition


def _with_disposition(snapshot, disposition):
    return replace(snapshot, dispositions=[disposition])


def test_default_disposition_upgrades_when_fix_exists(old_advisory, deployments):
    deployment = next(item for item in deployments if item.name == "foo")
    disposition = default_disposition(old_advisory, deployment, rule_version="rules-1")
    assert disposition.action.value == "upgrade"
    assert disposition.target_version == Version("1.1.0")
    assert disposition.rule_version == "rules-1"


def test_default_disposition_monitors_without_fix(late_advisory, deployments):
    advisory = replace(late_advisory, fix_versions=[])
    deployment = next(item for item in deployments if item.name == "foo")
    disposition = default_disposition(advisory, deployment)
    assert disposition.action.value == "monitor"
    assert disposition.target_version is None


@pytest.mark.parametrize("view", list(ReviewView))
def test_unaffected_version_produces_no_finding(second_snapshot, timestamps, view):
    deployment = next(item for item in second_snapshot.deployments if item.name == "foo")
    patched = replace(deployment, version=Version("2.0.0"))
    snapshot = replace(
        second_snapshot,
        deployments=[patched, *[d for d in second_snapshot.deployments if d.name != "foo"]],
    )
    report = OfflineReviewEngine(snapshot).review(timestamps["nov3"], view)
    assert report.summary()["vulnerability_count"] == 0
