"""
Tests for dispute review records on offline audit results.
"""

from pathlib import Path

import pytest
from packaging.version import Version

from pip_audit._dispute import (
    DimensionReview,
    DimensionVerdict,
    DisputeReviewRecord,
    DisputeStatus,
    apply_dispute_review,
    distribution_source_for_requirement,
    dump_dispute_records,
    load_dispute_records,
)
from pip_audit._service.interface import (
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
)

PYPI_MANIFEST = "demo-pkg==1.3.0"
MIRROR_MANIFEST = "demo-pkg @ https://mirror.vendor.example/wheels/demo-pkg-1.3.0-py3-none-any.whl"

VULN_ID = "PYSEC-2099-0001"
VULN_ALIAS = "CVE-2099-00001"
VULN_DESCRIPTION = "demo-pkg 1.3.0 allows remote code execution via crafted metadata"


def _vuln():
    return VulnerabilityResult.create(
        ids=[VULN_ID, VULN_ALIAS],
        description=VULN_DESCRIPTION,
        fix_versions=[Version("1.3.1")],
        published=None,
    )


def _dep():
    return ResolvedDependency(name="demo-pkg", version=Version("1.3.0"))


def _record(
    distribution_source,
    source_verdict,
    source_summary,
    version_verdict=DimensionVerdict.INCONCLUSIVE,
    publisher_verdict=DimensionVerdict.INCONCLUSIVE,
):
    return DisputeReviewRecord(
        package="demo-pkg",
        version=Version("1.3.0"),
        vulnerability_id=VULN_ID,
        distribution_source=distribution_source,
        prior_disposition="action_required",
        version_review=DimensionReview(
            version_verdict, "advisory does not enumerate affected versions per source"
        ),
        source_review=DimensionReview(source_verdict, source_summary),
        publisher_review=DimensionReview(
            publisher_verdict, "vendor claims the advisory only covers another source"
        ),
    )


def test_distribution_source_for_requirement():
    assert distribution_source_for_requirement(PYPI_MANIFEST) == "pypi"
    assert (
        distribution_source_for_requirement(MIRROR_MANIFEST) == "direct-url:mirror.vendor.example"
    )
    assert (
        distribution_source_for_requirement(
            "demo-pkg @ https://mirror.vendor.example/pkg.whl ; python_version >= '3.10'"
        )
        == "direct-url:mirror.vendor.example"
    )


def test_clear_scope_evidence_resolves_dispute():
    record = _record(
        "pypi",
        DimensionVerdict.SUPPORTS_DISPUTE,
        "advisory scope list names only mirror.vendor.example artifacts",
    )

    assert record.status is DisputeStatus.RESOLVED_OUT_OF_SCOPE
    assert not record.in_pending_queue
    assert not record.keeps_risk_display
    assert not record.keeps_prior_signoff


def test_inconclusive_scope_evidence_keeps_dispute_unresolved():
    record = _record(
        "direct-url:mirror.vendor.example",
        DimensionVerdict.INCONCLUSIVE,
        "available scope evidence does not conclusively exclude the mirror",
    )

    assert record.status is DisputeStatus.UNRESOLVED
    assert record.in_pending_queue
    assert record.keeps_risk_display
    assert record.keeps_prior_signoff


def test_publisher_statement_alone_does_not_resolve():
    record = _record(
        "pypi",
        DimensionVerdict.INCONCLUSIVE,
        "no independent scope evidence available",
        publisher_verdict=DimensionVerdict.SUPPORTS_DISPUTE,
    )

    assert record.status is DisputeStatus.UNRESOLVED
    assert record.in_pending_queue


def test_refuting_dimension_blocks_resolution():
    record = _record(
        "pypi",
        DimensionVerdict.SUPPORTS_DISPUTE,
        "advisory scope list names only mirror.vendor.example artifacts",
        publisher_verdict=DimensionVerdict.REFUTES_DISPUTE,
    )

    assert record.status is DisputeStatus.UNRESOLVED
    assert record.in_pending_queue


def test_record_matches_by_alias_and_source():
    record = _record("pypi", DimensionVerdict.INCONCLUSIVE, "no evidence")

    # Matches on the vulnerability alias as well as the primary ID.
    assert record.matches(_dep(), _vuln(), "pypi")
    # A record for one source never applies to a finding from another.
    assert not record.matches(_dep(), _vuln(), "direct-url:mirror.vendor.example")
    # Skipped or differently-versioned dependencies never match.
    assert not record.matches(
        SkippedDependency(name="demo-pkg", skip_reason="not installed"), _vuln(), "pypi"
    )
    assert not record.matches(
        ResolvedDependency(name="demo-pkg", version=Version("2.0.0")), _vuln(), "pypi"
    )


def test_two_manifests_same_version_only_clear_scope_evidence_exits_queue():
    pypi_record = _record(
        "pypi",
        DimensionVerdict.SUPPORTS_DISPUTE,
        "advisory scope list names only mirror.vendor.example artifacts; "
        "PyPI distributions are explicitly out of scope",
    )
    mirror_record = _record(
        "direct-url:mirror.vendor.example",
        DimensionVerdict.INCONCLUSIVE,
        "available scope evidence does not conclusively exclude the mirror",
        publisher_verdict=DimensionVerdict.SUPPORTS_DISPUTE,
    )
    records = [pypi_record, mirror_record]

    reports = {}
    for line in (PYPI_MANIFEST, MIRROR_MANIFEST):
        source = distribution_source_for_requirement(line)
        reports[source] = apply_dispute_review(
            [(_dep(), [_vuln()])],
            records,
            distribution_source=source,
        )

    pypi_report = reports["pypi"]
    mirror_report = reports["direct-url:mirror.vendor.example"]

    # Only the PyPI-sourced manifest has clear scope evidence, so only its
    # finding leaves the pending queue.
    assert pypi_report.pending == []
    assert len(pypi_report.resolved) == 1
    assert pypi_report.resolved[0].status is DisputeStatus.RESOLVED_OUT_OF_SCOPE

    # The mirror-sourced manifest stays pending, keeping both its risk
    # display and the prior first-line sign-off.
    assert mirror_report.resolved == []
    assert len(mirror_report.pending) == 1
    pending = mirror_report.pending[0]
    assert pending.keeps_risk_display
    assert pending.keeps_prior_signoff
    assert pending.record is not None
    assert pending.record.prior_disposition == "action_required"

    # Each report shows the three review dimensions independently.
    rendered = mirror_report.render()
    assert "version: inconclusive" in rendered
    assert "distribution-source evidence: inconclusive" in rendered
    assert "publisher statement: supports_dispute" in rendered
    assert "status: unresolved" in rendered
    assert "pending queue: retained" in rendered
    assert f"risk display: retained ({VULN_DESCRIPTION})" in rendered
    assert "prior sign-off: retained (action_required)" in rendered

    rendered = pypi_report.render()
    assert "status: resolved_out_of_scope" in rendered
    assert "pending queue: released" in rendered
    assert "distribution-source evidence: supports_dispute" in rendered
    assert "risk display" not in rendered
    assert "prior sign-off" not in rendered


def test_unreviewed_finding_stays_pending():
    report = apply_dispute_review(
        [(_dep(), [_vuln()])],
        [],
        distribution_source="pypi",
    )

    assert len(report.pending) == 1
    entry = report.pending[0]
    assert entry.record is None
    assert entry.keeps_risk_display
    assert not entry.keeps_prior_signoff
    assert "no dispute review record" in report.render()


def test_record_for_other_source_does_not_apply():
    pypi_record = _record(
        "pypi",
        DimensionVerdict.SUPPORTS_DISPUTE,
        "advisory scope list names only mirror.vendor.example artifacts",
    )

    report = apply_dispute_review(
        [(_dep(), [_vuln()])],
        [pypi_record],
        distribution_source="direct-url:mirror.vendor.example",
    )

    assert len(report.pending) == 1
    assert report.pending[0].record is None


def test_json_roundtrip(tmp_path: Path):
    records = [
        _record(
            "pypi",
            DimensionVerdict.SUPPORTS_DISPUTE,
            "advisory scope list names only mirror.vendor.example artifacts",
        ),
        _record(
            "direct-url:mirror.vendor.example",
            DimensionVerdict.INCONCLUSIVE,
            "available scope evidence does not conclusively exclude the mirror",
            publisher_verdict=DimensionVerdict.SUPPORTS_DISPUTE,
        ),
    ]

    path = tmp_path / "dispute-records.json"
    dump_dispute_records(records, path)
    loaded = load_dispute_records(path)

    assert loaded == records
    assert loaded[0].status is DisputeStatus.RESOLVED_OUT_OF_SCOPE
    assert loaded[1].status is DisputeStatus.UNRESOLVED


def test_report_pending_and_resolved_partition_entries():
    report = apply_dispute_review(
        [(_dep(), [_vuln()])],
        [_record("pypi", DimensionVerdict.SUPPORTS_DISPUTE, "clear scope evidence")],
        distribution_source="pypi",
    )

    assert len(report.entries) == 1
    assert report.pending == []
    assert len(report.resolved) == 1


@pytest.mark.parametrize("source", ["pypi", "direct-url:mirror.vendor.example"])
def test_unresolved_dispute_retains_risk_and_signoff(source):
    record = _record(source, DimensionVerdict.INCONCLUSIVE, "no conclusive evidence")
    report = apply_dispute_review(
        [(_dep(), [_vuln()])],
        [record],
        distribution_source=source,
    )

    (entry,) = report.pending
    assert entry.keeps_risk_display
    assert entry.keeps_prior_signoff
