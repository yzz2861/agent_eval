"""
Dispute review records for offline audit results.

This module implements "dispute review" for findings carried by an earlier
(offline) audit: when a vendor or publisher disputes a finding -- for example,
claiming that an advisory only covers a different distribution source -- the
dispute is recorded and reviewed along three independent dimensions (version,
distribution-source evidence, and publisher statement), then reconciled
against the disposition that first-line triage has already recorded.

A disputed finding leaves the pending queue only when the distribution-source
evidence conclusively supports the dispute and no review dimension refutes
it. While a dispute remains unresolved, the finding keeps both its risk
display and any prior sign-off (such as an "action required" disposition
recorded by first-line triage).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
)


class DimensionVerdict(str, Enum):
    """
    The verdict of a single dispute-review dimension.
    """

    SUPPORTS_DISPUTE = "supports_dispute"
    """
    The dimension's evidence supports the dispute (the finding is out of scope).
    """

    REFUTES_DISPUTE = "refutes_dispute"
    """
    The dimension's evidence refutes the dispute (the finding remains in scope).
    """

    INCONCLUSIVE = "inconclusive"
    """
    The dimension's evidence is inconclusive.
    """


class DisputeStatus(str, Enum):
    """
    The reconciled status of a disputed finding.
    """

    UNRESOLVED = "unresolved"
    """
    The dispute is still pending; the finding remains in the pending queue.
    """

    RESOLVED_OUT_OF_SCOPE = "resolved_out_of_scope"
    """
    The dispute is resolved in the disputer's favor; the finding leaves the
    pending queue.
    """


@dataclass(frozen=True)
class DimensionReview:
    """
    The independent conclusion of a single dispute-review dimension.
    """

    verdict: DimensionVerdict
    """
    The dimension's verdict.
    """

    summary: str
    """
    A human-readable summary of the evidence behind the verdict.
    """

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable representation of this review.
        """
        return {"verdict": self.verdict.value, "summary": self.summary}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DimensionReview:
        """
        Construct a DimensionReview from its JSON representation.
        """
        return cls(verdict=DimensionVerdict(data["verdict"]), summary=data["summary"])


@dataclass(frozen=True)
class DisputeReviewRecord:
    """
    A dispute review record for a single finding from an offline audit result.

    Each record keeps the three review dimensions (version, distribution-source
    evidence, and publisher statement) independent of one another, alongside
    the disposition that first-line triage recorded before the dispute.
    """

    package: str
    """
    The package the disputed finding applies to.
    """

    version: Version
    """
    The package version the disputed finding applies to.
    """

    vulnerability_id: str
    """
    The identifier of the disputed vulnerability (or one of its aliases).
    """

    distribution_source: str
    """
    The distribution source of the disputed finding, as derived from the
    dependency manifest (see distribution_source_for_requirement).
    """

    prior_disposition: str
    """
    The disposition recorded by first-line triage before the dispute, e.g.
    "action_required".
    """

    version_review: DimensionReview
    """
    The independent conclusion of the version dimension.
    """

    source_review: DimensionReview
    """
    The independent conclusion of the distribution-source evidence dimension.
    """

    publisher_review: DimensionReview
    """
    The independent conclusion of the publisher statement dimension.
    """

    @property
    def canonical_name(self) -> str:
        """
        The record's PEP-503 canonicalized package name.
        """
        return canonicalize_name(self.package)

    @property
    def status(self) -> DisputeStatus:
        """
        The reconciled status of the dispute.

        A dispute is resolved (out of scope) only when the distribution-source
        evidence conclusively supports it and no review dimension refutes it.
        A publisher statement on its own is never sufficient to resolve a
        dispute, and any refuting dimension keeps the dispute unresolved.
        """
        verdicts = (
            self.version_review.verdict,
            self.source_review.verdict,
            self.publisher_review.verdict,
        )
        if (
            self.source_review.verdict is DimensionVerdict.SUPPORTS_DISPUTE
            and DimensionVerdict.REFUTES_DISPUTE not in verdicts
        ):
            return DisputeStatus.RESOLVED_OUT_OF_SCOPE
        return DisputeStatus.UNRESOLVED

    @property
    def in_pending_queue(self) -> bool:
        """
        Whether the disputed finding remains in the pending queue.
        """
        return self.status is DisputeStatus.UNRESOLVED

    @property
    def keeps_risk_display(self) -> bool:
        """
        Whether the finding's risk display is retained.

        The risk display is retained for as long as the dispute is unresolved.
        """
        return self.in_pending_queue

    @property
    def keeps_prior_signoff(self) -> bool:
        """
        Whether the prior sign-off (disposition) is retained.

        The prior sign-off is retained for as long as the dispute is
        unresolved.
        """
        return self.in_pending_queue

    def matches(
        self,
        dep: Dependency,
        vuln: VulnerabilityResult,
        distribution_source: str | None = None,
    ) -> bool:
        """
        Return whether this record applies to the given finding.

        A record applies when the package, version, and vulnerability
        identifier (or one of its aliases) match. When the finding's
        distribution source is known, it must also match the record's
        distribution source, so that records for one source never resolve
        findings from another.
        """
        if not isinstance(dep, ResolvedDependency):
            return False
        if dep.canonical_name != self.canonical_name or dep.version != self.version:
            return False
        if not vuln.has_any_id({self.vulnerability_id}):
            return False
        return not (
            distribution_source is not None and distribution_source != self.distribution_source
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serializable representation of this record.
        """
        return {
            "package": self.package,
            "version": str(self.version),
            "vulnerability_id": self.vulnerability_id,
            "distribution_source": self.distribution_source,
            "prior_disposition": self.prior_disposition,
            "version_review": self.version_review.to_dict(),
            "source_review": self.source_review.to_dict(),
            "publisher_review": self.publisher_review.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DisputeReviewRecord:
        """
        Construct a DisputeReviewRecord from its JSON representation.
        """
        return cls(
            package=data["package"],
            version=Version(data["version"]),
            vulnerability_id=data["vulnerability_id"],
            distribution_source=data["distribution_source"],
            prior_disposition=data.get("prior_disposition", "action_required"),
            version_review=DimensionReview.from_dict(data["version_review"]),
            source_review=DimensionReview.from_dict(data["source_review"]),
            publisher_review=DimensionReview.from_dict(data["publisher_review"]),
        )


@dataclass(frozen=True)
class ReviewedFinding:
    """
    A single offline finding reconciled against its dispute review record.
    """

    package: str
    """
    The finding's package name.
    """

    version: Version
    """
    The finding's package version.
    """

    vulnerability_id: str
    """
    The finding's vulnerability identifier.
    """

    description: str
    """
    The finding's human-readable risk description.
    """

    distribution_source: str
    """
    The distribution source the finding was observed in, or "unknown".
    """

    record: DisputeReviewRecord | None
    """
    The dispute review record for this finding, or None if the finding
    has not been reviewed.
    """

    @property
    def status(self) -> DisputeStatus:
        """
        The finding's reconciled status.

        Findings without a dispute review record are always unresolved.
        """
        if self.record is None:
            return DisputeStatus.UNRESOLVED
        return self.record.status

    @property
    def in_pending_queue(self) -> bool:
        """
        Whether the finding remains in the pending queue.
        """
        return self.status is DisputeStatus.UNRESOLVED

    @property
    def keeps_risk_display(self) -> bool:
        """
        Whether the finding risk display is retained.
        """
        return self.in_pending_queue

    @property
    def keeps_prior_signoff(self) -> bool:
        """
        Whether the finding's prior sign-off (disposition) is retained.
        """
        return self.record is not None and self.record.keeps_prior_signoff


@dataclass(frozen=True)
class DisputeReviewReport:
    """
    The result of reconciling offline audit findings against dispute review
    records.
    """

    entries: list[ReviewedFinding]
    """
    Every reconciled finding, in audit order.
    """

    @property
    def pending(self) -> list[ReviewedFinding]:
        """
        The findings that remain in the pending queue.
        """
        return [entry for entry in self.entries if entry.in_pending_queue]

    @property
    def resolved(self) -> list[ReviewedFinding]:
        """
        The findings whose disputes were resolved, leaving the pending queue.
        """
        return [entry for entry in self.entries if not entry.in_pending_queue]

    def render(self) -> str:
        """
        Render the report as a human-readable string.

        Each entry shows the three review dimensions independently. Unresolved
        entries retain both their risk display and their prior sign-off.
        """
        lines: list[str] = []
        for entry in self.entries:
            lines.append(
                f"{entry.vulnerability_id}: {entry.package} {entry.version} "
                f"(source: {entry.distribution_source})"
            )
            record = entry.record
            if record is None:
                lines.append("  status: unresolved (no dispute review record)")
                lines.append("  pending queue: retained")
                lines.append(f"  risk display: retained ({entry.description})")
                continue
            lines.append(f"  status: {entry.status.value}")
            queue = "retained" if entry.in_pending_queue else "released"
            lines.append(f"  pending queue: {queue}")
            lines.append(
                f"  version: {record.version_review.verdict.value} "
                f"({record.version_review.summary})"
            )
            lines.append(
                f"  distribution-source evidence: {record.source_review.verdict.value} "
                f"({record.source_review.summary})"
            )
            lines.append(
                f"  publisher statement: {record.publisher_review.verdict.value} "
                f"({record.publisher_review.summary})"
            )
            if entry.keeps_risk_display:
                lines.append(f"  risk display: retained ({entry.description})")
            if entry.keeps_prior_signoff:
                lines.append(f"  prior sign-off: retained ({record.prior_disposition})")
        return "\n".join(lines)


def distribution_source_for_requirement(line: str) -> str:
    """
    Derive a distribution-source label from a single requirement line.

    Direct references (name @ URL) are labeled by their URL host as
    "direct-url:<host>"; all other requirements are assumed to resolve
    against the default package index and are labeled "pypi".
    """
    line = line.strip()
    if " @ " in line:
        url = line.split(" @ ", 1)[1].split(";", 1)[0].strip()
        host = urlparse(url).netloc
        return f"direct-url:{host}" if host else f"direct-url:{url}"
    return "pypi"


def apply_dispute_review(
    results: Iterable[tuple[Dependency, list[VulnerabilityResult]]],
    records: Iterable[DisputeReviewRecord],
    *,
    distribution_source: str | None = None,
) -> DisputeReviewReport:
    """
    Reconcile offline audit results against dispute review records.

    "results" is a collection of (dependency, vulnerabilities) pairs, as
    produced by Auditor.audit. "distribution_source" is the distribution
    source label shared by the audited manifest (see
    distribution_source_for_requirement); when given, only records for that
    source can match the findings.

    Every vulnerability found becomes an entry in the returned report:
    findings matched by a record carry that record's independent conclusions,
    while unmatched findings remain unresolved in the pending queue.
    """
    records = list(records)
    entries: list[ReviewedFinding] = []
    for dep, vulns in results:
        if not isinstance(dep, ResolvedDependency):
            continue
        for vuln in vulns:
            record = next(
                (r for r in records if r.matches(dep, vuln, distribution_source)),
                None,
            )
            source = distribution_source or (record.distribution_source if record else "unknown")
            entries.append(
                ReviewedFinding(
                    package=dep.name,
                    version=dep.version,
                    vulnerability_id=str(vuln.id),
                    description=vuln.description,
                    distribution_source=source,
                    record=record,
                )
            )
    return DisputeReviewReport(entries=entries)


def load_dispute_records(path: Path) -> list[DisputeReviewRecord]:
    """
    Load dispute review records from a JSON file.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    return [DisputeReviewRecord.from_dict(item) for item in data]


def dump_dispute_records(records: Iterable[DisputeReviewRecord], path: Path) -> None:
    """
    Write dispute review records to a JSON file.
    """
    path.write_text(
        json.dumps([record.to_dict() for record in records], indent=2),
        encoding="utf-8",
    )
