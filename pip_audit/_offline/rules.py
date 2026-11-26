"""
Dual-time review rules for offline pip-audit snapshots.

The engine is deliberately deterministic and side-effect free: given a
`Snapshot` and a cutoff time it can reproduce either the *as-of-known*
perspective (what the team could actually have known when the report was
written) or the *today* perspective (what the newest snapshot reveals when
looking back at the same cross-section).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pip_audit._offline.model import (
    AdvisoryRecord,
    AdvisoryStatus,
    DeploymentRecord,
    DispositionAction,
    DispositionRecord,
    ReviewView,
    Snapshot,
)

DEFAULT_RULE_VERSION = "rules-1"


def parse_affected_range(spec: str) -> SpecifierSet:
    """
    Parse an advisory's affected-range string into a PEP 440 specifier set.

    An empty string (or the wildcard ``*``) means "every version".
    """
    text = spec.strip()
    if not text or text == "*":
        return SpecifierSet()
    return SpecifierSet(text)


def affects(advisory: AdvisoryRecord, version: Version) -> bool:
    """Return whether `advisory` applies to the given package `version`."""
    return version in parse_affected_range(advisory.affected_range)


@dataclass(frozen=True)
class ReviewFinding:
    """
    A single finding produced for one deployment/advisory pair.

    Time-attribution flags explain *why* a finding is or isn't visible in each
    perspective, which is what the daily-report dispute hinges on:

    * `late_received` -- the advisory was effective before the cutoff but only
      received afterwards, so it could not have been known at report time;
    * `corrected_after_cutoff` -- the record on which the original report was
      based was later corrected or withdrawn;
    * `placeholder` -- the package was never deployed and is tracked only as a
      placeholder, so it can never contribute to a count.
    """

    advisory_id: str
    package: str
    version: Version | None
    effective_at: datetime
    received_at: datetime
    fix_versions: list[Version]
    visible: bool
    late_received: bool
    corrected_after_cutoff: bool
    placeholder: bool
    disposition: DispositionRecord | None = None
    reasons: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ReviewReport:
    """
    The result of recomputing a historical cross-section.
    """

    snapshot_id: str
    view: ReviewView
    cutoff: datetime
    rule_version: str
    findings: list[ReviewFinding] = field(default_factory=list)
    skipped_placeholders: list[DeploymentRecord] = field(default_factory=list)

    @property
    def visible_findings(self) -> list[ReviewFinding]:
        """Return only the findings that count towards the report totals."""
        return [finding for finding in self.findings if finding.visible]

    @property
    def vulnerable_packages(self) -> set[str]:
        """Return the distinct package names with at least one visible finding."""
        return {finding.package for finding in self.visible_findings}

    def summary(self) -> dict[str, object]:
        """Return the headline counts that appear in a daily report."""
        visible = self.visible_findings
        return {
            "snapshot_id": self.snapshot_id,
            "view": self.view.value,
            "cutoff": self.cutoff.isoformat(),
            "rule_version": self.rule_version,
            "vulnerability_count": len(visible),
            "vulnerable_package_count": len(self.vulnerable_packages),
            "placeholder_count": len(self.skipped_placeholders),
            "late_count": len([finding for finding in visible if finding.late_received]),
            "corrected_count": len(
                [finding for finding in visible if finding.corrected_after_cutoff]
            ),
        }


class OfflineReviewEngine:
    """
    Recompute historical audit conclusions from an offline `Snapshot`.

    The engine never performs network access: all advisory, deployment and
    disposition data comes from the snapshot passed to the constructor.
    """

    def __init__(self, snapshot: Snapshot):
        """Create an engine bound to the given immutable snapshot."""
        self._snapshot = snapshot
        self._advisories_by_package: dict[str, list[AdvisoryRecord]] = {}
        for advisory in snapshot.advisories:
            self._advisories_by_package.setdefault(advisory.package_key, []).append(advisory)
        self._dispositions = snapshot.disposition_index()

    @property
    def snapshot(self) -> Snapshot:
        """The snapshot this engine recomputes conclusions from."""
        return self._snapshot

    def review(self, cutoff: datetime, view: ReviewView) -> ReviewReport:
        """
        Recompute the report for the historical cross-section at `cutoff`.
        """
        findings: list[ReviewFinding] = []
        placeholders: list[DeploymentRecord] = []

        for deployment in self._snapshot.deployments:
            if not deployment.deployed or deployment.version is None:
                placeholders.append(deployment)
                findings.append(self._placeholder_finding(deployment, cutoff, view))
                continue

            for advisory in self._advisories_by_package.get(deployment.key, []):
                if not affects(advisory, deployment.version):
                    continue
                findings.append(self._finding(advisory, deployment, cutoff, view))

        return ReviewReport(
            snapshot_id=self._snapshot.id,
            view=view,
            cutoff=cutoff,
            rule_version=self._snapshot.rule_version,
            findings=findings,
            skipped_placeholders=placeholders,
        )

    def _finding(
        self,
        advisory: AdvisoryRecord,
        deployment: DeploymentRecord,
        cutoff: datetime,
        view: ReviewView,
    ) -> ReviewFinding:
        """Build the time-attributed finding for one affected deployment."""
        late_received = advisory.received_at > cutoff
        corrected_after_cutoff = (
            advisory.corrected_at is not None and advisory.corrected_at > cutoff
        ) or (advisory.withdrawn_at is not None and advisory.withdrawn_at > cutoff)

        reasons: set[str] = set()
        if view is ReviewView.AsOfKnown:
            visible = advisory.was_known(cutoff)
            if late_received:
                reasons.add("not-yet-received-at-cutoff")
            if not advisory.is_active(cutoff):
                reasons.add("not-authoritative-at-cutoff")
        else:
            # Today's view trusts the newest snapshot's current state. A record
            # that has since been withdrawn is no longer a finding; corrected
            # records remain visible but are flagged so the change is attributed.
            visible = advisory.status is not AdvisoryStatus.Withdrawn
            if late_received:
                reasons.add("late-received-after-cutoff")
            if corrected_after_cutoff:
                reasons.add("corrected-after-cutoff")

        disposition = self._dispositions.get((advisory.package_key, advisory.id))

        return ReviewFinding(
            advisory_id=advisory.id,
            package=deployment.name,
            version=deployment.version,
            effective_at=advisory.effective_at,
            received_at=advisory.received_at,
            fix_versions=list(advisory.fix_versions),
            visible=visible,
            late_received=late_received,
            corrected_after_cutoff=corrected_after_cutoff,
            placeholder=False,
            disposition=disposition,
            reasons=frozenset(reasons),
        )

    def _placeholder_finding(
        self, deployment: DeploymentRecord, cutoff: datetime, view: ReviewView
    ) -> ReviewFinding:
        """Build the always-hidden row representing a never-deployed package."""
        # Placeholder packages are never counted, regardless of view. We still
        # emit a (hidden) finding row so a reviewer can see the entry exists.
        del cutoff, view
        return ReviewFinding(
            advisory_id="",
            package=deployment.name,
            version=deployment.version,
            effective_at=self._snapshot.created_at,
            received_at=self._snapshot.created_at,
            fix_versions=[],
            visible=False,
            late_received=False,
            corrected_after_cutoff=False,
            placeholder=True,
            disposition=None,
            reasons=frozenset({"never-deployed-placeholder"}),
        )


def default_disposition(
    advisory: AdvisoryRecord,
    deployment: DeploymentRecord,
    *,
    rule_version: str = DEFAULT_RULE_VERSION,
    decided_at: datetime | None = None,
) -> DispositionRecord:
    """
    Produce the rule-based disposition for an affected, deployed package.

    A fixed version yields an ``upgrade`` disposition; anything else is kept
    under ``monitor``. This is the decision "as produced under the rules at
    the time", captured so later rule changes don't rewrite history.
    """
    if advisory.fix_versions:
        target = min(advisory.fix_versions)
        return DispositionRecord(
            advisory_id=advisory.id,
            package=deployment.name,
            action=DispositionAction.Upgrade,
            rule_version=rule_version,
            reason=f"upgrade to {target} resolves {advisory.id}",
            target_version=target,
            decided_at=decided_at,
        )

    return DispositionRecord(
        advisory_id=advisory.id,
        package=deployment.name,
        action=DispositionAction.Monitor,
        rule_version=rule_version,
        reason=f"no fixed version published for {advisory.id}",
        decided_at=decided_at,
    )
