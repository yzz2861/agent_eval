"""
Deployment-stage review engine.

Combines three offline inputs into a per-stage re-check:

* a PEP 751 lock file bound to a deployment role (build host, runtime
  image, ...), read by `read_stage_lockfile`,
* a frozen advisory snapshot served by `OfflineAdvisoryService`,
* a role-scoped `ExemptionCatalog` of caller-supplied notices.

Findings are kept per role. An exemption filed against one role never
cancels the same archive finding in another role, and entries targeting
unregistered roles are retained rather than applied.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path

from packaging.version import Version

from pip_audit._deployment.exemption import (
    Exemption,
    ExemptionCatalog,
    ExemptionDecision,
    ExemptionEvaluation,
    read_exemption_catalog,
)
from pip_audit._deployment.lockfile import (
    Artifact,
    LockedPackage,
    StageLockfile,
    read_stage_lockfile,
)
from pip_audit._deployment.offline import OfflineAdvisoryService
from pip_audit._service.interface import (
    ResolvedDependency,
    VulnerabilityResult,
)


class FindingStatus(enum.Enum):
    """The final disposition of a single advisory finding."""

    Open = "open"
    Exempt = "exempt"
    NotSelected = "not-selected"
    RoleNotRegistered = "role-not-registered"
    Skipped = "skipped"


@dataclass(frozen=True)
class AdvisoryEvidence:
    """pip-audit evidence for one advisory, independent of exemptions."""

    advisory_id: str
    aliases: tuple[str, ...]
    fix_versions: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class PackageReview:
    """The review outcome for one locked package in one stage."""

    name: str
    canonical_name: str
    version: str | None
    role: str
    dependency_groups: tuple[str, ...]
    marker: str | None
    selected: bool
    artifacts: tuple[Artifact, ...]
    status: FindingStatus
    findings: tuple[AdvisoryEvidence, ...] = field(default_factory=tuple)
    applied_exemption: Exemption | None = None
    retained_exemption: Exemption | None = None
    role_mismatch_exemption: Exemption | None = None
    skip_reason: str | None = None

    @property
    def is_runtime_warning(self) -> bool:
        """
        A retained finding on a selected package is a runtime
        warning.

        Both uncovered findings (`Open`) and findings whose
        exemption targets an unregistered role
        (`RoleNotRegistered`) warn: the latter are retained
        rather than applied, so the runtime still acts on them.
        """

        if not self.selected or not self.findings:
            return False
        return self.status in {
            FindingStatus.Open,
            FindingStatus.RoleNotRegistered,
        }


@dataclass(frozen=True)
class StageReview:
    """All package reviews for one deployment stage/role."""

    role: str
    lockfile: Path
    environment: dict[str, str] | None
    reviews: tuple[PackageReview, ...]

    @property
    def runtime_warnings(self) -> tuple[PackageReview, ...]:
        return tuple(review for review in self.reviews if review.is_runtime_warning)

    @property
    def retained_findings(self) -> tuple[PackageReview, ...]:
        """Selected packages whose findings were kept."""

        return tuple(
            review
            for review in self.reviews
            if review.selected
            and review.status
            in {FindingStatus.Open, FindingStatus.RoleNotRegistered}
            and review.findings
        )


def _audit_package(
    package: LockedPackage, service: OfflineAdvisoryService
) -> tuple[VulnerabilityResult, ...]:
    if package.is_skipped:
        return ()
    dep = ResolvedDependency(name=package.name, version=Version(str(package.version)))
    _returned_dep, results = service.query(dep)
    return tuple(results)


def _evidence_from_results(
    results: tuple[VulnerabilityResult, ...],
) -> tuple[AdvisoryEvidence, ...]:
    return tuple(
        AdvisoryEvidence(
            advisory_id=result.id,
            aliases=tuple(sorted(result.aliases)),
            fix_versions=tuple(str(version) for version in result.fix_versions),
            description=result.description,
        )
        for result in results
    )


def review_stage(
    stage: StageLockfile,
    service: OfflineAdvisoryService,
    catalog: ExemptionCatalog,
    environment: dict[str, str] | None = None,
) -> StageReview:
    """
    Re-check every package in one stage lock file.

    `environment` provides the marker evaluation context (e.g.
    ``{"sys_platform": "linux"}``). Packages whose marker does not match
    are recorded as `FindingStatus.NotSelected` and never warn.
    """

    reviews = [
        _review_package(stage.role, package, service, catalog, environment)
        for package in stage.packages
    ]
    return StageReview(
        role=stage.role,
        lockfile=stage.path,
        environment=environment,
        reviews=tuple(reviews),
    )


def _review_package(
    role: str,
    package: LockedPackage,
    service: OfflineAdvisoryService,
    catalog: ExemptionCatalog,
    environment: dict[str, str] | None,
) -> PackageReview:
    selected = package.selected_for(environment)
    common: dict = {
        "name": package.name,
        "canonical_name": package.canonical_name,
        "version": str(package.version) if package.version is not None else None,
        "role": role,
        "dependency_groups": package.dependency_groups,
        "marker": package.marker_raw,
        "selected": selected,
        "artifacts": package.artifacts,
    }

    if package.is_skipped:
        return PackageReview(
            **common,
            status=FindingStatus.Skipped,
            skip_reason=package.skip_reason,
        )

    results = _audit_package(package, service)
    evidence = _evidence_from_results(results)
    if not evidence:
        return PackageReview(**common, status=FindingStatus.Open)

    if not selected:
        return PackageReview(
            **common, status=FindingStatus.NotSelected, findings=evidence
        )

    applied: Exemption | None = None
    retained: Exemption | None = None
    role_mismatch: Exemption | None = None
    for result in results:
        evaluation: ExemptionEvaluation = catalog.evaluate(
            role=role,
            name=package.name,
            version=Version(str(package.version)),
            advisory_id=result.id,
            aliases=set(result.aliases),
        )
        if evaluation.decision is ExemptionDecision.Applied:
            applied = evaluation.exemption
        elif evaluation.decision is ExemptionDecision.RoleNotRegistered:
            retained = evaluation.exemption
        elif evaluation.decision is ExemptionDecision.RoleMismatch:
            role_mismatch = evaluation.exemption

    if retained is not None:
        status = FindingStatus.RoleNotRegistered
    elif applied is not None and role_mismatch is None:
        status = FindingStatus.Exempt
    else:
        status = FindingStatus.Open

    return PackageReview(
        **common,
        status=status,
        findings=evidence,
        applied_exemption=applied,
        retained_exemption=retained,
        role_mismatch_exemption=role_mismatch,
    )


def review_stages(
    stages: list[tuple[str, Path]],
    advisory_snapshot: Path,
    exemption_file: Path,
    environments: dict[str, dict[str, str]] | None = None,
) -> tuple[tuple[StageReview, ...], OfflineAdvisoryService, ExemptionCatalog]:
    """
    Read every stage lock file, the offline advisory snapshot and the
    exemption catalog, then review each stage.

    `stages` is a list of ``(role, lockfile_path)`` pairs. `environments`
    maps a role to its marker environment; roles without an entry get an
    empty environment, which deselects every marker-gated package.
    """

    service = OfflineAdvisoryService(advisory_snapshot)
    catalog = read_exemption_catalog(exemption_file)
    environments = environments or {}

    reviews: list[StageReview] = []
    for role, lockfile_path in stages:
        stage = read_stage_lockfile(role, lockfile_path)
        reviews.append(review_stage(stage, service, catalog, environments.get(role)))
    return tuple(reviews), service, catalog
