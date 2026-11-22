"""
Deployment-stage review support.

This subpackage re-checks PEP 751 lock files per deployment stage (for
example a build host versus a runtime image) against an offline advisory
snapshot, while applying caller-supplied exemptions that are scoped to an
explicit deployment role.
"""

from pip_audit._deployment.exemption import (
    Exemption,
    ExemptionCatalog,
    ExemptionCatalogError,
    ExemptionDecision,
    read_exemption_catalog,
)
from pip_audit._deployment.lockfile import (
    Artifact,
    LockedPackage,
    StageLockfile,
    StageLockfileError,
    read_stage_lockfile,
)
from pip_audit._deployment.offline import (
    OfflineAdvisory,
    OfflineAdvisoryService,
    OfflineAdvisoryServiceError,
)
from pip_audit._deployment.report import build_report, render_json
from pip_audit._deployment.review import (
    AdvisoryEvidence,
    FindingStatus,
    PackageReview,
    StageReview,
    review_stage,
    review_stages,
)

__all__ = [
    "AdvisoryEvidence",
    "Artifact",
    "Exemption",
    "ExemptionCatalog",
    "ExemptionCatalogError",
    "ExemptionDecision",
    "FindingStatus",
    "LockedPackage",
    "OfflineAdvisory",
    "OfflineAdvisoryService",
    "OfflineAdvisoryServiceError",
    "PackageReview",
    "StageLockfile",
    "StageLockfileError",
    "StageReview",
    "build_report",
    "read_exemption_catalog",
    "read_stage_lockfile",
    "render_json",
    "review_stage",
    "review_stages",
]
