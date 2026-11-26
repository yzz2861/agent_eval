"""
Public API for offline candidate-lock review.

See `pip_audit._review` for the implementation and input formats.
"""

from pip_audit._review import (
    REVIEW_SCHEMA,
    Advisory,
    Alternative,
    ArtifactReview,
    AuditedDependency,
    AuditReport,
    AuditVulnerability,
    CandidateArtifact,
    Combination,
    CoverageGap,
    InfeasibleReason,
    LockCandidate,
    LockCombination,
    PackageChange,
    PackageFix,
    ReviewError,
    ReviewOptions,
    ReviewParseError,
    ReviewReport,
    load_audit_report,
    load_audit_reports,
    load_candidates,
    parse_audit_report,
    parse_audit_reports,
    parse_candidates,
    reconcile,
    review,
    version_is_fixed,
)

__all__ = [
    "REVIEW_SCHEMA",
    "Advisory",
    "Alternative",
    "ArtifactReview",
    "AuditedDependency",
    "AuditReport",
    "AuditVulnerability",
    "CandidateArtifact",
    "Combination",
    "CoverageGap",
    "InfeasibleReason",
    "LockCandidate",
    "LockCombination",
    "PackageChange",
    "PackageFix",
    "ReviewError",
    "ReviewOptions",
    "ReviewParseError",
    "ReviewReport",
    "load_audit_report",
    "load_audit_reports",
    "load_candidates",
    "parse_audit_report",
    "parse_audit_reports",
    "parse_candidates",
    "reconcile",
    "review",
    "version_is_fixed",
]


if __name__ == "__main__":  # pragma: no cover
    from pip_audit._review_cli import main as _main

    raise SystemExit(_main())
