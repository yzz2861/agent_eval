"""
JSON reporting for deployment-stage review.

The report keeps each deployment role separate so that an exemption filed
against one role can never be read as cancelling a finding for the same
archive in another role. Every retained runtime warning carries both its
pip-audit advisory evidence and the exemption decision (if any) that
failed to cancel it.
"""

from __future__ import annotations

import json
from typing import Any

from pip_audit._deployment.exemption import Exemption
from pip_audit._deployment.review import PackageReview, StageReview


def _exemption_json(exemption: Exemption | None) -> dict[str, Any] | None:
    if exemption is None:
        return None
    return {
        "package": exemption.canonical_name,
        "version": str(exemption.version),
        "role": exemption.role,
        "advisory": exemption.advisory,
        "reason": exemption.reason,
    }


def _artifact_json(artifact: Any) -> dict[str, Any]:
    return {
        "filename": artifact.filename,
        "url": artifact.url,
        "sha256": artifact.sha256,
        "size": artifact.size,
    }


def _finding_json(review: PackageReview) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for evidence in review.findings:
        findings.append({
            "advisory_id": evidence.advisory_id,
            "aliases": list(evidence.aliases),
            "fix_versions": list(evidence.fix_versions),
            "description": evidence.description,
        })
    return findings


def _package_json(review: PackageReview) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": review.canonical_name,
        "display_name": review.name,
        "version": review.version,
        "role": review.role,
        "dependency_groups": list(review.dependency_groups),
        "marker": review.marker,
        "selected": review.selected,
        "status": review.status.value,
        "runtime_warning": review.is_runtime_warning,
        "artifacts": [_artifact_json(artifact) for artifact in review.artifacts],
        "findings": _finding_json(review),
        "applied_exemption": _exemption_json(review.applied_exemption),
        "retained_exemption": _exemption_json(review.retained_exemption),
        "role_mismatch_exemption": _exemption_json(review.role_mismatch_exemption),
    }
    if review.skip_reason is not None:
        payload["skip_reason"] = review.skip_reason
    return payload


def _stage_json(stage: StageReview) -> dict[str, Any]:
    return {
        "role": stage.role,
        "lockfile": str(stage.lockfile),
        "environment": stage.environment,
        "runtime_warning_count": len(stage.runtime_warnings),
        "retained_finding_count": len(stage.retained_findings),
        "packages": [_package_json(review) for review in stage.reviews],
        "runtime_warnings": [
            _package_json(review) for review in stage.runtime_warnings
        ],
    }


def build_report(stage_reviews: tuple[StageReview, ...]) -> dict[str, Any]:
    """Build the full JSON-serialisable review report."""

    all_warnings = [
        warning
        for stage in stage_reviews
        for warning in stage.runtime_warnings
    ]
    return {
        "schema": "deployment-stage-review/v1",
        "stage_count": len(stage_reviews),
        "runtime_warning_count": len(all_warnings),
        "stages": [_stage_json(stage) for stage in stage_reviews],
    }


def render_json(stage_reviews: tuple[StageReview, ...]) -> str:
    """Render the review report as a JSON string."""

    return json.dumps(build_report(stage_reviews), indent=2, sort_keys=False)
