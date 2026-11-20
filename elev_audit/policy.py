"""Approved-exception matching and audit orchestration.

An exception only covers the architectures and artifacts it explicitly names.
Coverage is never inferred from the scanning workstation; every decision is
traced to a piece of evidence or an explicit field of the approval record.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .evidence import (
    FINDING_EVIDENCE_MISSING,
    FINDING_LANGUAGE_BRANCH,
    FINDING_NO_DECLARATION,
    FINDING_PARSE_ERROR,
    ArtifactEvidence,
    DeploymentConditions,
    ManifestEvidence,
)

VERDICT_APPROVED = "approved"
VERDICT_REJECTED = "rejected"
VERDICT_INCONCLUSIVE = "inconclusive"

# Reasons recorded when an approval cannot cover an audit target.
REASON_ARTIFACT_MISMATCH = "artifact_not_listed"
REASON_ARCHITECTURE_MISMATCH = "architecture_not_approved"
REASON_PE_HASH_MISMATCH = "pe_hash_not_approved"
REASON_MANIFEST_HASH_MISMATCH = "manifest_hash_not_approved"
REASON_LANGUAGE_NOT_APPROVED = "language_branch_not_approved"
REASON_CONDITION_UNMET = "deployment_condition_unmet"
REASON_NO_APPLICABLE_EXCEPTION = "no_applicable_exception"
REASON_EVIDENCE_MISSING = "evidence_missing"
REASON_NO_DECLARATION = "no_declaration"
REASON_PARSE_ERROR = "manifest_parse_error"


@dataclass
class ApprovedException:
    """One approved exception record.

    Scope fields are explicit: artifact_ids and architectures name exactly
    what the approval covers. Optional content hashes pin the approval to a
    specific build; approved_languages limits which RT_MANIFEST language
    branches are covered (all languages when empty/None).
    """

    exception_id: str
    artifact_ids: List[str]
    architectures: List[str]
    approved_levels: List[str]
    allow_auto_elevate: bool = False
    approved_manifest_sha256: Optional[List[str]] = None
    approved_pe_sha256: Optional[List[str]] = None
    approved_languages: Optional[List[int]] = None
    required_conditions: Dict[str, object] = field(default_factory=dict)
    justification: str = ""

    def covers_artifact(self, artifact_id: str) -> bool:
        return artifact_id in self.artifact_ids

    def covers_architecture(self, machine: Optional[str]) -> bool:
        if machine is None:
            return False
        return machine in self.architectures

    def covers_language(self, language_id: Optional[int]) -> bool:
        if not self.approved_languages:
            return True
        return language_id in self.approved_languages

    def covers_pe_hash(self, pe_sha256: Optional[str]) -> bool:
        if not self.approved_pe_sha256:
            return True
        return pe_sha256 in self.approved_pe_sha256

    def covers_manifest_hash(self, manifest_sha256: str) -> bool:
        if not self.approved_manifest_sha256:
            return True
        return manifest_sha256 in self.approved_manifest_sha256


def _conditions_met(required: Dict[str, object], conditions: DeploymentConditions) -> List[str]:
    """Return the list of required condition keys that are not satisfied."""
    unmet = []
    for key, expected in required.items():
        actual = conditions.get(key)
        if actual != expected:
            unmet.append(key)
    return unmet


def _manifest_reasons(exception: ApprovedException, manifest: ManifestEvidence) -> List[str]:
    reasons: List[str] = []
    if not exception.covers_language(manifest.language_id):
        reasons.append(REASON_LANGUAGE_NOT_APPROVED)
    if not exception.covers_manifest_hash(manifest.sha256):
        reasons.append(REASON_MANIFEST_HASH_MISMATCH)
    if manifest.parse_error is not None:
        reasons.append(REASON_PARSE_ERROR)
    elif not manifest.has_execution_level_declaration:
        reasons.append(REASON_NO_DECLARATION)
    else:
        level = manifest.requested_level.level
        if level not in exception.approved_levels:
            reasons.append("execution_level_not_approved")
        if manifest.auto_elevate is True and not exception.allow_auto_elevate:
            reasons.append("auto_elevate_not_approved")
    return reasons


def evaluate_exception(
    exception: ApprovedException,
    evidence: ArtifactEvidence,
    conditions: Optional[DeploymentConditions] = None,
) -> Dict[str, object]:
    """Explain why one exception does or does not cover one artifact."""
    conditions = conditions or DeploymentConditions()
    reasons: List[str] = []
    if not exception.covers_artifact(evidence.artifact_id):
        reasons.append(REASON_ARTIFACT_MISMATCH)
    if not exception.covers_architecture(evidence.machine):
        reasons.append(REASON_ARCHITECTURE_MISMATCH)
    if not exception.covers_pe_hash(evidence.pe_sha256):
        reasons.append(REASON_PE_HASH_MISMATCH)
    unmet = _conditions_met(exception.required_conditions, conditions)
    for key in unmet:
        reasons.append(f"{REASON_CONDITION_UNMET}:{key}")
    if not evidence.manifests:
        reasons.append(REASON_EVIDENCE_MISSING)
    per_manifest = {}
    for manifest in evidence.manifests:
        key = manifest.source
        per_manifest[key] = _manifest_reasons(exception, manifest)
        reasons.extend(per_manifest[key])
    covered = not reasons
    return {
        "exception_id": exception.exception_id,
        "covered": covered,
        "reasons": sorted(set(reasons)),
        "unmet_conditions": unmet,
        "per_manifest": per_manifest,
    }


def audit_artifact(
    evidence: ArtifactEvidence,
    exceptions: Sequence[ApprovedException],
    conditions: Optional[DeploymentConditions] = None,
) -> Dict[str, object]:
    """Audit one artifact against a set of approved exception records.

    The verdict is approved only when at least one exception explicitly
    covers the artifact id, architecture, build hashes, every language
    branch manifest, and the caller-supplied deployment conditions.
    Missing evidence or declarations force an inconclusive verdict rather
    than silently granting coverage.
    """
    conditions = conditions or DeploymentConditions()
    evaluations = [
        evaluate_exception(record, evidence, conditions) for record in exceptions
    ]
    covering = [evaluation for evaluation in evaluations if evaluation["covered"]]
    blocking_findings = set(evidence.findings)
    for manifest in evidence.manifests:
        blocking_findings.update(manifest.findings)
    hard_blockers = {
        FINDING_EVIDENCE_MISSING,
        FINDING_NO_DECLARATION,
        FINDING_PARSE_ERROR,
    } & blocking_findings
    if covering:
        verdict = VERDICT_APPROVED
        matched = [evaluation["exception_id"] for evaluation in covering]
    elif hard_blockers:
        verdict = VERDICT_INCONCLUSIVE
        matched = []
    else:
        verdict = VERDICT_REJECTED
        matched = []
    return {
        "verdict": verdict,
        "artifact_id": evidence.artifact_id,
        "machine": evidence.machine,
        "pe_sha256": evidence.pe_sha256,
        "matched_exception_ids": matched,
        "evaluations": evaluations,
        "findings": sorted(blocking_findings),
        "language_branch_conflict": FINDING_LANGUAGE_BRANCH in blocking_findings,
        "conditions_source": conditions.source,
        "conditions": dict(conditions.conditions),
    }


def why_not_applicable(
    exception: ApprovedException,
    evidence: ArtifactEvidence,
    conditions: Optional[DeploymentConditions] = None,
) -> List[str]:
    """Convenience accessor returning the human-readable blocker reason codes."""
    return evaluate_exception(exception, evidence, conditions)["reasons"]
