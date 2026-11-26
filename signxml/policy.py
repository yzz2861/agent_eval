"""
Offline policy determination for staged approval workflows.

This module builds on top of :class:`signxml.VerifyResult` to support compliance workflows in which a signed
document passes through three lifecycle stages: signing, archiving, and republishing. Historical approval files
may be verified under the policy that was in effect on their signing date, while archive uploads and re-reviews
carry their own recorded approval versions. Given a verification result, per-stage evidence records, and a
registry of versioned policies, :func:`evaluate_stages` produces a deterministic, fully offline determination
for each stage. Stages whose evidence is incomplete, whose timeline conflicts with earlier stages, or whose
applicable policy version is unknown are reported as suspended rather than conclusive.

All evaluation is a pure function of its inputs: no wall-clock time, network access, or mutable state is
involved, so evaluating the same inputs always reproduces the same determination.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .exceptions import InvalidInput
from .verifier import VerifyResult


class ApprovalStage(Enum):
    """
    Lifecycle stages of an approval workflow, in canonical order. Each stage is assessed independently,
    and every determination reports one decision per stage in this order.
    """

    SIGNING = "signing"
    "The document was signed. Independent evidence for this stage is the verified XML signature itself."

    ARCHIVING = "archiving"
    "The signed document was uploaded to an archive. Independent evidence requires a recorded archive time and approval version."

    REPUBLISHING = "republishing"
    "The archived document was re-reviewed and republished. Independent evidence requires a recorded time and approval version."


class PolicyStatus(Enum):
    """
    Outcome of the offline policy determination for a single stage.
    """

    CONCLUSIVE = "conclusive"
    "The stage has independent evidence and an applicable known policy version, so a conclusion can be drawn."

    SUSPENDED = "suspended"
    "The conclusion for the stage must be suspended, for example because of a time conflict or an unknown version."


class SuspensionReason(str, Enum):
    """
    Machine-readable reasons why a stage conclusion is suspended. A suspended decision may carry several reasons.
    """

    SIGNATURE_VERIFICATION_FAILED = "signature-verification-failed"
    "The XML signature did not verify, so no stage can be considered conclusive."

    MISSING_STAGE_TIME = "missing-stage-time"
    "No time was recorded for the stage, so the applicable policy version cannot be determined."

    MISSING_STAGE_APPROVAL_VERSION = "missing-stage-approval-version"
    "The stage has no recorded approval version, so it has no independent evidence of its own."

    TIME_CONFLICT = "time-conflict"
    "The recorded stage time is earlier than the time of a preceding stage."

    UNKNOWN_POLICY_VERSION = "unknown-policy-version"
    "No policy version in the registry was in effect at the recorded stage time."

    UNKNOWN_APPROVAL_VERSION = "unknown-approval-version"
    "The approval version recorded for the stage is not present in the policy registry."

    APPROVAL_VERSION_MISMATCH = "approval-version-mismatch"
    "The recorded approval version does not match the policy version in effect at the recorded stage time."


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


@dataclass(frozen=True)
class PolicyVersion:
    """
    One version of an approval policy, together with the period during which it was in effect. Superseded
    versions remain in the registry so that historical files can be evaluated under the policy in effect on
    their signing date, and so that the explanation of a restored old policy can be recovered.
    """

    version: str
    "The unique identifier of this policy version."

    effective_from: datetime
    "The time from which this version is in effect (inclusive). Naive datetimes are treated as UTC."

    effective_to: datetime | None = None
    "The time from which this version is no longer in effect (exclusive), or None if it is still in effect."

    explanation: str = ""
    "A human-readable description of this policy version, reproduced in decisions made under it."

    def __post_init__(self) -> None:
        object.__setattr__(self, "effective_from", _as_utc(self.effective_from))
        if self.effective_to is not None:
            object.__setattr__(self, "effective_to", _as_utc(self.effective_to))
            if self.effective_to <= self.effective_from:
                raise InvalidInput("PolicyVersion effective_to must be later than effective_from")

    def in_effect_at(self, when: datetime) -> bool:
        "Return True if this version was in effect at the given time."
        when = _as_utc(when)
        return self.effective_from <= when and (self.effective_to is None or when < self.effective_to)


class PolicyRegistry:
    """
    An offline registry of known policy versions. Versions may not overlap. The registry is the single source
    of truth for resolving which policy version applies at a given stage time and for recovering the
    explanation of a historical (restored) policy version.
    """

    def __init__(self, versions: Iterable[PolicyVersion]):
        ordered = tuple(sorted(versions, key=lambda v: v.effective_from))
        seen = set()
        for version in ordered:
            if version.version in seen:
                raise InvalidInput(f"Duplicate policy version: {version.version}")
            seen.add(version.version)
        for earlier, later in zip(ordered, ordered[1:]):
            if earlier.effective_to is None or later.effective_from < earlier.effective_to:
                raise InvalidInput(f"Overlapping policy versions: {earlier.version} and {later.version}")
        self._versions = ordered

    @property
    def versions(self) -> tuple[PolicyVersion, ...]:
        "All known policy versions, ordered by effective_from."
        return self._versions

    def policy_at(self, when: datetime) -> PolicyVersion | None:
        "Return the policy version in effect at the given time, or None if no known version covers it."
        for version in self._versions:
            if version.in_effect_at(when):
                return version
        return None

    def get(self, version: str) -> PolicyVersion | None:
        "Return the policy version with the given identifier, or None if it is unknown to this registry."
        for known in self._versions:
            if known.version == version:
                return known
        return None

    def explain(self, version: str) -> str | None:
        """
        Recover the explanation of a policy version, including a superseded one. This supports restoring an
        old policy: its identifier remains in the registry and its explanation can be reproduced verbatim.
        """
        known = self.get(version)
        return known.explanation if known is not None else None


@dataclass(frozen=True)
class StageEvidence:
    """
    The offline evidence record presented for one stage of the approval workflow. For the signing stage, the
    verified signature itself constitutes the independent evidence and only the signing time is needed. For
    the archiving and republishing stages, independent evidence requires both a recorded stage time and the
    approval version recorded for that stage.
    """

    stage: ApprovalStage
    "The lifecycle stage this evidence describes."

    stage_time: datetime | None = None
    "The recorded time of the stage action. Naive datetimes are treated as UTC. None means the time is unknown."

    approval_version: str | None = None
    "The approval version recorded for this stage, or None if none was recorded."

    def __post_init__(self) -> None:
        if self.stage_time is not None:
            object.__setattr__(self, "stage_time", _as_utc(self.stage_time))


@dataclass(frozen=True)
class StageDecision:
    """
    The offline policy determination for a single stage.
    """

    stage: ApprovalStage
    "The lifecycle stage this decision belongs to."

    status: PolicyStatus
    "Whether the stage conclusion is conclusive or must be suspended."

    independent_evidence: bool
    "Whether the stage has independent evidence of its own (see :class:`ApprovalStage` and :class:`StageEvidence`)."

    policy_version: str | None
    "The policy version in effect at the recorded stage time, or None if it could not be determined."

    explanation: str | None
    "The explanation of the resolved policy version, reproduced verbatim so old policies can be restored."

    reasons: tuple[SuspensionReason, ...]
    "The reasons the conclusion is suspended, in canonical order. Empty when the decision is conclusive."


@dataclass(frozen=True)
class PolicyDetermination:
    """
    The complete offline policy determination for one verified document, containing exactly one decision per
    stage in canonical stage order. Determinations are comparable: evaluating the same inputs twice yields
    equal determinations.
    """

    signature_valid: bool
    "Whether the underlying XML signature verification succeeded."

    decisions: tuple[StageDecision, ...]
    "One decision per stage, in canonical :class:`ApprovalStage` order."

    def decision_for(self, stage: ApprovalStage) -> StageDecision:
        "Return the decision for the given stage."
        for decision in self.decisions:
            if decision.stage is stage:
                return decision
        raise InvalidInput(f"Unknown stage: {stage}")


def _evaluate_stage(
    evidence: StageEvidence,
    *,
    verify_result: VerifyResult | None,
    registry: PolicyRegistry,
    previous_stage_time: datetime | None,
) -> StageDecision:
    reasons = []
    if verify_result is None:
        reasons.append(SuspensionReason.SIGNATURE_VERIFICATION_FAILED)

    if evidence.stage is ApprovalStage.SIGNING:
        independent_evidence = verify_result is not None
    else:
        independent_evidence = evidence.stage_time is not None and evidence.approval_version is not None
        if evidence.approval_version is None:
            reasons.append(SuspensionReason.MISSING_STAGE_APPROVAL_VERSION)

    policy = None
    if evidence.stage_time is None:
        reasons.append(SuspensionReason.MISSING_STAGE_TIME)
    else:
        if previous_stage_time is not None and evidence.stage_time < previous_stage_time:
            reasons.append(SuspensionReason.TIME_CONFLICT)
        policy = registry.policy_at(evidence.stage_time)
        if policy is None:
            reasons.append(SuspensionReason.UNKNOWN_POLICY_VERSION)

    if evidence.approval_version is not None:
        recorded = registry.get(evidence.approval_version)
        if recorded is None:
            reasons.append(SuspensionReason.UNKNOWN_APPROVAL_VERSION)
        elif policy is not None and recorded.version != policy.version:
            reasons.append(SuspensionReason.APPROVAL_VERSION_MISMATCH)

    return StageDecision(
        stage=evidence.stage,
        status=PolicyStatus.SUSPENDED if reasons else PolicyStatus.CONCLUSIVE,
        independent_evidence=independent_evidence,
        policy_version=policy.version if policy is not None else None,
        explanation=policy.explanation if policy is not None else None,
        reasons=tuple(reasons),
    )


def evaluate_stages(
    verify_result: VerifyResult | None,
    *,
    evidence: Iterable[StageEvidence],
    registry: PolicyRegistry,
) -> PolicyDetermination:
    """
    Evaluate the three approval stages of one document against a registry of versioned policies, entirely
    offline. ``verify_result`` is the result of a successful :func:`signxml.XMLVerifier.verify` call, or None
    if signature verification failed, in which case every stage is suspended. Each stage is assessed
    independently; a stage whose recorded time conflicts with an earlier stage, or whose applicable policy or
    approval version is unknown, is suspended with the corresponding reasons. The result is a pure function of
    the inputs, so the same document and evidence always reproduce the same determination.
    """
    evidence_by_stage: dict[ApprovalStage, StageEvidence] = {}
    for record in evidence:
        if record.stage in evidence_by_stage:
            raise InvalidInput(f"Duplicate evidence for stage: {record.stage.value}")
        evidence_by_stage[record.stage] = record

    decisions = []
    previous_stage_time = None
    for stage in ApprovalStage:
        record = evidence_by_stage.get(stage, StageEvidence(stage=stage))
        decisions.append(
            _evaluate_stage(record, verify_result=verify_result, registry=registry, previous_stage_time=previous_stage_time)
        )
        if record.stage_time is not None:
            previous_stage_time = record.stage_time

    return PolicyDetermination(signature_valid=verify_result is not None, decisions=tuple(decisions))

