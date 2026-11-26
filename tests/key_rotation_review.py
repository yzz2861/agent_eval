"""Time-aware signature review for key rotation and launch approval.

This is test support for the review test.  It deliberately keeps four checks
separate:

* signing: the artifact key must cover the trusted signing time;
* approval: the approver must have approved the exact artifact while the
  launch approval window was open;
* ingestion: the artifact must enter the repository after approval and while
  the launch approval window is still open;
* re-verification: the reviewer must be able to establish the original
  signing time and must re-verify while the launch approval is still active.

Cryptographic verification only proves that a private key was used.  A public
key that remains readable after retirement therefore does *not* prove that the
key was authorised when the artifact was signed.  When no trusted signing-time
evidence exists, the result is explicitly ``INDETERMINATE`` and no party is
held liable.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time
from enum import Enum

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.hash import digest
from securesystemslib.signer import Key, Signature, Signer

Clock = Callable[[], datetime]


class Verdict(Enum):
    """Result of an individual lifecycle check."""

    VALID = "valid"
    INVALID = "invalid"
    INDETERMINATE = "indeterminate"


class Responsibility(Enum):
    """The party liable for a failed or unresolvable check."""

    NONE = "none"
    SIGNER = "signer"
    APPROVER = "approver"
    INGEST_OWNER = "ingest_owner"
    ON_CALL_VERIFIER = "on_call_verifier"
    UNDETERMINED = "undetermined"


class Stage(Enum):
    SIGNING = "signing"
    APPROVAL = "approval"
    INGESTION = "ingestion"
    REVERIFICATION = "reverification"


class ReasonCode(Enum):
    OK = "ok"
    KEY_UNKNOWN = "key_unknown"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNING_TIME_UNKNOWN = "signing_time_unknown"
    SIGNING_TIME_UNTRUSTED = "signing_time_untrusted"
    KEY_NOT_AUTHORIZED_AT_SIGNING = "key_not_authorized_at_signing"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_DIGEST_MISMATCH = "approval_digest_mismatch"
    APPROVAL_UNTRUSTED = "approval_untrusted"
    APPROVAL_OUTSIDE_WINDOW = "approval_outside_window"
    APPROVAL_PRECEDES_SIGNING = "approval_precedes_signing"
    INGESTION_MISSING = "ingestion_missing"
    INGESTION_WITHOUT_SIGNING_TIME = "ingestion_without_signing_time"
    INGESTION_REQUIRES_VALID_SIGNING = "ingestion_requires_valid_signing"
    INGESTION_REQUIRES_VALID_APPROVAL = "ingestion_requires_valid_approval"
    INGESTION_OUTSIDE_APPROVAL_WINDOW = "ingestion_outside_approval_window"
    INGESTION_BEFORE_APPROVAL = "ingestion_before_approval"
    INGESTION_BEFORE_SIGNING = "ingestion_before_signing"
    REVERIFICATION_WITHOUT_SIGNING_TIME = "reverification_without_signing_time"
    REVERIFICATION_REQUIRES_VALID_SIGNING = "reverification_requires_valid_signing"
    REVERIFICATION_REQUIRES_VALID_APPROVAL = "reverification_requires_valid_approval"
    REVERIFICATION_REQUIRES_VALID_INGESTION = "reverification_requires_valid_ingestion"
    REVERIFICATION_OUTSIDE_APPROVAL_WINDOW = "reverification_outside_approval_window"


def utc(moment: datetime) -> datetime:
    """Return an aware UTC datetime, rejecting naive input."""

    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(UTC)


def date_window(start: date, end: date) -> Window:
    """Create a half-open ``[start, end)`` UTC window from two dates."""

    return Window(
        datetime.combine(start, time.min, tzinfo=UTC),
        datetime.combine(end, time.min, tzinfo=UTC),
    )


@dataclass(frozen=True)
class Window:
    """A half-open UTC interval: ``start <= moment < end``."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        start = utc(self.start)
        end = utc(self.end)
        if start >= end:
            raise ValueError("window start must precede window end")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    def covers(self, moment: datetime) -> bool:
        moment = utc(moment)
        return self.start <= moment < self.end


@dataclass(frozen=True)
class FixedClock:
    """An injectable clock whose instant can be moved by the test."""

    _instant: datetime

    def __init__(self, instant: datetime):
        object.__setattr__(self, "_instant", utc(instant))

    def __call__(self) -> datetime:
        return self._instant

    def move_to(self, instant: datetime) -> None:
        object.__setattr__(self, "_instant", utc(instant))

    @property
    def instant(self) -> datetime:
        return self._instant


def artifact_digest(payload: bytes) -> str:
    """Return a SHA-256 digest over the exact signed payload."""

    digest_object = digest("sha256")
    digest_object.update(payload)
    return digest_object.hexdigest()


def _canonical_json(value: Mapping[str, str]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def canonical_timestamp_message(
    artifact_sha256: str, artifact_keyid: str, signed_at: datetime
) -> bytes:
    """Build the byte string signed by the timestamp authority."""

    return _canonical_json(
        {
            "artifact_digest": artifact_sha256,
            "artifact_keyid": artifact_keyid,
            "signed_at": utc(signed_at).isoformat().replace("+00:00", "Z"),
            "type": "signing-time-attestation/v1",
        }
    )


def canonical_approval_message(
    approval_id: str, artifact_sha256: str, approved_at: datetime
) -> bytes:
    """Build the byte string signed by the approver."""

    return _canonical_json(
        {
            "approval_id": approval_id,
            "approved_at": utc(approved_at).isoformat().replace("+00:00", "Z"),
            "artifact_digest": artifact_sha256,
            "type": "launch-approval/v1",
        }
    )


@dataclass(frozen=True)
class TimestampAttestation:
    """A trusted signing-time claim countersigned by a timestamp authority."""

    signed_at: datetime
    signature: Signature

    def __post_init__(self) -> None:
        object.__setattr__(self, "signed_at", utc(self.signed_at))


@dataclass(frozen=True)
class ApprovalRecord:
    """An approval for one exact artifact, signed by the approver."""

    approval_id: str
    artifact_sha256: str
    approved_at: datetime
    signature: Signature

    def __post_init__(self) -> None:
        object.__setattr__(self, "approved_at", utc(self.approved_at))


def make_timestamp_attestation(
    signer: Signer,
    artifact_sha256: str,
    artifact_keyid: str,
    signed_at: datetime,
) -> TimestampAttestation:
    """Create a timestamp countersignature for the exact artifact digest."""

    message = canonical_timestamp_message(artifact_sha256, artifact_keyid, signed_at)
    return TimestampAttestation(signed_at, signer.sign(message))


def make_approval_record(
    signer: Signer,
    approval_id: str,
    artifact_sha256: str,
    approved_at: datetime,
) -> ApprovalRecord:
    """Create an approval countersignature for the exact artifact digest."""

    message = canonical_approval_message(approval_id, artifact_sha256, approved_at)
    return ApprovalRecord(
        approval_id, artifact_sha256, approved_at, signer.sign(message)
    )


@dataclass(frozen=True)
class Evidence:
    """Everything a reviewer has about one signed artifact."""

    artifact_id: str
    payload: bytes
    signature: Signature
    timestamp: TimestampAttestation | None = None
    approval: ApprovalRecord | None = None
    ingested_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.ingested_at is not None:
            object.__setattr__(self, "ingested_at", utc(self.ingested_at))

    @property
    def sha256(self) -> str:
        return artifact_digest(self.payload)


@dataclass(frozen=True)
class KeyAuthorization:
    """A readable public key and the period in which it may sign."""

    key: Key
    window: Window


@dataclass(frozen=True)
class ReviewPolicy:
    """Independent key-rotation, approval, and re-verification boundaries."""

    keys: Mapping[str, KeyAuthorization]
    approval_window: Window
    reverification_window: Window
    timestamp_key: Key
    approval_key: Key


@dataclass(frozen=True)
class StageResult:
    """One explicit lifecycle judgement."""

    stage: Stage
    verdict: Verdict
    responsibility: Responsibility
    reason: ReasonCode
    event_at: datetime | None = None


@dataclass(frozen=True)
class ReviewReport:
    """The four independent checks and their aggregate judgement."""

    evaluated_at: datetime
    stages: tuple[StageResult, ...]

    def for_stage(self, stage: Stage) -> StageResult:
        for result in self.stages:
            if result.stage is stage:
                return result
        raise KeyError(stage)

    @property
    def verdict(self) -> Verdict:
        if any(stage.verdict is Verdict.INVALID for stage in self.stages):
            return Verdict.INVALID
        if any(stage.verdict is Verdict.INDETERMINATE for stage in self.stages):
            return Verdict.INDETERMINATE
        return Verdict.VALID

    @property
    def responsibility(self) -> Responsibility:
        for stage in self.stages:
            if stage.verdict is Verdict.INVALID:
                return stage.responsibility
        if any(stage.verdict is Verdict.INDETERMINATE for stage in self.stages):
            return Responsibility.UNDETERMINED
        return Responsibility.NONE

    @property
    def reason(self) -> ReasonCode:
        for stage in self.stages:
            if stage.verdict is not Verdict.VALID:
                return stage.reason
        return ReasonCode.OK


class Reviewer:
    """Review evidence using a clock supplied by the caller."""

    def __init__(self, policy: ReviewPolicy, clock: Clock):
        self.policy = policy
        self.clock = clock

    def review(self, evidence: Evidence) -> ReviewReport:
        now = utc(self.clock())
        signing = self.check_signing(evidence)
        approval = self.check_approval(evidence, signing)
        ingestion = self.check_ingestion(evidence, signing, approval)
        reverification = self.check_reverification(
            evidence, signing, approval, ingestion, now
        )
        return ReviewReport(
            now,
            (signing, approval, ingestion, reverification),
        )

    def check_signing(self, evidence: Evidence) -> StageResult:
        """Check the key authority at the trusted signing time."""

        authorization = self.policy.keys.get(evidence.signature.keyid)
        if authorization is None:
            return self._result(
                Stage.SIGNING,
                Verdict.INVALID,
                Responsibility.SIGNER,
                ReasonCode.KEY_UNKNOWN,
            )

        try:
            authorization.key.verify_signature(evidence.signature, evidence.payload)
        except UnverifiedSignatureError:
            return self._result(
                Stage.SIGNING,
                Verdict.INVALID,
                Responsibility.SIGNER,
                ReasonCode.SIGNATURE_INVALID,
            )

        attestation = evidence.timestamp
        if attestation is None:
            return self._result(
                Stage.SIGNING,
                Verdict.INDETERMINATE,
                Responsibility.UNDETERMINED,
                ReasonCode.SIGNING_TIME_UNKNOWN,
            )

        message = canonical_timestamp_message(
            evidence.sha256,
            evidence.signature.keyid,
            attestation.signed_at,
        )
        try:
            self.policy.timestamp_key.verify_signature(attestation.signature, message)
        except UnverifiedSignatureError:
            return self._result(
                Stage.SIGNING,
                Verdict.INDETERMINATE,
                Responsibility.UNDETERMINED,
                ReasonCode.SIGNING_TIME_UNTRUSTED,
                attestation.signed_at,
            )

        if not authorization.window.covers(attestation.signed_at):
            return self._result(
                Stage.SIGNING,
                Verdict.INVALID,
                Responsibility.SIGNER,
                ReasonCode.KEY_NOT_AUTHORIZED_AT_SIGNING,
                attestation.signed_at,
            )

        return self._result(
            Stage.SIGNING,
            Verdict.VALID,
            Responsibility.NONE,
            ReasonCode.OK,
            attestation.signed_at,
        )

    def check_approval(
        self, evidence: Evidence, signing: StageResult | None = None
    ) -> StageResult:
        """Check approval authenticity, binding, order, and approval window."""

        if signing is None:
            signing = self.check_signing(evidence)

        approval = evidence.approval
        if approval is None:
            return self._result(
                Stage.APPROVAL,
                Verdict.INVALID,
                Responsibility.APPROVER,
                ReasonCode.APPROVAL_MISSING,
            )

        if approval.artifact_sha256 != evidence.sha256:
            return self._result(
                Stage.APPROVAL,
                Verdict.INVALID,
                Responsibility.APPROVER,
                ReasonCode.APPROVAL_DIGEST_MISMATCH,
            )

        message = canonical_approval_message(
            approval.approval_id,
            approval.artifact_sha256,
            approval.approved_at,
        )
        try:
            self.policy.approval_key.verify_signature(approval.signature, message)
        except UnverifiedSignatureError:
            return self._result(
                Stage.APPROVAL,
                Verdict.INVALID,
                Responsibility.APPROVER,
                ReasonCode.APPROVAL_UNTRUSTED,
                approval.approved_at,
            )

        if not self.policy.approval_window.covers(approval.approved_at):
            return self._result(
                Stage.APPROVAL,
                Verdict.INVALID,
                Responsibility.APPROVER,
                ReasonCode.APPROVAL_OUTSIDE_WINDOW,
                approval.approved_at,
            )

        if (
            signing.verdict is Verdict.VALID
            and signing.event_at is not None
            and approval.approved_at < signing.event_at
        ):
            return self._result(
                Stage.APPROVAL,
                Verdict.INVALID,
                Responsibility.APPROVER,
                ReasonCode.APPROVAL_PRECEDES_SIGNING,
                approval.approved_at,
            )

        return self._result(
            Stage.APPROVAL,
            Verdict.VALID,
            Responsibility.NONE,
            ReasonCode.OK,
            approval.approved_at,
        )

    def check_ingestion(  # noqa: PLR0911
        self,
        evidence: Evidence,
        signing: StageResult | None = None,
        approval: StageResult | None = None,
    ) -> StageResult:
        """Check that ingestion happened after approval and inside its window."""

        if signing is None:
            signing = self.check_signing(evidence)
        if approval is None:
            approval = self.check_approval(evidence, signing)

        ingested_at = evidence.ingested_at
        if ingested_at is None:
            return self._result(
                Stage.INGESTION,
                Verdict.INVALID,
                Responsibility.INGEST_OWNER,
                ReasonCode.INGESTION_MISSING,
            )

        if signing.verdict is Verdict.INDETERMINATE:
            return self._result(
                Stage.INGESTION,
                Verdict.INDETERMINATE,
                Responsibility.UNDETERMINED,
                ReasonCode.INGESTION_WITHOUT_SIGNING_TIME,
                ingested_at,
            )
        if signing.verdict is Verdict.INVALID:
            return self._result(
                Stage.INGESTION,
                Verdict.INVALID,
                Responsibility.INGEST_OWNER,
                ReasonCode.INGESTION_REQUIRES_VALID_SIGNING,
                ingested_at,
            )
        if approval.verdict is not Verdict.VALID:
            return self._result(
                Stage.INGESTION,
                Verdict.INVALID,
                Responsibility.INGEST_OWNER,
                ReasonCode.INGESTION_REQUIRES_VALID_APPROVAL,
                ingested_at,
            )
        if not self.policy.approval_window.covers(ingested_at):
            return self._result(
                Stage.INGESTION,
                Verdict.INVALID,
                Responsibility.INGEST_OWNER,
                ReasonCode.INGESTION_OUTSIDE_APPROVAL_WINDOW,
                ingested_at,
            )

        approval_record = evidence.approval
        if approval_record is None or ingested_at < approval_record.approved_at:
            return self._result(
                Stage.INGESTION,
                Verdict.INVALID,
                Responsibility.INGEST_OWNER,
                ReasonCode.INGESTION_BEFORE_APPROVAL,
                ingested_at,
            )
        if signing.event_at is not None and ingested_at < signing.event_at:
            return self._result(
                Stage.INGESTION,
                Verdict.INVALID,
                Responsibility.INGEST_OWNER,
                ReasonCode.INGESTION_BEFORE_SIGNING,
                ingested_at,
            )

        return self._result(
            Stage.INGESTION,
            Verdict.VALID,
            Responsibility.NONE,
            ReasonCode.OK,
            ingested_at,
        )

    def check_reverification(  # noqa: PLR0911
        self,
        evidence: Evidence,
        signing: StageResult | None = None,
        approval: StageResult | None = None,
        ingestion: StageResult | None = None,
        now: datetime | None = None,
    ) -> StageResult:
        """Re-verify using the original signing time, never the key's current state.

        The artifact key is looked up as long as its public material is readable.
        Its presence in the registry is necessary for cryptography but is not
        evidence of authority at signing time.  ``now`` is used only to decide
        whether this re-verification is covered by an active launch approval.
        Whether the old key's validity window contains ``now`` is intentionally
        irrelevant.
        """

        if signing is None:
            signing = self.check_signing(evidence)
        if approval is None:
            approval = self.check_approval(evidence, signing)
        if ingestion is None:
            ingestion = self.check_ingestion(evidence, signing, approval)

        now = utc(self.clock() if now is None else now)
        authorization = self.policy.keys.get(evidence.signature.keyid)

        if authorization is None:
            return self._result(
                Stage.REVERIFICATION,
                Verdict.INVALID,
                Responsibility.SIGNER,
                ReasonCode.KEY_UNKNOWN,
            )

        try:
            authorization.key.verify_signature(evidence.signature, evidence.payload)
        except UnverifiedSignatureError:
            return self._result(
                Stage.REVERIFICATION,
                Verdict.INVALID,
                Responsibility.SIGNER,
                ReasonCode.SIGNATURE_INVALID,
            )

        if signing.verdict is Verdict.INDETERMINATE:
            return self._result(
                Stage.REVERIFICATION,
                Verdict.INDETERMINATE,
                Responsibility.UNDETERMINED,
                ReasonCode.REVERIFICATION_WITHOUT_SIGNING_TIME,
                now,
            )
        if signing.verdict is Verdict.INVALID:
            return self._result(
                Stage.REVERIFICATION,
                Verdict.INVALID,
                Responsibility.SIGNER,
                ReasonCode.REVERIFICATION_REQUIRES_VALID_SIGNING,
                now,
            )
        if approval.verdict is not Verdict.VALID:
            return self._result(
                Stage.REVERIFICATION,
                Verdict.INVALID,
                Responsibility.APPROVER,
                ReasonCode.REVERIFICATION_REQUIRES_VALID_APPROVAL,
                now,
            )
        if ingestion.verdict is not Verdict.VALID:
            return self._result(
                Stage.REVERIFICATION,
                Verdict.INVALID,
                Responsibility.INGEST_OWNER,
                ReasonCode.REVERIFICATION_REQUIRES_VALID_INGESTION,
                now,
            )
        if not self.policy.reverification_window.covers(now):
            return self._result(
                Stage.REVERIFICATION,
                Verdict.INVALID,
                Responsibility.ON_CALL_VERIFIER,
                ReasonCode.REVERIFICATION_OUTSIDE_APPROVAL_WINDOW,
                now,
            )

        return self._result(
            Stage.REVERIFICATION,
            Verdict.VALID,
            Responsibility.NONE,
            ReasonCode.OK,
            now,
        )

    @staticmethod
    def _result(
        stage: Stage,
        verdict: Verdict,
        responsibility: Responsibility,
        reason: ReasonCode,
        event_at: datetime | None = None,
    ) -> StageResult:
        return StageResult(stage, verdict, responsibility, reason, event_at)


def with_timestamp(
    evidence: Evidence, attestation: TimestampAttestation | None
) -> Evidence:
    """Return a copy of evidence carrying a different timestamp attestation."""

    return replace(evidence, timestamp=attestation)


def with_approval(evidence: Evidence, approval: ApprovalRecord | None) -> Evidence:
    """Return a copy of evidence carrying a different approval record."""

    return replace(evidence, approval=approval)


def with_ingestion(evidence: Evidence, ingested_at: datetime | None) -> Evidence:
    """Return a copy of evidence carrying a different ingestion time."""

    return replace(evidence, ingested_at=ingested_at)
