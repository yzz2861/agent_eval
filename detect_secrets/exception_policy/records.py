# Immutable exception decision records.
#
# A record captures a single human/automated decision about a secret identity.
# Records are append-only and never mutated: a changed decision is expressed by
# appending a new record that supersedes the old one. The record stores hashed
# approval evidence (never plaintext) so an auditor can reconstruct *why* a
# decision was made without the secret value ever being persisted.
import hashlib
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from enum import Enum
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple
from uuid import uuid4

from .identity import SecretIdentity
from .rules import RuleVersion
from .scope import Scope


class DecisionState(str, Enum):
    APPROVED = "approved"
    REVOKED = "revoked"


def _require_aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be a timezone-aware datetime")
    return value


@dataclass(frozen=True)
class ExceptionRecord:
    decision_id: str
    secret_identity: SecretIdentity
    scope: Scope
    rule: RuleVersion
    state: DecisionState
    created_at: datetime
    effective_at: datetime
    expires_at: datetime
    decided_by: str
    rationale: str
    evidence_fingerprints: Tuple[str, ...] = field(default_factory=tuple)
    supersedes: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.decision_id:
            raise ValueError("decision_id is required")
        if not self.decided_by:
            raise ValueError("decided_by is required")
        if not self.rationale:
            raise ValueError("rationale is required to preserve approval basis")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.effective_at, "effective_at")
        _require_aware(self.expires_at, "expires_at")
        if self.effective_at > self.expires_at:
            raise ValueError("effective_at must not be after expires_at")
        if not isinstance(self.state, DecisionState):
            raise ValueError("state must be a DecisionState")

    @property
    def is_approved(self) -> bool:
        return self.state is DecisionState.APPROVED

    def is_active_at(self, snapshot: datetime) -> bool:
        # Half-open interval [effective_at, expires_at): the exact expiry
        # instant is no longer covered, which makes the clock boundary testable.
        _require_aware(snapshot, "snapshot")
        return self.effective_at <= snapshot < self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "secret_identity": self.secret_identity.to_dict(),
            "scope": self.scope.to_dict(),
            "rule": self.rule.to_dict(),
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "effective_at": self.effective_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "decided_by": self.decided_by,
            "rationale": self.rationale,
            "evidence_fingerprints": list(self.evidence_fingerprints),
            "supersedes": list(self.supersedes),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExceptionRecord":
        return cls(
            decision_id=str(data["decision_id"]),
            secret_identity=SecretIdentity.from_dict(data["secret_identity"]),
            scope=Scope.from_dict(data["scope"]),
            rule=RuleVersion(
                name=str(data["rule"]["name"]),
                major=int(str(data["rule"]["version"]).split(".")[0]),
                minor=int(str(data["rule"]["version"]).split(".")[1]),
                patch=int(str(data["rule"]["version"]).split(".")[2]),
            ),
            state=DecisionState(str(data["state"])),
            created_at=datetime.fromisoformat(str(data["created_at"])),
            effective_at=datetime.fromisoformat(str(data["effective_at"])),
            expires_at=datetime.fromisoformat(str(data["expires_at"])),
            decided_by=str(data["decided_by"]),
            rationale=str(data["rationale"]),
            evidence_fingerprints=tuple(data.get("evidence_fingerprints", [])),
            supersedes=tuple(data.get("supersedes", [])),
        )


def evidence_fingerprint(reference: str, detail: Optional[str] = None) -> str:
    # Hash an approval reference (ticket URL, reviewer note, ...) so the basis
    # for the decision is retained without storing any secret material.
    payload = reference if detail is None else f"{reference}\n{detail}"
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()



def build_record(
    secret_identity: SecretIdentity,
    scope: Scope,
    rule: RuleVersion,
    decided_by: str,
    rationale: str,
    created_at: datetime,
    expires_at: datetime,
    state: DecisionState = DecisionState.APPROVED,
    effective_at: Optional[datetime] = None,
    evidence_references: Tuple[str, ...] = (),
    supersedes: Tuple[str, ...] = (),
    decision_id: Optional[str] = None,
) -> ExceptionRecord:
    # Convenience constructor: defaults the validity window to the creation
    # time and fingerprints approval references instead of storing raw notes.
    return ExceptionRecord(
        decision_id=decision_id or uuid4().hex,
        secret_identity=secret_identity,
        scope=scope,
        rule=rule,
        state=state,
        created_at=created_at,
        effective_at=effective_at or created_at,
        expires_at=expires_at,
        decided_by=decided_by,
        rationale=rationale,
        evidence_fingerprints=tuple(
            evidence_fingerprint(reference) for reference in evidence_references
        ),
        supersedes=tuple(supersedes),
    )
