# Independent exception decision engine.
#
# The engine answers a single question for each finding at a given point in
# time: is there a valid exception that covers it, and if so why (or why not)?
#
# Time is always supplied by the caller as an explicit snapshot. The engine
# never reads the wall clock, so replaying a historical report with the same
# snapshot and the same immutable store yields the exact same decisions.
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from enum import Enum
from typing import List
from typing import Sequence

from .identity import SecretIdentity
from .records import ExceptionRecord
from .rules import RuleVersion
from .scope import Scope
from .store import ExceptionStore


def utc_now() -> datetime:
    # Convenience for callers that want the real clock. The engine itself never
    # calls this; tests and historical replays pass an explicit snapshot.
    from datetime import timezone

    return datetime.now(timezone.utc)


def _require_aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be a timezone-aware datetime")
    return value


@dataclass(frozen=True)
class Finding:
    # A scan result. The location is descriptive only: it is never part of the
    # identity, which is what allows a file move to preserve the exception.
    secret_identity: SecretIdentity
    scope: Scope
    rule: RuleVersion
    filename: str
    line_number: int = 0


class DecisionStatus(str, Enum):
    EXEMPT = "exempt"
    CONFLICT = "conflict"
    NO_EXCEPTION = "no_exception"
    REVOKED = "revoked"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    SCOPE_WIDENED = "scope_widened"
    RULE_UPGRADED = "rule_upgraded"


@dataclass(frozen=True)
class Decision:
    finding: Finding
    status: DecisionStatus
    snapshot: datetime
    reasons: List[str] = field(default_factory=list)
    matching_records: List[ExceptionRecord] = field(default_factory=list)

    @property
    def is_exempt(self) -> bool:
        return self.status is DecisionStatus.EXEMPT


class ExceptionEngine:
    def __init__(self, store: ExceptionStore) -> None:
        self._store = store

    def evaluate(self, finding: Finding, snapshot: datetime) -> Decision:
        _require_aware(snapshot, "snapshot")

        conflict_ids = {
            tuple(conflict.decision_ids)
            for conflict in self._store.active_conflicts()
            if conflict.secret_identity == finding.secret_identity
        }
        if conflict_ids:
            return Decision(
                finding=finding,
                status=DecisionStatus.CONFLICT,
                snapshot=snapshot,
                reasons=[
                    "unresolved merged exception conflict; refusing to pick a "
                    "winner automatically",
                    f"candidate decision_ids: {sorted(conflict_ids)[0]}",
                ],
                matching_records=self._store.heads_for(finding.secret_identity),
            )

        heads = self._store.heads_for(finding.secret_identity)
        if not heads:
            return Decision(
                finding=finding,
                status=DecisionStatus.NO_EXCEPTION,
                snapshot=snapshot,
                reasons=["no exception record exists for this secret identity"],
            )

        head = heads[0]

        if not head.is_approved:
            return Decision(
                finding=finding,
                status=DecisionStatus.REVOKED,
                snapshot=snapshot,
                reasons=[f"decision {head.decision_id} revoked the exception"],
                matching_records=[head],
            )

        if not head.scope.contains(finding.scope):
            return Decision(
                finding=finding,
                status=DecisionStatus.SCOPE_WIDENED,
                snapshot=snapshot,
                reasons=[
                    f"approved scope {head.scope} does not contain finding "
                    f"scope {finding.scope}; scope widening needs a new decision",
                ],
                matching_records=[head],
            )

        if not head.rule.is_compatible_with(finding.rule):
            return Decision(
                finding=finding,
                status=DecisionStatus.RULE_UPGRADED,
                snapshot=snapshot,
                reasons=[
                    f"rule {finding.rule.name} semantics changed: approved at "
                    f"{head.rule.to_string()}, finding produced by "
                    f"{finding.rule.to_string()}; re-judgement required",
                ],
                matching_records=[head],
            )

        if snapshot < head.effective_at:
            return Decision(
                finding=finding,
                status=DecisionStatus.NOT_YET_VALID,
                snapshot=snapshot,
                reasons=[
                    f"decision {head.decision_id} becomes valid at "
                    f"{head.effective_at.isoformat()}",
                ],
                matching_records=[head],
            )

        if snapshot >= head.expires_at:
            return Decision(
                finding=finding,
                status=DecisionStatus.EXPIRED,
                snapshot=snapshot,
                reasons=[
                    f"decision {head.decision_id} expired at "
                    f"{head.expires_at.isoformat()}",
                ],
                matching_records=[head],
            )

        return Decision(
            finding=finding,
            status=DecisionStatus.EXEMPT,
            snapshot=snapshot,
            reasons=[
                f"covered by decision {head.decision_id}",
                f"approved by {head.decided_by}: {head.rationale}",
            ],
            matching_records=[head],
        )

    def evaluate_many(
        self,
        findings: Sequence[Finding],
        snapshot: datetime,
    ) -> List[Decision]:
        return [self.evaluate(finding, snapshot) for finding in findings]
