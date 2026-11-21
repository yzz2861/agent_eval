from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from sigma.review.synthesis import UnexplainedModifier

#: Verdict of a replacement review.
ReviewVerdict = Literal["replacement_covers", "keep_old_rules", "inconclusive"]

#: Statement attached to every report: only the current review run may serve as approval basis.
APPROVAL_BASIS_NOTE = (
    "Only this review run is a valid approval basis; coverage results from previous "
    "reviews must not be reused to approve the removal of old rules."
)


@dataclass
class UniqueEventEvidence:
    """
    Evidence for a synthetic event that is only detected by old rules.

    This is the proof a maintainer keeps when an old rule must stay (or its consumers must be
    migrated) because the candidate replacement does not cover the event.
    """

    rule: str
    perspective: str  # "original", "transformed" or "consumer"
    event_data: dict[str, Any]
    event_raw: str | None
    logsource: tuple[str | None, str | None, str | None]
    affected_consumers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "perspective": self.perspective,
            "event_data": self.event_data,
            "event_raw": self.event_raw,
            "logsource": list(self.logsource),
            "affected_consumers": list(self.affected_consumers),
        }


@dataclass
class ReplacementReviewReport:
    """
    Result of an offline replacement review.

    Each report is generated from scratch in a single review run. ``prior_coverage_accepted``
    is always ``False``: results of earlier coverage reviews are never an approval basis for
    removing old rules.
    """

    review_id: str
    generated_at: datetime
    verdict: ReviewVerdict
    unique_events: list[UniqueEventEvidence] = field(default_factory=list)
    unexplained_modifiers: list[UnexplainedModifier] = field(default_factory=list)
    uncovered_rules: list[str] = field(default_factory=list)
    on_call_briefing: str = ""
    prior_coverage_accepted: bool = False
    approval_basis: str = APPROVAL_BASIS_NOTE

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "generated_at": self.generated_at.isoformat(),
            "verdict": self.verdict,
            "unique_events": [event.to_dict() for event in self.unique_events],
            "unexplained_modifiers": [
                modifier.to_dict() for modifier in self.unexplained_modifiers
            ],
            "uncovered_rules": list(self.uncovered_rules),
            "on_call_briefing": self.on_call_briefing,
            "prior_coverage_accepted": self.prior_coverage_accepted,
            "approval_basis": self.approval_basis,
        }
