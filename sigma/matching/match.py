from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sigma.matching.handover import HandoverUndeterminableRange

if TYPE_CHECKING:
    from sigma.matching.event import Event
    from sigma.rule.base import SigmaRuleBase


@dataclass
class SigmaMatch:
    """Result of a successful Sigma rule match against one or more events."""

    rule: SigmaRuleBase
    events: list[Event]
    timestamp: datetime
    group_values: dict[str, Any] | None = None


@dataclass(frozen=True)
class MatchOutcome:
    """Matches and handover coverage information produced for one event."""

    matches: list[SigmaMatch]
    undeterminable_ranges: list[HandoverUndeterminableRange] = field(default_factory=list)

    @property
    def undecidable_ranges(self) -> list[HandoverUndeterminableRange]:
        return self.undeterminable_ranges
