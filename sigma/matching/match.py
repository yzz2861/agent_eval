from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

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

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """Evidence identities explicitly attached to the matched events."""
        return tuple(e.event_id for e in self.events if e.event_id is not None)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable offline representation of this match."""
        rule_id = getattr(self.rule, "id", None)
        return {
            "rule": getattr(self.rule, "name", None) or str(self.rule.title),
            "rule_id": str(rule_id) if rule_id is not None else None,
            "timestamp": self.timestamp.isoformat(),
            "group_values": dict(self.group_values) if self.group_values is not None else None,
            "evidence_ids": sorted(set(self.evidence_ids)),
            "event_count": len(self.events),
        }
