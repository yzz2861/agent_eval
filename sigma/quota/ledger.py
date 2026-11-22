"""Per-window quota ledger built from distinct observations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sigma.quota.types import Observation


@dataclass
class WindowLedger:
    """Bookkeeping of one half-open ``[start, end)`` quota window.

    Only the first distinct exempt event per event identity consumes quota.
    Duplicates from multiple collectors are recorded but never deduct twice.
    """

    window_start: datetime
    window_end: datetime
    group_key: str
    quota: int
    observations: list[Observation] = field(default_factory=list)
    copies_by_event: dict[str, int] = field(default_factory=dict)

    def add(self, observation: Observation) -> bool:
        """Add an observation. Return ``True`` if it is a new distinct event."""
        seen = observation.event_id in self.copies_by_event
        self.copies_by_event[observation.event_id] = (
            self.copies_by_event.get(observation.event_id, 0) + 1
        )
        if seen:
            return False
        self.observations.append(observation)
        return True

    def _ordered(self) -> list[Observation]:
        return sorted(
            self.observations,
            key=lambda item: (item.event_time, item.ingest_time, item.event_id),
        )

    def distinct_events(self) -> list[Observation]:
        return self._ordered()

    def exempt_events(self) -> list[Observation]:
        return [item for item in self._ordered() if item.exempt]

    def nonexempt_events(self) -> list[Observation]:
        return [item for item in self._ordered() if not item.exempt]

    def deductions(self) -> list[Observation]:
        """Distinct exempt events that actually consume quota."""
        return self.exempt_events()[: self.quota]

    def forgiven(self) -> list[Observation]:
        """Exempt events covered by the window quota."""
        return self.deductions()

    def over_quota_exempt(self) -> list[Observation]:
        """Exempt distinct events that arrived after the quota ran out."""
        return self.exempt_events()[self.quota :]

    def actionable(self) -> list[Observation]:
        """Every distinct event that still requires an alert or a ticket action."""
        return self.nonexempt_events() + self.over_quota_exempt()

    def duplicate_count(self) -> int:
        return sum(copies - 1 for copies in self.copies_by_event.values())

    def remaining_quota(self) -> int:
        return max(0, self.quota - len(self.deductions()))

    def is_empty(self) -> bool:
        return not self.observations and not self.copies_by_event
