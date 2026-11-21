from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sigma.matching.event import EventLogSource
from sigma.rule.logsource import SigmaLogSource


@dataclass(frozen=True)
class ConsumerProfile:
    """
    Describes a downstream consumer of Sigma detections.

    A consumer subscribes to a log source and only receives a restricted set of
    event fields. The replacement review uses this profile to determine which
    synthetic events a consumer would actually still observe after old rules are
    removed.

    * ``available_fields`` is ``None`` if the consumer receives all event fields,
      otherwise it restricts the fields the consumer can evaluate.
    * ``on_call`` names the on-call channel or rotation that must be briefed when
      evidence is kept for this consumer.
    """

    name: str
    logsource: SigmaLogSource
    available_fields: frozenset[str] | None = None
    on_call: str | None = None

    def subscribes_to(self, logsource: EventLogSource) -> bool:
        """Check if this consumer subscribes to events from the given log source."""
        event_logsource = SigmaLogSource(
            category=logsource.category,
            product=logsource.product,
            service=logsource.service,
        )
        return event_logsource in self.logsource

    def project(self, data: dict[str, Any]) -> dict[str, Any]:
        """Restrict event data to the fields the consumer actually receives."""
        if self.available_fields is None:
            return dict(data)
        return {field: value for field, value in data.items() if field in self.available_fields}
