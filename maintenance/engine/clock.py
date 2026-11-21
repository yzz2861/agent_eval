"""Fixed clock support for deterministic offline verification.

The maintenance station evaluates bundles at a known fixed time (the
inventory / preparation instant) rather than relying on the host wall clock.
All expiry decisions in the engine go through :class:`FixedClock`, so the same
scenario always produces the same verdict on any machine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


def parse_iso(value: str | datetime) -> datetime:
    """Parse an ISO-8601 string into a timezone-aware datetime."""
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp {value!r} must be timezone-aware")
    return parsed


@dataclass(frozen=True)
class FixedClock:
    """A single immutable reference instant used for every expiry check."""

    now: datetime

    @classmethod
    def from_iso(cls, value: str | datetime) -> FixedClock:
        return cls(parse_iso(value))

    def is_before_expiry(self, expires: datetime) -> bool:
        return self.now < parse_iso(expires)
