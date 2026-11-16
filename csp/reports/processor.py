from __future__ import annotations

from enum import Enum

from csp.reports.events import CSPViolationEvent
from csp.reports.rate_limiting import RateLimiter
from csp.reports.storage import InMemoryStorage, ReportStorage


class ReportStatus(str, Enum):
    STORED = "stored"
    DUPLICATE = "duplicate"
    RATE_LIMITED = "rate_limited"
    INVALID = "invalid"


class ReportProcessor:
    """Parse, normalize, deduplicate, throttle and store CSP violation reports."""

    def __init__(self, storage: ReportStorage | None = None, rate_limiter: RateLimiter | None = None) -> None:
        self.storage = storage if storage is not None else InMemoryStorage()
        self.rate_limiter = rate_limiter if rate_limiter is not None else RateLimiter()

    def process(self, payload: object) -> tuple[ReportStatus, CSPViolationEvent | None]:
        try:
            event = CSPViolationEvent.from_report(payload)
        except (TypeError, ValueError):
            return ReportStatus.INVALID, None

        key = event.deduplication_key
        # Throttle first so repeated reports count against the rate limit.
        if not self.rate_limiter.allow(key):
            return ReportStatus.RATE_LIMITED, event
        if self.storage.seen(key):
            return ReportStatus.DUPLICATE, event

        self.storage.store(event)
        return ReportStatus.STORED, event
