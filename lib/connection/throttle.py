from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Awaitable, Callable
from email.utils import parsedate_to_datetime

from lib.core.settings import (
    RATE_LIMIT_BACKOFF_MAX,
    RATE_LIMIT_BACKOFF_MIN,
    RATE_LIMIT_STATUSES,
    RATE_LIMIT_WAIT_POLL_SECONDS,
)


def parse_retry_after(value: str | None) -> float | None:
    """Return the delay in seconds asked for by a Retry-After header value.

    Supports both delta-seconds and HTTP-date forms. Returns None when the
    header is absent or unparsable, and clamps absurd values to the backoff
    ceiling so a hostile target cannot stall a scan forever.
    """
    if not value:
        return None

    value = value.strip()
    if value.isdigit():
        return min(float(int(value)), RATE_LIMIT_BACKOFF_MAX)

    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None

    if retry_at is None:
        return None

    delay = retry_at.timestamp() - time.time()
    if delay <= 0:
        return None

    return min(delay, RATE_LIMIT_BACKOFF_MAX)


def is_rate_limit_signal(status: int, retry_after: str | None) -> bool:
    """Return whether a response carries a target-side throttling signal."""
    return status in RATE_LIMIT_STATUSES or retry_after is not None


class AdaptiveThrottle:
    """Per-target adaptive backoff for rate-limited responses.

    Combines three knobs that react to 429/503 responses and Retry-After
    headers: an in-flight concurrency cap (multiplicative decrease, additive
    recovery), a minimum interval between request starts, and an absolute
    backoff deadline during which no new request may start. One instance is
    owned by a requester and reset whenever the target URL changes, so state
    never leaks across targets.
    """

    def __init__(
        self,
        max_concurrency: int,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
        async_sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._async_sleep = async_sleep or asyncio.sleep
        self._max_limit = max(1, max_concurrency)
        self._limit = self._max_limit
        self._in_flight = 0
        self._backoff = 0.0
        self._backoff_until = 0.0
        self._last_start: float | None = None
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        """Current adaptive cap on simultaneous in-flight requests."""
        with self._lock:
            return self._limit

    @property
    def interval(self) -> float:
        """Current minimum delay between request starts."""
        with self._lock:
            return self._backoff

    @property
    def throttled(self) -> bool:
        with self._lock:
            return self._backoff > 0 or self._limit < self._max_limit

    def reset(self) -> None:
        """Drop all adaptive state; called when the target changes."""
        with self._lock:
            self._limit = self._max_limit
            self._backoff = 0.0
            self._backoff_until = 0.0
            self._last_start = None

    def record_response(self, status: int, retry_after: str | None) -> float | None:
        """Adapt to a finished response.

        Returns the backoff delay applied when the response carried a
        throttling signal, or None for an ordinary response.
        """
        if not is_rate_limit_signal(status, retry_after):
            with self._lock:
                self._limit = min(self._max_limit, self._limit + 1)
                self._backoff = max(0.0, self._backoff / 2)
                if self._backoff < RATE_LIMIT_BACKOFF_MIN:
                    self._backoff = 0.0
            return None

        requested = parse_retry_after(retry_after)
        with self._lock:
            self._backoff = min(
                RATE_LIMIT_BACKOFF_MAX,
                max(self._backoff * 2, RATE_LIMIT_BACKOFF_MIN),
            )
            delay = max(self._backoff, requested or 0.0)
            self._backoff_until = self._clock() + delay
            self._limit = max(1, self._limit // 2)
            return delay

    def acquire(self) -> None:
        while (delay := self._try_reserve()) is not None:
            self._sleep(min(delay, RATE_LIMIT_WAIT_POLL_SECONDS))

    async def acquire_async(self) -> None:
        while (delay := self._try_reserve()) is not None:
            await self._async_sleep(min(delay, RATE_LIMIT_WAIT_POLL_SECONDS))

    def release(self) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)

    def _try_reserve(self) -> float | None:
        with self._lock:
            now = self._clock()
            if self._in_flight >= self._limit:
                return RATE_LIMIT_WAIT_POLL_SECONDS

            ready_at = max(self._backoff_until, 0.0)
            if self._last_start is not None:
                ready_at = max(ready_at, self._last_start + self._backoff)

            if now < ready_at:
                return ready_at - now

            self._in_flight += 1
            self._last_start = now
            return None
