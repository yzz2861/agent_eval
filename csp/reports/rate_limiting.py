from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Callable, Deque

KeyT = tuple[Any, ...]


class RateLimiter:
    """Sliding-window rate limiter.

    Reports are grouped by a key derived from the normalized event. By default
    the full source/directive/document-uri dedup tuple is used, but a custom
    ``key_func`` (for example one that drops the document-uri) allows all
    reports from the same source/directive to share one budget.

    At most ``max_events`` attempts are allowed within any rolling
    ``window_seconds`` interval.
    """

    def __init__(
        self,
        max_events: int = 100,
        window_seconds: float = 60.0,
        key_func: Callable[[KeyT], KeyT] | None = None,
    ) -> None:
        if max_events < 1:
            raise ValueError("max_events must be a positive integer")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.key_func = key_func
        self._lock = Lock()
        self._hits: dict[KeyT, Deque[float]] = defaultdict(deque)

    def _bucket(self, key: KeyT) -> KeyT:
        return self.key_func(key) if self.key_func is not None else key

    def allow(self, key: KeyT, now: float | None = None) -> bool:
        """Record an attempt and return whether it is within the rate limit."""
        current = time.monotonic() if now is None else now
        cutoff = current - self.window_seconds
        bucket = self._bucket(key)
        with self._lock:
            hits = self._hits[bucket]
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.max_events:
                return False
            hits.append(current)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
