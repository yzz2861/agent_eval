from __future__ import annotations

import threading
from typing import Protocol


class DPoPReplayCache(Protocol):
    def claim(self, jti: str, ttl: int, now: int | float) -> bool:
        """Atomically store ``jti``.

        Return ``True`` when this caller wins the claim and ``False`` when
        ``jti`` has already been used within its replay window.
        """


class InMemoryDPoPReplayCache:
    def __init__(self):
        self._items: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, jti: str, ttl: int, now: int | float) -> bool:
        expires_at = now + ttl
        with self._lock:
            current = self._items.get(jti)
            if current is not None and current > now:
                return False
            self._items[jti] = expires_at
            expired = [key for key, value in self._items.items() if value <= now]
            for key in expired:
                self._items.pop(key, None)
            return True

    def __len__(self):
        return len(self._items)
