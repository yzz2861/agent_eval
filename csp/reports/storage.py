from __future__ import annotations

from abc import ABC, abstractmethod
from threading import Lock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from csp.reports.events import CSPViolationEvent


class ReportStorage(ABC):
    """Abstract storage backend for normalized CSP violation events."""

    @abstractmethod
    def store(self, event: CSPViolationEvent) -> None:
        """Persist a normalized violation event."""

    @abstractmethod
    def seen(self, key: tuple[str, str, str]) -> bool:
        """Return whether an event with the given dedup key has been stored."""

    @abstractmethod
    def clear(self) -> None:
        """Remove all stored events and dedup state."""


class InMemoryStorage(ReportStorage):
    """A thread-safe in-memory storage backend, suitable for tests and small deployments."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._events: list[CSPViolationEvent] = []
        self._keys: set[tuple[str, str, str]] = set()

    def store(self, event: CSPViolationEvent) -> None:
        with self._lock:
            self._events.append(event)
            self._keys.add(event.deduplication_key)

    def seen(self, key: tuple[str, str, str]) -> bool:
        with self._lock:
            return key in self._keys

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._keys.clear()

    @property
    def events(self) -> list[CSPViolationEvent]:
        with self._lock:
            return list(self._events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
