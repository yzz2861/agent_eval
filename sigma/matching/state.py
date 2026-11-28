from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch


class SlidingWindowState:
    """Manages sliding time window state for correlation rules."""

    def __init__(self, window_seconds: int, max_entries: int | None = None) -> None:
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        # group_key -> deque of (timestamp, identifier, match)
        self._state: dict[
            tuple[Any, ...], deque[tuple[datetime, str, SigmaMatch]]
        ] = defaultdict(deque)
        self._identifiers: dict[tuple[Any, ...], set[str]] = defaultdict(set)

    def add(self, group_key: tuple[Any, ...], match: SigmaMatch, identifier: str) -> bool:
        """Add a match to the state for the given group key."""
        entries = self._state[group_key]
        identifiers = self._identifiers[group_key]
        if identifier in identifiers:
            return False
        entries.append((match.timestamp, identifier, match))
        identifiers.add(identifier)
        if self.max_entries is not None and len(entries) > self.max_entries:
            _, removed_identifier, _ = entries.popleft()
            identifiers.discard(removed_identifier)
        return True

    def get_window(self, group_key: tuple[Any, ...], now: datetime) -> list[SigmaMatch]:
        """Get all matches within the time window for the given group key."""
        self._evict_group(group_key, now)
        return [match for _, _, match in self._state[group_key]]

    def _evict_group(self, group_key: tuple[Any, ...], now: datetime) -> None:
        """Remove entries outside the time window."""
        entries = self._state[group_key]
        cutoff = now - timedelta(seconds=self.window_seconds)
        while entries and entries[0][0] < cutoff:
            _, removed_identifier, _ = entries.popleft()
            self._identifiers[group_key].discard(removed_identifier)

    def evict(self) -> None:
        """Remove empty groups."""
        empty_keys = [k for k, v in self._state.items() if not v]
        for k in empty_keys:
            del self._state[k]
            self._identifiers.pop(k, None)

    def snapshot(self) -> dict[str, object]:
        return {
            "state": {
                group_key: list(entries) for group_key, entries in self._state.items() if entries
            },
            "identifiers": {
                group_key: set(identifiers)
                for group_key, identifiers in self._identifiers.items()
                if identifiers
            },
        }

    def restore(self, state: dict[str, object], rules_by_name: dict[str, Any]) -> None:
        self._state = defaultdict(deque)
        self._identifiers = defaultdict(set)
        for group_key, entries in state["state"].items():  # type: ignore[union-attr]
            restored_entries = deque()
            for timestamp, identifier, match in entries:
                rule_name = getattr(match.rule, "name", None)
                if rule_name is not None and rule_name in rules_by_name:
                    match.rule = rules_by_name[rule_name]
                restored_entries.append((timestamp, identifier, match))
            self._state[group_key] = restored_entries
        for group_key, identifiers in state["identifiers"].items():  # type: ignore[union-attr]
            self._identifiers[group_key] = set(identifiers)


def event_hash(event: Event) -> str:
    payload = json.dumps(
        {
            "timestamp": event.timestamp.isoformat(),
            "logsource": event.logsource.as_tuple(),
            "data": event.data,
            "raw": event.raw,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def event_identity(event: Event | None, allow_content_identity: bool) -> str | None:
    if event is None:
        return None
    if event.synthetic_event_id is not None:
        return f"synthetic:{event.synthetic_event_id}"
    if allow_content_identity:
        return f"content:{event_hash(event)}"
    return None
