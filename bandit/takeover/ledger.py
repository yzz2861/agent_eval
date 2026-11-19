# SPDX-License-Identifier: Apache-2.0
"""Directory handoff ledger.

A handoff record is the *only* evidence that allows findings moved across an
ownership boundary to keep their legacy status ("old debt"). Without a
matching record the finding is treated as brand new for the receiving team,
even if the same code existed before the move.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date

from bandit.takeover import paths as path_utils

LOG = logging.getLogger(__name__)


@dataclass
class Handoff:
    """A single accepted directory handoff between two teams."""

    record_id: str
    old_path: str
    new_path: str
    from_team: str
    to_team: str
    date: str
    ticket: str = ""
    note: str = ""
    _old_n: str = field(default="", repr=False)
    _new_n: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        self._old_n = path_utils.normalize_path(self.old_path)
        self._new_n = path_utils.normalize_path(self.new_path)

    def covers(self, normalized_path: str) -> bool:
        """Return True when the handoff covers the given new-location path."""
        return path_utils.is_within(self._new_n, normalized_path)

    def moved_from(self, normalized_path: str) -> str:
        """Translate a new-location path back to its pre-handoff location."""
        base = self._new_n
        if normalized_path == base:
            return self._old_n
        suffix = normalized_path[len(base):].lstrip("/")
        return path_utils.normalize_path(self._old_n + "/" + suffix)

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "from_team": self.from_team,
            "to_team": self.to_team,
            "date": self.date,
            "ticket": self.ticket,
            "note": self.note,
        }


class HandoffLedger:
    """An append-only collection of accepted handoff records."""

    def __init__(self, handoffs=None) -> None:
        self._handoffs = list(handoffs or [])

    @classmethod
    def from_dict(cls, payload: dict) -> "HandoffLedger":
        raw = payload.get(
            "handoffs",
            payload if isinstance(payload, list) else [],
        )
        handoffs = []
        for item in raw:
            try:
                handoffs.append(
                    Handoff(
                        record_id=str(item["record_id"]),
                        old_path=str(item["old_path"]),
                        new_path=str(item["new_path"]),
                        from_team=str(item["from_team"]),
                        to_team=str(item["to_team"]),
                        date=str(item.get("date", date.today().isoformat())),
                        ticket=str(item.get("ticket", "")),
                        note=str(item.get("note", "")),
                    )
                )
            except (KeyError, TypeError) as exc:
                LOG.warning(
                    "Skipping malformed handoff record %r: %s",
                    item,
                    exc,
                )
        return cls(handoffs)

    def find(self, normalized_path: str):
        """Return the most specific (longest) handoff covering a path."""
        candidates = [h for h in self._handoffs if h.covers(normalized_path)]
        if not candidates:
            return None
        return max(candidates, key=lambda h: len(h._new_n))

    def all(self) -> list:
        return list(self._handoffs)

    def __len__(self) -> int:
        return len(self._handoffs)
