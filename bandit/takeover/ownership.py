# SPDX-License-Identifier: Apache-2.0
"""Path ownership policy.

Maps every repository path to the team currently responsible for it.  The
policy is a list of directory entries ordered from most specific (longest
prefix) to least specific; the first match wins.  A path matching no entry is
reported as unowned rather than silently assigned to a fallback team.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from bandit.takeover import paths as path_utils

LOG = logging.getLogger(__name__)

UNOWNED = "UNOWNED"


@dataclass
class OwnershipEntry:
    """One directory -> team assignment from the policy document."""

    directory: str
    team: str
    _normalized: str = ""

    def __post_init__(self) -> None:
        self._normalized = path_utils.normalize_path(self.directory)

    def covers(self, normalized_path: str) -> bool:
        return path_utils.is_within(self._normalized, normalized_path)

    def to_dict(self) -> dict:
        return {"directory": self.directory, "team": self.team}


class OwnershipPolicy:
    """Resolves the responsible team for any repository path."""

    def __init__(self, entries=None, path_map=None) -> None:
        self.path_map = path_map
        # Longest prefix first so nested, more specific directories win.
        self._entries = sorted(
            entries or [], key=lambda e: len(e._normalized), reverse=True
        )

    @classmethod
    def from_dict(cls, payload: dict, path_map=None) -> "OwnershipPolicy":
        payload = payload or {}
        raw = payload.get("ownership", payload)
        entries = []
        for item in raw:
            if (
                isinstance(item, dict)
                and "directory" in item
                and "team" in item
            ):
                entries.append(
                    OwnershipEntry(
                        directory=str(item["directory"]),
                        team=str(item["team"]),
                    )
                )
            else:
                LOG.warning("Skipping malformed ownership entry %r", item)
        return cls(entries, path_map=path_map)

    def resolve(self, path: str) -> str:
        """Return the team responsible for *path*.

        The path is first rewritten through the current :class: so
        policies can be authored against post-split repository locations even
        when a report still carries historical paths.
        """
        normalized = path_utils.normalize_path(path)
        if self.path_map is not None:
            normalized = self.path_map.rewrite(normalized)
        for entry in self._entries:
            if entry.covers(normalized):
                return entry.team
        return UNOWNED

    def owned_directories(self) -> list:
        return list(self._entries)
