from __future__ import annotations

import json
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from .exceptions import UnsafeMigrationReportError

# Keys whose presence would let a finding be re-identified across projects.
# Secret plaintext is banned too; pseudonymous identifiers are equally unsafe
# because a report could be joined against another project material set.
_CORRELATABLE_KEYS = frozenset(
    {
        "old_secret_id",
        "new_secret_id",
        "hashed_secret",
        "secret_hash",
        "secret",
        "secret_value",
    },
)


class MigrationStatus(Enum):
    """Outcome of carrying one human-adjudicated alert forward."""

    MIGRATED = "migrated"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"
    EXPIRED = "expired"
    UNMIGRATED = "unmigrated"
    TARGET_MISSING = "target_missing"


class MigrationEntry:
    """One sanitized, project-scoped report row."""

    def __init__(
        self,
        record_ref: str,
        project_id: str,
        rule_id: str,
        filename: str,
        line_number: int,
        status: MigrationStatus,
        reason: str,
        decision: Optional[bool],
        evidence_count: int,
    ) -> None:
        self.record_ref = record_ref
        self.project_id = project_id
        self.rule_id = rule_id
        self.filename = filename
        self.line_number = line_number
        self.status = status
        self.reason = reason
        self.decision = decision
        self.evidence_count = evidence_count

    def json(self) -> Dict[str, Any]:
        return {
            "record_ref": self.record_ref,
            "project_id": self.project_id,
            "rule_id": self.rule_id,
            "filename": self.filename,
            "line_number": self.line_number,
            "status": self.status.value,
            "reason": self.reason,
            "decision": self.decision,
            "evidence_count": self.evidence_count,
        }


class MigrationReport:
    """Durable, shareable artifact of a migration run.

    It contains no secret plaintext and no value that can correlate the
    same finding across projects. record_ref values are per-run random ids,
    generated independently for every report.
    """

    def __init__(
        self,
        project_id: str,
        window_open: bool,
        evaluated_at: str,
        entries: List[MigrationEntry],
    ) -> None:
        self.project_id = project_id
        self.window_open = window_open
        self.evaluated_at = evaluated_at
        self.entries = entries

    def entries_with_status(
        self,
        status: MigrationStatus,
    ) -> List[MigrationEntry]:
        return [entry for entry in self.entries if entry.status == status]

    @property
    def pending_entries(self) -> List[MigrationEntry]:
        """Items not carried forward, including after an early close."""
        return [
            entry
            for entry in self.entries
            if entry.status != MigrationStatus.MIGRATED
        ]

    def json(self) -> Dict[str, Any]:
        return {
            "project_id": self.project_id,
            "window_open": self.window_open,
            "evaluated_at": self.evaluated_at,
            "summary": {
                status.value: len(self.entries_with_status(status))
                for status in MigrationStatus
            },
            "entries": [entry.json() for entry in self.entries],
        }

    def to_json_string(self) -> str:
        return json.dumps(self.json(), indent=2, sort_keys=True)


def assert_report_is_sanitized(
    report: Dict[str, Any],
    forbidden_values: Optional[List[str]] = None,
) -> None:
    """Validate that a serialized report leaks neither plaintext nor
    cross-project correlatable identifiers.

    :param forbidden_values: secret plaintext candidates (test virtual
        candidates, or any value that must never appear).
    :raises UnsafeMigrationReportError: on the first violation found.
    """
    forbidden = [value for value in (forbidden_values or []) if value]

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _CORRELATABLE_KEYS:
                    raise UnsafeMigrationReportError(
                        "correlatable identifier key in report: {}".format(key),
                    )
                walk(value, "{}.{}".format(path, key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, "{}[{}]".format(path, index))
        elif isinstance(node, str):
            for value in forbidden:
                if value in node:
                    raise UnsafeMigrationReportError(
                        "forbidden plaintext value in report at {}".format(path),
                    )

    walk(report, "$")
