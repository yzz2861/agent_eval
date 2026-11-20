from __future__ import annotations

import json
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from ...exceptions import UnableToReadBaselineError
from .exceptions import InvalidLinkageMaterialError
from .exceptions import LinkageProjectMismatchError
from .schema import REQUIRED_FIELDS
from .schema import LinkageRecord
from .schema import parse_timestamp
from .timeutil import format_timestamp
from .timeutil import utcnow


class LinkageManifest:
    """Trusted, project-scoped linkage material for one transition window.

    The manifest only stores pseudonymous identifiers shaped like baseline
    hashed_secret values. Secret plaintext is never present: a new key
    cannot recompute old identifiers and review history cannot be re-read.
    """

    def __init__(
        self,
        project_id: str,
        transition_starts_at: str,
        transition_ends_at: str,
        records: List[LinkageRecord],
    ) -> None:
        self.project_id = project_id
        self.transition_starts_at = parse_timestamp(transition_starts_at)
        self.transition_ends_at = parse_timestamp(transition_ends_at)
        if self.transition_ends_at <= self.transition_starts_at:
            raise InvalidLinkageMaterialError(
                "transition_ends_at must be later than transition_starts_at",
            )
        for record in records:
            if record.project_id != project_id:
                raise LinkageProjectMismatchError(
                    "record {} belongs to project {}, expected {}".format(
                        record.record_id, record.project_id, project_id,
                    ),
                )
        self.records = records

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LinkageManifest":
        try:
            records = [
                LinkageRecord.from_dict(item) for item in data["records"]
            ]
            return cls(
                project_id=str(data["project_id"]),
                transition_starts_at=str(data["transition_starts_at"]),
                transition_ends_at=str(data["transition_ends_at"]),
                records=records,
            )
        except InvalidLinkageMaterialError:
            raise
        except LinkageProjectMismatchError:
            raise
        except (KeyError, TypeError, ValueError) as e:
            raise InvalidLinkageMaterialError(str(e)) from e

    @classmethod
    def load(cls, filename: str) -> "LinkageManifest":
        try:
            with open(filename, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as e:
            raise UnableToReadBaselineError(str(e)) from e

        if not isinstance(data, dict):
            raise InvalidLinkageMaterialError(
                "linkage material must be a JSON object",
            )
        missing = REQUIRED_FIELDS - set(data.keys())
        if missing:
            raise InvalidLinkageMaterialError(
                "linkage material is missing fields: {}".format(
                    ", ".join(sorted(missing)),
                ),
            )
        return cls.from_dict(data)

    def records_for(
        self,
        rule_id: str,
        old_secret_id: str,
    ) -> List[LinkageRecord]:
        """Return evidence for one rule + old identifier pair.

        The old identifier is never matched on its own: rule_id is part of
        the key so equal hashes under different rules cannot be merged.
        """
        return [
            record
            for record in self.records
            if record.rule_id == rule_id
            and record.old_secret_id == old_secret_id
        ]

    def require_project(self, project_id: str) -> None:
        """Refuse linkage material produced for a different project."""
        if project_id != self.project_id:
            raise LinkageProjectMismatchError(
                "linkage material is scoped to project {}, not {}".format(
                    self.project_id, project_id,
                ),
            )

    def is_window_open(self, at: Optional[str] = None) -> bool:
        moment = parse_timestamp(at) if at else utcnow()
        return self.transition_starts_at <= moment < self.transition_ends_at

    def json(self) -> Dict[str, Any]:
        return {
            "project_id": self.project_id,
            "transition_starts_at": format_timestamp(self.transition_starts_at),
            "transition_ends_at": format_timestamp(self.transition_ends_at),
            "records": [record.json() for record in self.records],
        }
