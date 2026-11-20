from __future__ import annotations

from datetime import datetime
from typing import Any
from typing import Dict

from .exceptions import InvalidLinkageMaterialError
from .timeutil import parse_timestamp

REQUIRED_FIELDS = frozenset(
    {
        "project_id",
        "transition_starts_at",
        "transition_ends_at",
        "records",
    },
)

_RECORD_FIELDS = frozenset(
    {
        "record_id",
        "project_id",
        "rule_id",
        "old_secret_id",
        "new_secret_id",
        "not_before",
        "not_after",
    },
)


class LinkageRecord:
    """Trusted association between an old pseudonymous identifier and its
    replacement under the new desensitization key.

    Both identifiers are hashes shaped like a baseline hashed_secret field;
    secret plaintext is never read or stored in linkage material.
    """

    def __init__(
        self,
        project_id: str,
        rule_id: str,
        old_secret_id: str,
        new_secret_id: str,
        not_before: str,
        not_after: str,
        filename: str = "",
        attestation: str = "",
        record_id: str = "",
    ) -> None:
        self.record_id = record_id
        self.project_id = project_id
        self.rule_id = rule_id
        self.old_secret_id = old_secret_id
        self.new_secret_id = new_secret_id
        self.not_before = parse_timestamp(not_before)
        self.not_after = parse_timestamp(not_after)
        if self.not_after <= self.not_before:
            raise InvalidLinkageMaterialError(
                "not_after must be later than not_before for record {}".format(
                    record_id or "?",
                ),
            )
        self.filename = filename
        self.attestation = attestation

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LinkageRecord":
        missing = _RECORD_FIELDS - set(data.keys())
        if missing:
            raise InvalidLinkageMaterialError(
                "linkage record is missing fields: {}".format(
                    ", ".join(sorted(missing)),
                ),
            )
        return cls(
            record_id=str(data["record_id"]),
            project_id=str(data["project_id"]),
            rule_id=str(data["rule_id"]),
            old_secret_id=str(data["old_secret_id"]),
            new_secret_id=str(data["new_secret_id"]),
            not_before=str(data["not_before"]),
            not_after=str(data["not_after"]),
            filename=str(data.get("filename", "")),
            attestation=str(data.get("attestation", "")),
        )

    def is_active_at(self, moment: datetime) -> bool:
        return self.not_before <= moment <= self.not_after

    def json(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "record_id": self.record_id,
            "project_id": self.project_id,
            "rule_id": self.rule_id,
            "old_secret_id": self.old_secret_id,
            "new_secret_id": self.new_secret_id,
            "not_before": self.not_before.isoformat().replace("+00:00", "Z"),
            "not_after": self.not_after.isoformat().replace("+00:00", "Z"),
        }
        if self.filename:
            output["filename"] = self.filename
        if self.attestation:
            output["attestation"] = self.attestation
        return output
