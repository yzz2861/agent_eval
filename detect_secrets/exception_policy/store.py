# Append-only persistent store of exception decision records.
#
# The store keeps the full ordered history of decisions. Nothing is ever
# rewritten: revocations and re-approvals are new records that supersede older
# ones. Because the log is immutable and all time-based checks take an explicit
# snapshot, a historical report can be replayed against the same log and always
# produce the same verdict.
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence

from .identity import SecretIdentity
from .records import ExceptionRecord

STORE_VERSION = 1


@dataclass(frozen=True)
class Conflict:
    secret_identity: SecretIdentity
    decision_ids: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret_identity": self.secret_identity.to_dict(),
            "decision_ids": list(self.decision_ids),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Conflict":
        return cls(
            secret_identity=SecretIdentity.from_dict(data["secret_identity"]),
            decision_ids=list(data["decision_ids"]),
            reason=str(data["reason"]),
        )


class DuplicateDecisionError(ValueError):
    pass


class ExceptionStore:
    def __init__(self, records: Optional[Sequence[ExceptionRecord]] = None) -> None:
        self._records: List[ExceptionRecord] = list(records or [])
        self._seen = {record.decision_id for record in self._records}

    @property
    def records(self) -> List[ExceptionRecord]:
        # Return a copy so callers cannot mutate the append-only log.
        return list(self._records)

    def add(self, record: ExceptionRecord) -> None:
        if record.decision_id in self._seen:
            raise DuplicateDecisionError(
                f"decision_id already recorded: {record.decision_id}",
            )
        self._records.append(record)
        self._seen.add(record.decision_id)

    def for_identity(self, identity: SecretIdentity) -> List[ExceptionRecord]:
        return [
            record
            for record in self._records
            if record.secret_identity == identity
        ]

    def heads_for(self, identity: SecretIdentity) -> List[ExceptionRecord]:
        records = self.for_identity(identity)
        superseded: set[str] = set()
        for record in records:
            superseded.update(record.supersedes)
        return [record for record in records if record.decision_id not in superseded]

    def active_conflicts(self) -> List[Conflict]:
        conflicts: List[Conflict] = []
        identities = {record.secret_identity for record in self._records}
        for identity in identities:
            heads = self.heads_for(identity)
            approved = [head for head in heads if head.is_approved]
            if len(approved) > 1:
                conflicts.append(
                    Conflict(
                        secret_identity=identity,
                        decision_ids=sorted(
                            head.decision_id for head in approved
                        ),
                        reason=(
                            "multiple concurrent APPROVED decisions for the same "
                            "secret identity; manual resolution required"
                        ),
                    ),
                )
        return sorted(conflicts, key=lambda conflict: conflict.decision_ids)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": STORE_VERSION,
            "records": [record.to_dict() for record in self._records],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExceptionStore":
        version = int(data["version"])
        if version != STORE_VERSION:
            raise ValueError(f"unsupported exception store version: {version!r}")
        return cls(
            [ExceptionRecord.from_dict(item) for item in data.get("records", [])],
        )

    def write(self, path: Any) -> None:
        target = Path(path)
        target.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def read(cls, path: Any) -> "ExceptionStore":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def merge_stores(stores: Iterable[ExceptionStore]) -> ExceptionStore:
    # Union of records keyed by decision_id. Identical records shared by both
    # branches collapse to one; divergent decisions keep all heads so the
    # conflict surfaces instead of one branch silently winning.
    merged: Dict[str, ExceptionRecord] = {}
    for store in stores:
        for record in store.records:
            existing = merged.get(record.decision_id)
            if existing is not None and existing != record:
                raise DuplicateDecisionError(
                    f"conflicting payload for decision_id: {record.decision_id}",
                )
            merged[record.decision_id] = record
    return ExceptionStore(list(merged.values()))
