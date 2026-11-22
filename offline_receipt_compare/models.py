"""Data model for acceptance receipts, retained evidence and verdicts.

A receipt is the historical "repair acceptance" record: it pins a target
path, the content hashes/length that were accepted, when and under which
delegation path the conclusion was drawn. Evidence is the actual file content
still retained on disk. The comparator never treats a target without a
receipt as a risk: only receipt-bearing targets enter the audit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class VerdictCode:
    """Machine-readable outcome codes for a single receipt.

    Only :data:`REVERIFIABLE` means the historical conclusion still holds.
    Every other code describes why the receipt must be re-issued or why the
    retained evidence is insufficient.
    """

    #: Candidate metadata still resolves the target and evidence re-hashes.
    REVERIFIABLE = "reverifiable"
    #: No trusted delegation path resolves the target path any more.
    PATH_BROKEN = "path_broken"
    #: Path resolves, but the role metadata that carries it is gone.
    DELEGATED_ROLE_REMOVED = "delegated_role_removed"
    #: Path resolves, but candidate hashes/length differ from the receipt.
    CONTENT_DRIFTED = "content_drifted"
    #: Candidate metadata chain fails to verify against the candidate root.
    METADATA_UNTRUSTED = "metadata_untrusted"
    #: The receipt cannot be reproduced even against the historical metadata.
    NOT_HISTORICALLY_VALID = "not_historically_valid"
    #: No retained evidence bytes are available for the receipt.
    EVIDENCE_MISSING = "evidence_missing"
    #: Retained bytes do not match the hashes recorded in the receipt.
    EVIDENCE_MISMATCH = "evidence_mismatch"


#: Codes that mean a brand new receipt is required rather than an evidence fix.
REISSUE_CODES = frozenset(
    {
        VerdictCode.PATH_BROKEN,
        VerdictCode.DELEGATED_ROLE_REMOVED,
        VerdictCode.CONTENT_DRIFTED,
        VerdictCode.METADATA_UNTRUSTED,
        VerdictCode.NOT_HISTORICALLY_VALID,
    }
)


def _parse_iso8601(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, accepting a trailing ``Z``."""
    parsed = datetime.fromisoformat(value.removesuffix("Z"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


@dataclass(frozen=True)
class Receipt:
    """A single historical acceptance receipt.

    Attributes:
        receipt_id: Stable identifier of the acceptance record.
        target_path: TUF target path that the conclusion was drawn for.
        hashes: Accepted content hashes, keyed by algorithm name.
        length: Accepted content length in bytes.
        issued_at: When the receipt was issued (used as verification time).
        delegation_path: Roles walked when the receipt was issued, ordered
            from the top-level ``targets`` role down to the role carrying
            the target. Informational; re-verified rather than trusted.
        evidence_relpath: Location of retained evidence inside the evidence
            store, relative to the store root.
    """

    receipt_id: str
    target_path: str
    hashes: dict[str, str]
    length: int
    issued_at: datetime
    delegation_path: list[str]
    evidence_relpath: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Receipt:
        """Build a receipt from its on-disk JSON representation."""
        return cls(
            receipt_id=data["receipt_id"],
            target_path=data["target_path"],
            hashes=dict(data["hashes"]),
            length=int(data["length"]),
            issued_at=_parse_iso8601(data["issued_at"]),
            delegation_path=list(data.get("delegation_path", [])),
            evidence_relpath=data["evidence_relpath"],
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the receipt to its on-disk JSON representation."""
        return {
            "receipt_id": self.receipt_id,
            "target_path": self.target_path,
            "hashes": dict(self.hashes),
            "length": self.length,
            "issued_at": self.issued_at.astimezone(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "delegation_path": list(self.delegation_path),
            "evidence_relpath": self.evidence_relpath,
        }


@dataclass
class ReceiptSet:
    """Collection of receipts loaded from a directory of JSON files."""

    receipts: list[Receipt] = field(default_factory=list)

    @classmethod
    def load(cls, receipts_dir: str | Path) -> ReceiptSet:
        """Load every ``*.json`` receipt file from ``receipts_dir``."""
        root = Path(receipts_dir)
        receipts: list[Receipt] = []
        for path in sorted(root.glob("*.json")):
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            entries = payload if isinstance(payload, list) else [payload]
            for entry in entries:
                receipts.append(Receipt.from_dict(entry))
        return cls(receipts=receipts)


class EvidenceStore:
    """On-disk directory holding the actual retained acceptance evidence.

    Evidence is addressed by the receipt's ``evidence_relpath`` so that two
    receipts for the same target path can still point at distinct retained
    artifacts when needed.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def read(self, evidence_relpath: str) -> bytes | None:
        """Return evidence bytes, or ``None`` when it is not retained."""
        path = self.root / evidence_relpath
        if not path.is_file():
            return None
        return path.read_bytes()


@dataclass(frozen=True)
class Verdict:
    """Outcome of re-verifying one receipt against one metadata bundle."""

    receipt_id: str
    target_path: str
    code: str
    reverifiable: bool
    detail: str
    candidate_path: tuple[str, ...] = field(default_factory=tuple)
    historical_path: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the verdict for JSON reporting."""
        return {
            "receipt_id": self.receipt_id,
            "target_path": self.target_path,
            "code": self.code,
            "reverifiable": self.reverifiable,
            "detail": self.detail,
            "candidate_delegation_path": list(self.candidate_path),
            "historical_delegation_path": list(self.historical_path),
        }
