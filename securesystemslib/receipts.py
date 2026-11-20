"""Offline reconciliation of release approvals and signed receipts.

Emergency releases are often approved and acknowledged out of band: an
approval form is handed over separately from the signed receipts that prove
which approval seats accepted it.  This module keeps that workflow offline and
uses :mod:`securesystemslib` signature verification for every approval and
receipt.

The important matching rule is that an approval can list several purposes for
one artifact, but it can only be consumed by one independent approval seat.
Receipts are therefore not accepted greedily: all seats are reconciled with a
bipartite maximum matching, so an approval already needed by one seat is never
silently reused for another.

Example::

    verifier = OfflineReceiptVerifier(
        requirements=[
            SeatRequirement("release", "release_manager", {"deploy"}, artifact),
            SeatRequirement("security", "security", {"deploy"}, artifact),
        ],
        approval_keys={"approval-key-id": approval_key},
        receipt_keys={
            "release_manager": {"release-key-id": release_key},
            "security": {"security-key-id": security_key},
        },
    )
    verifier.add_approvals(approvals)
    verifier.add_receipts(receipts)
    result = verifier.reconcile(as_of=now)
    if not result.ok:
        print(result.summary())
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from securesystemslib.exceptions import FormatError, UnverifiedSignatureError
from securesystemslib.signer import Key, Signature, Signer

APPROVAL_SCHEMA = "securesystemslib.approval/v1"
RECEIPT_SCHEMA = "securesystemslib.receipt/v1"


class ReceiptError(FormatError):
    """Base error for malformed approval or receipt evidence."""


def _utc(value: datetime | str) -> datetime:
    """Return an aware datetime in UTC.

    Strings must contain a timezone.  Accepting naive timestamps would make
    validity checks depend on the machine running the offline verifier.
    """

    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e:
            raise ReceiptError(f"invalid timestamp {value!r}") from e

    if not isinstance(value, datetime):
        raise TypeError("timestamp must be a datetime or ISO 8601 string")

    if value.tzinfo is None or value.utcoffset() is None:
        raise ReceiptError("timestamps must include a timezone")

    return value.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    """Serialize a datetime as a stable UTC ISO 8601 string."""

    return _utc(value).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    """Encode a value as deterministic JSON for signing and comparison."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _signature_from_dict(data: Mapping[str, Any]) -> Signature:
    try:
        return Signature.from_dict(dict(data))
    except (KeyError, TypeError, ValueError) as e:
        raise ReceiptError("invalid signature entry") from e


def _signatures_from_dict(data: Any) -> list[Signature]:
    if data is None:
        return []

    if not isinstance(data, list):
        raise ReceiptError("'signatures' must be a list")

    signatures = []
    for item in data:
        if not isinstance(item, Mapping):
            raise ReceiptError("signature entries must be objects")
        signatures.append(_signature_from_dict(item))

    return signatures


def _merge_signatures(
    existing: Sequence[Signature], incoming: Sequence[Signature]
) -> list[Signature]:
    """Merge signatures without treating a harmless re-sign as new evidence."""

    merged = list(existing)
    seen = set(existing)
    for signature in incoming:
        if signature not in seen:
            stored = copy.deepcopy(signature)
            merged.append(stored)
            seen.add(stored)

    return merged


@dataclass(frozen=True)
class Artifact:
    """An artifact name and its canonical digest.

    The digest is an opaque, already-formatted value such as
    ``sha256:0123...``.  Approvals and receipts must carry exactly the same
    value; the verifier never guesses that two artifact descriptions
    "probably" refer to the same release.
    """

    name: str
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ReceiptError("artifact name must be a non-empty string")
        if not isinstance(self.digest, str) or not self.digest.strip():
            raise ReceiptError("artifact digest must be a non-empty string")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Artifact:
        try:
            return cls(data["name"], data["digest"])
        except (KeyError, TypeError) as e:
            raise ReceiptError("artifact requires 'name' and 'digest'") from e

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "digest": self.digest}


@dataclass
class Approval:
    """A signed approval form for one artifact and one or more purposes.

    ``not_before`` and ``not_after`` are inclusive.  The signatures are not
    part of the signed payload; :meth:`payload` returns the exact bytes that a
    signer must sign.
    """

    approval_id: str
    artifact: Artifact
    purposes: frozenset[str]
    not_before: datetime
    not_after: datetime
    issuer: str = ""
    signatures: list[Signature] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.approval_id, str) or not self.approval_id.strip():
            raise ReceiptError("approval_id must be a non-empty string")
        if not isinstance(self.artifact, Artifact):
            raise ReceiptError("artifact must be an Artifact")
        if not isinstance(self.issuer, str):
            raise ReceiptError("issuer must be a string")

        purposes = _normalize_purposes(self.purposes)
        if not purposes:
            raise ReceiptError("an approval must allow at least one purpose")

        not_before = _utc(self.not_before)
        not_after = _utc(self.not_after)
        if not_before > not_after:
            raise ReceiptError("approval not_before must not be after not_after")

        self.purposes = purposes
        self.not_before = not_before
        self.not_after = not_after

    def body(self) -> dict[str, Any]:
        return {
            "schema": APPROVAL_SCHEMA,
            "approval_id": self.approval_id,
            "issuer": self.issuer,
            "artifact": self.artifact.to_dict(),
            "purposes": sorted(self.purposes),
            "not_before": _format_timestamp(self.not_before),
            "not_after": _format_timestamp(self.not_after),
        }

    def payload(self) -> bytes:
        """Return the canonical bytes covered by approval signatures."""

        return _canonical_bytes(self.body())

    def sign(self, signer: Signer) -> Signature:
        signature = signer.sign(self.payload())
        self.signatures = _merge_signatures(self.signatures, [signature])
        return signature

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Approval:
        if data.get("schema", APPROVAL_SCHEMA) != APPROVAL_SCHEMA:
            raise ReceiptError("unsupported approval schema")

        artifact = data.get("artifact")
        if not isinstance(artifact, Mapping):
            raise ReceiptError("approval artifact must be an object")

        try:
            return cls(
                approval_id=data["approval_id"],
                issuer=data.get("issuer", ""),
                artifact=Artifact.from_dict(artifact),
                purposes=_normalize_purposes(data["purposes"]),
                not_before=_utc(data["not_before"]),
                not_after=_utc(data["not_after"]),
                signatures=_signatures_from_dict(data.get("signatures")),
            )
        except (KeyError, TypeError) as e:
            raise ReceiptError("invalid approval") from e

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "signatures": [signature.to_dict() for signature in self.signatures],
        }


@dataclass
class Receipt:
    """A signed acknowledgement from one independent approval seat."""

    receipt_id: str
    approval_id: str
    seat: str
    signature_type: str
    purpose: str
    artifact: Artifact
    issued_at: datetime
    signatures: list[Signature] = field(default_factory=list)

    def __post_init__(self) -> None:
        for name, value in (
            ("receipt_id", self.receipt_id),
            ("approval_id", self.approval_id),
            ("seat", self.seat),
            ("signature_type", self.signature_type),
            ("purpose", self.purpose),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ReceiptError(f"{name} must be a non-empty string")

        if not isinstance(self.artifact, Artifact):
            raise ReceiptError("artifact must be an Artifact")

        self.issued_at = _utc(self.issued_at)

    def body(self) -> dict[str, Any]:
        return {
            "schema": RECEIPT_SCHEMA,
            "receipt_id": self.receipt_id,
            "approval_id": self.approval_id,
            "seat": self.seat,
            "signature_type": self.signature_type,
            "purpose": self.purpose,
            "artifact": self.artifact.to_dict(),
            "issued_at": _format_timestamp(self.issued_at),
        }

    def payload(self) -> bytes:
        """Return the canonical bytes covered by receipt signatures."""

        return _canonical_bytes(self.body())

    def sign(self, signer: Signer) -> Signature:
        signature = signer.sign(self.payload())
        self.signatures = _merge_signatures(self.signatures, [signature])
        return signature

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Receipt:
        if data.get("schema", RECEIPT_SCHEMA) != RECEIPT_SCHEMA:
            raise ReceiptError("unsupported receipt schema")

        artifact = data.get("artifact")
        if not isinstance(artifact, Mapping):
            raise ReceiptError("receipt artifact must be an object")

        try:
            return cls(
                receipt_id=data["receipt_id"],
                approval_id=data["approval_id"],
                seat=data["seat"],
                signature_type=data["signature_type"],
                purpose=data["purpose"],
                artifact=Artifact.from_dict(artifact),
                issued_at=_utc(data["issued_at"]),
                signatures=_signatures_from_dict(data.get("signatures")),
            )
        except (KeyError, TypeError) as e:
            raise ReceiptError("invalid receipt") from e

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "signatures": [signature.to_dict() for signature in self.signatures],
        }


@dataclass(frozen=True)
class SeatRequirement:
    """One independent approval seat that must produce evidence.

    If ``purposes`` is empty, any purpose allowed by the matched approval is
    sufficient.  If it is non-empty, every listed purpose must be supported by
    a receipt at this seat, all tied to the same approval.
    """

    seat: str
    signature_type: str
    purposes: frozenset[str] = frozenset()
    artifact: Artifact | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.seat, str) or not self.seat.strip():
            raise ReceiptError("seat must be a non-empty string")
        if not isinstance(self.signature_type, str) or not self.signature_type.strip():
            raise ReceiptError("signature_type must be a non-empty string")

        object.__setattr__(self, "purposes", _normalize_purposes(self.purposes))

        if self.artifact is not None and not isinstance(self.artifact, Artifact):
            raise ReceiptError("requirement artifact must be an Artifact")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SeatRequirement:
        artifact = data.get("artifact")
        if artifact is not None and not isinstance(artifact, Mapping):
            raise ReceiptError("requirement artifact must be an object")

        try:
            return cls(
                seat=data["seat"],
                signature_type=data["signature_type"],
                purposes=_normalize_purposes(data.get("purposes", ())),
                artifact=Artifact.from_dict(artifact)
                if isinstance(artifact, Mapping)
                else None,
            )
        except (KeyError, TypeError) as e:
            raise ReceiptError("invalid seat requirement") from e

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "seat": self.seat,
            "signature_type": self.signature_type,
            "purposes": sorted(self.purposes),
        }
        if self.artifact is not None:
            result["artifact"] = self.artifact.to_dict()

        return result


@dataclass(frozen=True)
class SeatMatch:
    """Successful evidence assignment for one seat."""

    seat: str
    signature_type: str
    approval_id: str
    receipt_ids: tuple[str, ...]
    purposes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "seat": self.seat,
            "signature_type": self.signature_type,
            "approval_id": self.approval_id,
            "receipt_ids": list(self.receipt_ids),
            "purposes": list(self.purposes),
        }


@dataclass(frozen=True)
class MissingSignature:
    """Why a required signature type could not be matched."""

    seat: str
    signature_type: str
    purposes: tuple[str, ...]
    reason: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seat": self.seat,
            "signature_type": self.signature_type,
            "purposes": list(self.purposes),
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RejectedEvidence:
    """An approval or receipt that failed individual validation."""

    kind: str
    evidence_id: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "id": self.evidence_id,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class EvidenceConflict:
    """Conflicting bodies submitted under the same evidence identity."""

    kind: str
    evidence_id: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "id": self.evidence_id,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ReconciliationResult:
    """Structured outcome of an offline reconciliation."""

    as_of: datetime
    matches: tuple[SeatMatch, ...]
    missing: tuple[MissingSignature, ...]
    rejected_approvals: tuple[RejectedEvidence, ...]
    rejected_receipts: tuple[RejectedEvidence, ...]
    conflicts: tuple[EvidenceConflict, ...]
    manual_receipt_ids: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.missing

    @property
    def missing_signature_types(self) -> tuple[str, ...]:
        return tuple(sorted({item.signature_type for item in self.missing}))

    def summary(self) -> str:
        """Return a concise reviewer-facing explanation."""

        if self.ok:
            return (
                f"PASS: all {len(self.matches)} approval seat(s) matched "
                f"at {_format_timestamp(self.as_of)}"
            )

        missing_types = ", ".join(self.missing_signature_types) or "unknown"
        lines = [
            (
                f"FAIL: missing signature type(s): {missing_types}; "
                f"matched {len(self.matches)} seat(s)"
            )
        ]
        for item in self.missing:
            purposes = ",".join(item.purposes) or "any"
            lines.append(
                f"- seat {item.seat!r} ({item.signature_type}, "
                f"purpose={purposes}): {item.detail} "
                f"[{item.reason}]"
            )

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "as_of": _format_timestamp(self.as_of),
            "matches": [match.to_dict() for match in self.matches],
            "missing": [item.to_dict() for item in self.missing],
            "missing_signature_types": list(self.missing_signature_types),
            "rejected_approvals": [item.to_dict() for item in self.rejected_approvals],
            "rejected_receipts": [item.to_dict() for item in self.rejected_receipts],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "manual_receipt_ids": list(self.manual_receipt_ids),
        }


class OfflineReceiptVerifier:
    """Reconcile signed approvals and receipts without network access.

    Args:
        requirements: Independent approval seats that must be satisfied.
        approval_keys: Trusted public keys for approval forms, keyed by keyid.
            An approval is accepted when at least one signature verifies with
            one of these keys.
        receipt_keys: Trusted public keys per signature type.  A receipt's
            ``signature_type`` selects the allowed key set.
        require_approval_signatures: When true (the default), unsigned
            approval forms are rejected.  Disable only when the caller has
            authenticated approvals through another offline channel.
    """

    def __init__(
        self,
        requirements: Iterable[SeatRequirement] = (),
        *,
        approval_keys: Mapping[str, Key] | None = None,
        receipt_keys: Mapping[str, Mapping[str, Key]] | None = None,
        require_approval_signatures: bool = True,
    ):
        self.requirements = tuple(requirements)
        self.approval_keys = dict(approval_keys or {})
        self.receipt_keys = {
            signature_type: dict(keys)
            for signature_type, keys in (receipt_keys or {}).items()
        }
        self.require_approval_signatures = require_approval_signatures

        seats = [requirement.seat for requirement in self.requirements]
        if len(seats) != len(set(seats)):
            raise ReceiptError("seat requirements must have unique seat names")

        self._approvals: dict[str, Approval] = {}
        self._receipts: dict[str, Receipt] = {}
        self._conflicts: dict[tuple[str, str], EvidenceConflict] = {}
        self._manual_receipt_ids: set[str] = set()

    def add_approvals(self, approvals: Iterable[Approval]) -> OfflineReceiptVerifier:
        """Add approval forms, merging idempotent retransmissions.

        A conflicting body under an existing ``approval_id`` invalidates that
        identity rather than silently keeping whichever copy arrived first.
        """

        for approval in approvals:
            key = ("approval", approval.approval_id)
            conflict = self._conflicts.get(key)
            if conflict is not None:
                continue

            existing = self._approvals.get(approval.approval_id)
            if existing is None:
                self._approvals[approval.approval_id] = copy.deepcopy(approval)
                continue

            if existing.payload() != approval.payload():
                self._approvals.pop(approval.approval_id, None)
                self._conflicts[key] = EvidenceConflict(
                    "approval",
                    approval.approval_id,
                    "the same approval_id was submitted with a different body",
                )
                continue

            existing.signatures = _merge_signatures(
                existing.signatures, approval.signatures
            )

        return self

    def add_receipts(
        self,
        receipts: Iterable[Receipt],
        *,
        manual: bool = False,
    ) -> OfflineReceiptVerifier:
        """Add receipts, keeping retransmissions under one evidence identity.

        ``manual=True`` marks receipts that arrived through a human
        supplement.  It does not bypass signature or validity checks; it only
        records the provenance in the result.
        """

        for receipt in receipts:
            key = ("receipt", receipt.receipt_id)
            conflict = self._conflicts.get(key)
            if conflict is not None:
                continue

            existing = self._receipts.get(receipt.receipt_id)
            if existing is None:
                self._receipts[receipt.receipt_id] = copy.deepcopy(receipt)
            elif existing.payload() != receipt.payload():
                self._receipts.pop(receipt.receipt_id, None)
                self._conflicts[key] = EvidenceConflict(
                    "receipt",
                    receipt.receipt_id,
                    "the same receipt_id was submitted with a different body",
                )
                continue
            else:
                existing.signatures = _merge_signatures(
                    existing.signatures, receipt.signatures
                )

            if manual:
                self._manual_receipt_ids.add(receipt.receipt_id)

        return self

    def add_manual_receipts(
        self, receipts: Iterable[Receipt]
    ) -> OfflineReceiptVerifier:
        """Convenience wrapper for late, human-supplied evidence."""

        return self.add_receipts(receipts, manual=True)

    def reconcile(self, as_of: datetime | str | None = None) -> ReconciliationResult:
        """Verify and globally match all collected evidence.

        The default ``as_of`` is the current UTC time.  The verifier requires
        approvals to be valid at that instant and receipts to have been issued
        while the approval was valid and no later than ``as_of``.
        """

        if as_of is None:
            as_of = datetime.now(UTC)
        else:
            as_of = _utc(as_of)

        valid_approvals, rejected_approvals = self._validate_approvals(as_of)
        valid_receipts, rejected_receipts = self._validate_receipts(as_of)

        candidates, pair_receipts = self._build_candidates(
            valid_approvals, valid_receipts
        )
        assignment = _maximum_matching(
            [requirement.seat for requirement in self.requirements],
            candidates,
        )

        matches = []
        for requirement in sorted(self.requirements, key=lambda item: item.seat):
            approval_id = assignment.get(requirement.seat)
            if approval_id is None:
                continue

            selected = _select_receipts(
                requirement,
                pair_receipts[(requirement.seat, approval_id)],
            )
            matches.append(
                SeatMatch(
                    seat=requirement.seat,
                    signature_type=requirement.signature_type,
                    approval_id=approval_id,
                    receipt_ids=tuple(receipt.receipt_id for receipt in selected),
                    purposes=tuple(sorted({receipt.purpose for receipt in selected})),
                )
            )

        missing = tuple(
            self._explain_missing(
                requirement,
                assignment,
                candidates,
                valid_approvals,
                rejected_approvals,
                valid_receipts,
                rejected_receipts,
            )
            for requirement in sorted(self.requirements, key=lambda item: item.seat)
            if requirement.seat not in assignment
        )

        return ReconciliationResult(
            as_of=as_of,
            matches=tuple(matches),
            missing=missing,
            rejected_approvals=tuple(rejected_approvals),
            rejected_receipts=tuple(rejected_receipts),
            conflicts=tuple(self._conflicts[key] for key in sorted(self._conflicts)),
            manual_receipt_ids=tuple(sorted(self._manual_receipt_ids)),
        )

    def _validate_approvals(
        self, as_of: datetime
    ) -> tuple[dict[str, Approval], list[RejectedEvidence]]:
        valid = {}
        rejected = []

        for approval_id in sorted(self._approvals):
            approval = self._approvals[approval_id]
            reasons = []

            if as_of < approval.not_before:
                reasons.append("approval_not_yet_valid")
            if as_of > approval.not_after:
                reasons.append("approval_expired")

            if self.require_approval_signatures:
                if not self.approval_keys:
                    reasons.append("no_trusted_approval_keys")
                elif not _verify_any_signature(
                    approval.signatures,
                    approval.payload(),
                    self.approval_keys,
                ):
                    reasons.append("untrusted_or_invalid_approval_signature")

            if reasons:
                rejected.append(
                    RejectedEvidence("approval", approval_id, tuple(reasons))
                )
            else:
                valid[approval_id] = approval

        return valid, rejected

    def _validate_receipts(
        self, as_of: datetime
    ) -> tuple[dict[str, Receipt], list[RejectedEvidence]]:
        valid = {}
        rejected = []

        for receipt_id in sorted(self._receipts):
            receipt = self._receipts[receipt_id]
            reasons = []

            trusted_keys = self.receipt_keys.get(receipt.signature_type, {})
            if not trusted_keys:
                reasons.append("no_trusted_keys_for_signature_type")
            elif not _verify_any_signature(
                receipt.signatures,
                receipt.payload(),
                trusted_keys,
            ):
                reasons.append("untrusted_or_invalid_receipt_signature")

            if receipt.issued_at > as_of:
                reasons.append("receipt_issued_in_future")

            if reasons:
                rejected.append(RejectedEvidence("receipt", receipt_id, tuple(reasons)))
            else:
                valid[receipt_id] = receipt

        return valid, rejected

    def _build_candidates(
        self,
        valid_approvals: Mapping[str, Approval],
        valid_receipts: Mapping[str, Receipt],
    ) -> tuple[dict[str, set[str]], dict[tuple[str, str], list[Receipt]]]:
        candidates: dict[str, set[str]] = {
            requirement.seat: set() for requirement in self.requirements
        }
        pair_receipts: dict[tuple[str, str], list[Receipt]] = {}

        for requirement in self.requirements:
            for approval_id in sorted(valid_approvals):
                approval = valid_approvals[approval_id]
                if (
                    requirement.artifact is not None
                    and approval.artifact != requirement.artifact
                ):
                    continue

                usable = []
                for receipt in valid_receipts.values():
                    if (
                        receipt.seat != requirement.seat
                        or receipt.signature_type != requirement.signature_type
                        or receipt.approval_id != approval_id
                    ):
                        continue
                    if receipt.artifact != approval.artifact:
                        continue
                    if receipt.purpose not in approval.purposes:
                        continue
                    if not (
                        approval.not_before <= receipt.issued_at <= approval.not_after
                    ):
                        continue

                    usable.append(receipt)

                if not usable:
                    continue

                if requirement.purposes:
                    covered = {receipt.purpose for receipt in usable}
                    if not requirement.purposes <= covered:
                        continue

                candidates[requirement.seat].add(approval_id)
                pair_receipts[(requirement.seat, approval_id)] = sorted(
                    usable, key=lambda item: item.receipt_id
                )

        return candidates, pair_receipts

    def _explain_missing(  # noqa: PLR0913
        self,
        requirement: SeatRequirement,
        assignment: Mapping[str, str],
        candidates: Mapping[str, set[str]],
        valid_approvals: Mapping[str, Approval],
        rejected_approvals: Sequence[RejectedEvidence],
        valid_receipts: Mapping[str, Receipt],
        rejected_receipts: Sequence[RejectedEvidence],
    ) -> MissingSignature:
        purposes = tuple(sorted(requirement.purposes))
        seat_receipts = [
            receipt
            for receipt in self._receipts.values()
            if receipt.seat == requirement.seat
            and receipt.signature_type == requirement.signature_type
        ]

        if not seat_receipts:
            return MissingSignature(
                seat=requirement.seat,
                signature_type=requirement.signature_type,
                purposes=purposes,
                reason="missing_signature",
                detail=(
                    f"no receipt was submitted for signature type "
                    f"{requirement.signature_type!r}"
                ),
            )

        valid_ids = {
            receipt.receipt_id
            for receipt in seat_receipts
            if receipt.receipt_id in valid_receipts
        }
        if not valid_ids:
            rejection_details = {
                item.evidence_id: item.reasons
                for item in rejected_receipts
                if item.evidence_id in {receipt.receipt_id for receipt in seat_receipts}
            }
            details = "; ".join(
                f"{receipt_id}: {', '.join(reasons)}"
                for receipt_id, reasons in sorted(rejection_details.items())
            )
            return MissingSignature(
                seat=requirement.seat,
                signature_type=requirement.signature_type,
                purposes=purposes,
                reason="invalid_receipt",
                detail=(
                    "submitted receipts did not verify"
                    + (f" ({details})" if details else "")
                ),
            )

        candidate_approvals = candidates.get(requirement.seat, set())
        if candidate_approvals:
            used_by = {
                approval_id: seat
                for seat, approval_id in assignment.items()
                if approval_id in candidate_approvals and seat != requirement.seat
            }
            if used_by:
                details = ", ".join(
                    f"{approval_id} already used by seat {seat!r}"
                    for approval_id, seat in sorted(used_by.items())
                )
                return MissingSignature(
                    seat=requirement.seat,
                    signature_type=requirement.signature_type,
                    purposes=purposes,
                    reason="approval_already_used",
                    detail=(
                        "valid receipts exist, but their approvals are consumed "
                        f"by other independent seats ({details})"
                    ),
                )

        valid_seat_receipts = [
            receipt for receipt in seat_receipts if receipt.receipt_id in valid_ids
        ]
        reason, detail = self._diagnose_unmatched_receipts(
            requirement,
            valid_seat_receipts,
            valid_approvals,
            rejected_approvals,
        )
        return MissingSignature(
            seat=requirement.seat,
            signature_type=requirement.signature_type,
            purposes=purposes,
            reason=reason,
            detail=detail,
        )

    def _diagnose_unmatched_receipts(
        self,
        requirement: SeatRequirement,
        seat_receipts: Sequence[Receipt],
        valid_approvals: Mapping[str, Approval],
        rejected_approvals: Sequence[RejectedEvidence],
    ) -> tuple[str, str]:
        rejection_by_id = {
            item.evidence_id: item.reasons for item in rejected_approvals
        }
        observed: dict[str, list[str]] = {}

        for receipt in seat_receipts:
            approval = valid_approvals.get(receipt.approval_id)
            if approval is None:
                conflicts = self._conflicts.get(("approval", receipt.approval_id))
                if conflicts is not None:
                    observed.setdefault("invalid_approval", []).append(
                        f"approval {receipt.approval_id!r} has conflicting bodies"
                    )
                elif receipt.approval_id in rejection_by_id:
                    reasons = ", ".join(rejection_by_id[receipt.approval_id])
                    observed.setdefault("invalid_approval", []).append(
                        f"approval {receipt.approval_id!r}: {reasons}"
                    )
                else:
                    observed.setdefault("unknown_approval", []).append(
                        f"approval {receipt.approval_id!r} was not submitted"
                    )
                continue

            if (
                requirement.artifact is not None
                and approval.artifact != requirement.artifact
            ):
                observed.setdefault("artifact_mismatch", []).append(
                    f"approval {approval.approval_id!r} covers a different artifact"
                )
                continue

            if receipt.artifact != approval.artifact:
                observed.setdefault("artifact_mismatch", []).append(
                    f"receipt {receipt.receipt_id!r} covers a different artifact"
                )
                continue

            if receipt.purpose not in approval.purposes:
                observed.setdefault("purpose_not_allowed", []).append(
                    f"purpose {receipt.purpose!r} is not allowed by approval "
                    f"{approval.approval_id!r}"
                )
                continue

            if not (approval.not_before <= receipt.issued_at <= approval.not_after):
                observed.setdefault("outside_validity", []).append(
                    f"receipt {receipt.receipt_id!r} was issued outside the "
                    f"approval validity window"
                )
                continue

            observed.setdefault("insufficient_purpose_evidence", []).append(
                f"approval {approval.approval_id!r} does not have a receipt for "
                "every required purpose"
            )

        if not observed:
            return (
                "no_match",
                "no approval can satisfy this seat under the global matching rules",
            )

        priority = (
            "unknown_approval",
            "invalid_approval",
            "artifact_mismatch",
            "purpose_not_allowed",
            "outside_validity",
            "insufficient_purpose_evidence",
        )
        reason = next(item for item in priority if item in observed)
        return reason, "; ".join(observed[reason])


def _normalize_purposes(value: Iterable[str] | str) -> frozenset[str]:
    """Normalize a single purpose or an iterable of purposes."""

    if isinstance(value, str):
        values: Iterable[Any] = (value,)
    else:
        values = value

    purposes = set()
    for purpose in values:
        if not isinstance(purpose, str) or not purpose.strip():
            raise ReceiptError("purposes must be non-empty strings")
        purposes.add(purpose)

    return frozenset(purposes)


def _verify_any_signature(
    signatures: Sequence[Signature],
    payload: bytes,
    trusted_keys: Mapping[str, Key],
) -> bool:
    """Return true when any signature verifies with a trusted key."""

    for signature in signatures:
        key = trusted_keys.get(signature.keyid)
        if key is None:
            continue
        try:
            key.verify_signature(signature, payload)
        except (UnverifiedSignatureError, TypeError, ValueError):
            continue

        return True

    return False


def _maximum_matching(
    seats: Sequence[str],
    candidates: Mapping[str, set[str]],
) -> dict[str, str]:
    """Return a maximum bipartite seat-to-approval matching.

    Approvals are the right-hand resource and may be consumed only once.  A
    greedy walk is not sufficient: a seat with two options may need to yield
    its first choice so that a constrained seat can still be matched.
    """

    approval_to_seat: dict[str, str] = {}

    def augment(seat: str, seen: set[str]) -> bool:
        for approval_id in sorted(candidates.get(seat, ())):
            if approval_id in seen:
                continue

            seen.add(approval_id)
            current = approval_to_seat.get(approval_id)
            if current is None or augment(current, seen):
                approval_to_seat[approval_id] = seat
                return True

        return False

    for seat in sorted(seats):
        augment(seat, set())

    return {seat: approval_id for approval_id, seat in approval_to_seat.items()}


def _select_receipts(
    requirement: SeatRequirement,
    usable: Sequence[Receipt],
) -> list[Receipt]:
    """Pick one deterministic receipt for each required purpose."""

    if not requirement.purposes:
        return [usable[0]]

    selected = []
    for purpose in sorted(requirement.purposes):
        selected.append(
            next(receipt for receipt in usable if receipt.purpose == purpose)
        )

    return selected


def _load_trusted_keys(data: Mapping[str, Any]) -> dict[str, Key]:
    keys = {}
    for keyid, key_dict in data.items():
        if not isinstance(key_dict, Mapping):
            raise ReceiptError(f"trusted key {keyid!r} must be an object")
        keys[keyid] = Key.from_dict(keyid, dict(key_dict))

    return keys


def _mapping_items(value: Any, name: str) -> list[Mapping[str, Any]]:
    """Return a validated list of JSON objects from a bundle field."""

    if not isinstance(value, list):
        raise ReceiptError(f"'{name}' must be a list")

    items = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ReceiptError(f"'{name}[{index}]' must be an object")
        items.append(item)

    return items


def verifier_from_dict(data: Mapping[str, Any]) -> OfflineReceiptVerifier:
    """Build a verifier from the JSON bundle accepted by the CLI."""

    trusted_keys = data.get("trusted_keys", {})
    if not isinstance(trusted_keys, Mapping):
        raise ReceiptError("'trusted_keys' must be an object")

    approval_keys_data = trusted_keys.get("approval", {})
    receipt_keys_data = trusted_keys.get("receipt", {})
    if not isinstance(approval_keys_data, Mapping) or not isinstance(
        receipt_keys_data, Mapping
    ):
        raise ReceiptError(
            "'trusted_keys.approval' and 'trusted_keys.receipt' must be objects"
        )

    receipt_keys = {}
    for signature_type, keys in receipt_keys_data.items():
        if not isinstance(signature_type, str) or not isinstance(keys, Mapping):
            raise ReceiptError("trusted receipt keys must be keyed by signature type")
        receipt_keys[signature_type] = _load_trusted_keys(keys)

    requirements_data = _mapping_items(data.get("requirements", []), "requirements")
    approvals_data = _mapping_items(data.get("approvals", []), "approvals")
    receipts_data = _mapping_items(data.get("receipts", []), "receipts")
    manual_receipts_data = _mapping_items(
        data.get("manual_receipts", []), "manual_receipts"
    )

    verifier = OfflineReceiptVerifier(
        requirements=[SeatRequirement.from_dict(item) for item in requirements_data],
        approval_keys=_load_trusted_keys(approval_keys_data),
        receipt_keys=receipt_keys,
        require_approval_signatures=data.get("require_approval_signatures", True),
    )
    verifier.add_approvals(Approval.from_dict(item) for item in approvals_data)
    verifier.add_receipts(Receipt.from_dict(item) for item in receipts_data)
    verifier.add_manual_receipts(
        Receipt.from_dict(item) for item in manual_receipts_data
    )

    return verifier


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point for an offline JSON evidence bundle."""

    parser = argparse.ArgumentParser(
        prog="python -m securesystemslib.receipts",
        description="Verify and globally reconcile signed release receipts.",
    )
    parser.add_argument(
        "bundle",
        type=Path,
        help="JSON evidence bundle, or '-' to read from standard input",
    )
    parser.add_argument(
        "--as-of",
        help="UTC verification time (defaults to now)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the complete structured result as JSON",
    )
    args = parser.parse_args(argv)

    try:
        if str(args.bundle) == "-":
            data = json.load(sys.stdin)
        else:
            data = json.loads(args.bundle.read_text(encoding="utf-8"))

        if not isinstance(data, Mapping):
            raise ReceiptError("evidence bundle must be a JSON object")

        verifier = verifier_from_dict(data)
        as_of = args.as_of if args.as_of is not None else data.get("as_of")
        result = verifier.reconcile(as_of=as_of)
    except (KeyError, OSError, ValueError, ReceiptError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(result.summary())

    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
