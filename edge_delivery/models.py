"""Immutable records for the claim-and-confirm interface.

All records are frozen dataclasses: once a claim ticket is sealed it is
never mutated in place. Status changes (superseded, confirmed) are
expressed by replacing the stored ticket with a modified copy, so a
ticket handed to a device on offline media stays byte-identical forever.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return uuid.uuid4().hex


class TicketStatus(StrEnum):
    """Lifecycle of a claim ticket."""

    SEALED = "sealed"
    SUPERSEDED = "superseded"
    CONFIRMED = "confirmed"


class ConflictKind(StrEnum):
    """Explicit conflict categories recorded by the station."""

    VERSION_CHANGED = "version_changed"
    DELIVERY_DEPRECATED = "delivery_deprecated"
    RECEIPT_MISMATCH = "receipt_mismatch"


@dataclass(frozen=True)
class ClaimTicket:
    """A sealed, claimable snapshot of one delivery for one device.

    The payload is captured from trusted TUF metadata at claim time and
    is immutable: later remote refreshes cannot change what a device was
    told it may install.
    """

    claim_id: str
    device_id: str
    target_path: str
    hashes: dict[str, str]
    length: int
    custom: dict
    sealed_at: datetime
    status: TicketStatus = TicketStatus.SEALED

    def with_status(self, status: TicketStatus) -> ClaimTicket:
        """Return a copy of this ticket with a new lifecycle status."""
        return replace(self, status=status)


@dataclass(frozen=True)
class Receipt:
    """A device report of what it actually installed."""

    device_id: str
    target_path: str
    installed_hashes: dict[str, str]
    received_at: datetime = field(default_factory=_utcnow)


@dataclass(frozen=True)
class ConflictRecord:
    """An explicit record of a version change, deprecation or mismatch."""

    conflict_id: str
    kind: ConflictKind
    device_id: str
    target_path: str
    detail: str
    sealed_hashes: dict[str, str] | None
    observed_hashes: dict[str, str] | None
    recorded_at: datetime = field(default_factory=_utcnow)


@dataclass(frozen=True)
class DeliveryReport:
    """Station-side summary of claims, confirmations and conflicts.

    ``confirmed`` contains only tickets whose receipt matches the sealed
    payload, i.e. artifacts that were actually installed on a device.
    """

    confirmed: tuple[ClaimTicket, ...]
    pending: tuple[ClaimTicket, ...]
    conflicts: tuple[ConflictRecord, ...]
    generated_at: datetime = field(default_factory=_utcnow)


def new_claim_id() -> str:
    """Return a fresh unique claim identifier."""
    return _new_id()


def new_conflict_id() -> str:
    """Return a fresh unique conflict identifier."""
    return _new_id()
