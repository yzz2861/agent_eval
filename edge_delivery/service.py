"""Station-side claim-and-confirm service.

The service sits on top of a TUF ``Updater``: at claim time it reads the
already-trusted target metadata and seals an immutable
``ClaimTicket``. Sealed tickets are never changed by later remote
refreshes, version bumps or deprecations; those events only produce new
tickets and explicit ``ConflictRecord`` entries.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from edge_delivery.models import (
    ClaimTicket,
    ConflictKind,
    ConflictRecord,
    DeliveryReport,
    Receipt,
    TicketStatus,
    new_claim_id,
    new_conflict_id,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from tuf.api.metadata import TargetFile
    from tuf.ngclient import Updater


class DeliveryDeprecatedError(Exception):
    """The requested delivery is no longer present in trusted metadata."""


class ReceiptMismatchError(Exception):
    """The receipt does not match any ticket sealed for this device."""


class ClaimService:
    """Claim-and-confirm interface over TUF-trusted artifacts.

    Args:
        updater_factory: Callable returning a fresh ``Updater`` bound to
            the station metadata/target directories. A new instance is
            required per remote refresh because ``Updater.refresh()``
            may only be called once per instance.
    """

    def __init__(self, updater_factory: Callable[[], Updater]):
        self._updater_factory = updater_factory
        self._updater: Updater | None = None
        self._tickets: dict[str, ClaimTicket] = {}
        self._conflicts: list[ConflictRecord] = []
        self._receipts: list[Receipt] = []

    def refresh_remote(self) -> None:
        """Refresh trusted metadata from the remote repository.

        This only replaces the trust view used for future claims. Every
        previously sealed ticket is left untouched: a refresh can never
        change an already-sealed claimable result.
        """
        self._updater = self._updater_factory()
        self._updater.refresh()

    def claim(self, device_id: str, target_path: str) -> ClaimTicket:
        """Seal a claim ticket for a device on the current trust view.

        Re-claiming an unchanged delivery is idempotent and returns the
        original ticket. If the trusted artifact changed since the
        device's previous claim, a ``VERSION_CHANGED`` conflict is
        recorded and a new ticket is sealed. If the delivery was removed
        from trusted metadata, a ``DELIVERY_DEPRECATED`` conflict is
        recorded and ``DeliveryDeprecatedError`` is raised.
        """
        info = self._targetinfo(target_path)
        existing = self._active_ticket(device_id, target_path)

        if info is None:
            self._record_conflict(
                ConflictKind.DELIVERY_DEPRECATED,
                device_id,
                target_path,
                "delivery is no longer present in trusted metadata",
                sealed_hashes=existing.hashes if existing else None,
                observed_hashes=None,
            )
            raise DeliveryDeprecatedError(
                f"{target_path!r} is deprecated: not in trusted metadata"
            )

        if existing is not None and existing.hashes == info.hashes:
            return existing

        if existing is not None:
            self._record_conflict(
                ConflictKind.VERSION_CHANGED,
                device_id,
                target_path,
                "trusted artifact changed since the previous claim",
                sealed_hashes=existing.hashes,
                observed_hashes=dict(info.hashes),
            )
            self._store(existing.with_status(TicketStatus.SUPERSEDED))

        ticket = ClaimTicket(
            claim_id=new_claim_id(),
            device_id=device_id,
            target_path=target_path,
            hashes=dict(info.hashes),
            length=info.length,
            custom=dict(info.custom) if info.custom else {},
            sealed_at=datetime.now(UTC),
        )
        self._store(ticket)
        return ticket

    def confirm(
        self,
        device_id: str,
        target_path: str,
        installed_hashes: dict[str, str],
        received_at: datetime | None = None,
    ) -> ClaimTicket:
        """Confirm a (possibly late) installation receipt from a device.

        The receipt is accepted only if it matches a ticket previously
        sealed for this device and delivery; the matching ticket becomes
        ``CONFIRMED``. Otherwise a ``RECEIPT_MISMATCH`` conflict is
        recorded and ``ReceiptMismatchError`` is raised.
        """
        receipt = Receipt(
            device_id=device_id,
            target_path=target_path,
            installed_hashes=dict(installed_hashes),
            received_at=received_at or datetime.now(UTC),
        )
        for ticket in self._device_tickets(device_id, target_path):
            if ticket.hashes == receipt.installed_hashes:
                confirmed = ticket.with_status(TicketStatus.CONFIRMED)
                self._store(confirmed)
                self._receipts.append(receipt)
                return confirmed

        self._record_conflict(
            ConflictKind.RECEIPT_MISMATCH,
            device_id,
            target_path,
            "receipt does not match any ticket sealed for this device",
            sealed_hashes=None,
            observed_hashes=dict(installed_hashes),
        )
        raise ReceiptMismatchError(
            f"receipt for {target_path!r} from {device_id!r} matches no "
            "sealed ticket"
        )

    def get_ticket(self, claim_id: str) -> ClaimTicket | None:
        """Return the stored ticket for a claim id, if any."""
        return self._tickets.get(claim_id)

    def report(self) -> DeliveryReport:
        """Summarize claims, actual installations and conflicts.

        Only tickets with a matching device receipt are reported as
        confirmed, i.e. artifacts actually installed on a device.
        """
        tickets = sorted(
            self._tickets.values(), key=lambda t: (t.sealed_at, t.claim_id)
        )
        return DeliveryReport(
            confirmed=tuple(
                t for t in tickets if t.status is TicketStatus.CONFIRMED
            ),
            pending=tuple(
                t for t in tickets if t.status is TicketStatus.SEALED
            ),
            conflicts=tuple(self._conflicts),
        )

    def _targetinfo(self, target_path: str) -> TargetFile | None:
        if self._updater is None:
            self._updater = self._updater_factory()
        return self._updater.get_targetinfo(target_path)

    def _store(self, ticket: ClaimTicket) -> None:
        self._tickets[ticket.claim_id] = ticket

    def _device_tickets(
        self, device_id: str, target_path: str
    ) -> list[ClaimTicket]:
        return [
            t
            for t in self._tickets.values()
            if t.device_id == device_id and t.target_path == target_path
        ]

    def _active_ticket(
        self, device_id: str, target_path: str
    ) -> ClaimTicket | None:
        active = [
            t
            for t in self._device_tickets(device_id, target_path)
            if t.status is not TicketStatus.SUPERSEDED
        ]
        if not active:
            return None
        return max(active, key=lambda t: (t.sealed_at, t.claim_id))

    def _record_conflict(
        self,
        kind: ConflictKind,
        device_id: str,
        target_path: str,
        detail: str,
        sealed_hashes: dict[str, str] | None,
        observed_hashes: dict[str, str] | None,
    ) -> None:
        self._conflicts.append(
            ConflictRecord(
                conflict_id=new_conflict_id(),
                kind=kind,
                device_id=device_id,
                target_path=target_path,
                detail=detail,
                sealed_hashes=sealed_hashes,
                observed_hashes=observed_hashes,
            )
        )
