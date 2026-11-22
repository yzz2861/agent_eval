"""Claim-and-confirm interface layered on top of TUF-trusted artifacts.

A repair station hands artifacts to edge devices via offline media. This
package lets the station seal claim tickets from already-trusted TUF
metadata, lets devices re-claim the same delivery idempotently, records
explicit conflicts on version changes or deprecation, and accepts
(possibly next-day) installation receipts. A remote metadata refresh
never mutates an already-sealed ticket.
"""

from edge_delivery.models import (
    ClaimTicket,
    ConflictKind,
    ConflictRecord,
    DeliveryReport,
    Receipt,
    TicketStatus,
)
from edge_delivery.service import (
    ClaimService,
    DeliveryDeprecatedError,
    ReceiptMismatchError,
)

__all__ = [
    "ClaimService",
    "ClaimTicket",
    "ConflictKind",
    "ConflictRecord",
    "DeliveryDeprecatedError",
    "DeliveryReport",
    "Receipt",
    "ReceiptMismatchError",
    "TicketStatus",
]
