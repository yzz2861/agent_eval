"""Record types exchanged between the parser callbacks and the two sinks.

Three trust levels are modelled explicitly so a sink can never accidentally
persist data it is not allowed to hold:

* :class:`ConfirmedMetadata` - only produced once a part is fully parsed and
  accepted; safe for the business receipt, never for the customer-service log.
* :class:`PublicReference` - opaque, content-derived identifiers with no
  personal data; the only per-part information the support log may retain.
* :class:`RejectionInfo` - the minimum information required to explain why a
  part or request was refused: a stable reason code, a processing status and a
  byte count, with no field values or half-parsed fragments.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Prefix keeps references self-describing in log storage while staying opaque.
_REF_PREFIX = "up_"


class PartStatus(str, Enum):
    """Lifecycle status of a single multipart part.

    The enum value (not its name) is serialised so logs keep a stable,
    language-independent vocabulary.
    """

    RECEIVED = "received"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    FAILED = "failed"
    SKIPPED = "skipped"


class RejectReason(str, Enum):
    """Stable reason codes used in :class:`RejectionInfo`.

    Codes are deliberately coarse: they explain the processing decision without
    embedding request content, which could itself contain personal data.
    """

    EMPTY_NAME = "empty_name"
    UNKNOWN_CONTENT_TYPE = "unknown_content_type"
    AUDIT_CALLBACK_FAILED = "audit_callback_failed"
    MALFORMED_BODY = "malformed_body"
    TOO_LARGE = "too_large"
    INTERNAL_ERROR = "internal_error"


class RequestStatus(str, Enum):
    """Overall request processing status for the final summary."""

    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"


def new_request_ref() -> str:
    """Return a fresh, unguessable request reference (e.g. ``up_8f3a...``)."""
    return _REF_PREFIX + secrets.token_hex(16)


def new_part_ref() -> str:
    """Return a fresh, unguessable per-part reference."""
    return _REF_PREFIX + secrets.token_hex(8)


def redact_label(raw: bytes | None) -> str | None:
    """Redact a filename-like label to a safe, non-reversible token.

    The original name (which may contain a person's name, an ID number
    or a path) is never returned. The whole name body is discarded; at
    most a short alphabetic extension hint survives, so digits,
    identifiers and path components cannot be reconstructed.
    """
    if not raw:
        return None
    tail = raw.replace(b"\\", b"/").rpartition(b"/")[-1]
    _, dot, extension = tail.rpartition(b".")
    if dot and re.fullmatch(rb"[A-Za-z]{1,10}", extension):
        return "file_redacted." + extension.decode("ascii")
    return "file_redacted"


@dataclass(frozen=True, slots=True)
class PublicReference:
    """Information the customer-service sink is permitted to retain."""

    request_ref: str
    part_ref: str
    status: PartStatus
    bytes_received: int
    fingerprint: str | None
    reason: RejectReason | None = None
    is_file: bool = False

    def to_log_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict containing only safe fields."""
        record: dict[str, Any] = {
            "request_ref": self.request_ref,
            "part_ref": self.part_ref,
            "status": self.status.value,
            "is_file": self.is_file,
            "bytes_received": self.bytes_received,
            "fingerprint": self.fingerprint,
        }
        if self.reason is not None:
            record["reason"] = self.reason.value
        return record


@dataclass(frozen=True, slots=True)
class RejectionInfo:
    """Minimum information required when a part or request is refused."""

    part_ref: str
    status: PartStatus
    reason: RejectReason
    bytes_received: int
    detail: str | None = None

    def to_log_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "part_ref": self.part_ref,
            "status": self.status.value,
            "reason": self.reason.value,
            "bytes_received": self.bytes_received,
        }
        return record

    def to_receipt_dict(self) -> dict[str, Any]:
        # Business-only view: keeps the free-text detail. It is deliberately
        # excluded from the support view so an audit backend cannot smuggle
        # untrusted or personal text into customer-service logs.
        record = self.to_log_dict()
        if self.detail is not None:
            record["detail"] = self.detail
        return record


@dataclass(frozen=True, slots=True)
class ConfirmedMetadata:
    """Metadata confirmed only after a complete, accepted part.

    Field names, content type and the redacted filename are retained here for
    reconciliation against the original request. The raw value / file body is
    deliberately not stored: the receipt describes what was accepted, it does
    not duplicate the upload content.
    """

    request_ref: str
    part_ref: str
    field_name: str
    is_file: bool
    content_type: str | None
    bytes_received: int
    chunk_count: int
    content_hash: str
    fingerprint: str
    redacted_filename: str | None = None

    def to_receipt_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "request_ref": self.request_ref,
            "part_ref": self.part_ref,
            "field_name": self.field_name,
            "is_file": self.is_file,
            "content_type": self.content_type,
            "bytes_received": self.bytes_received,
            "chunk_count": self.chunk_count,
            "content_hash": self.content_hash,
            "fingerprint": self.fingerprint,
        }
        if self.redacted_filename is not None:
            record["redacted_filename"] = self.redacted_filename
        return record

    def to_public_reference(self) -> PublicReference:
        """Project onto the support-safe subset, dropping names and labels."""
        return PublicReference(
            request_ref=self.request_ref,
            part_ref=self.part_ref,
            status=PartStatus.ACCEPTED,
            bytes_received=self.bytes_received,
            fingerprint=self.fingerprint,
            is_file=self.is_file,
        )


@dataclass(frozen=True, slots=True)
class RequestSummary:
    """Final per-request record emitted once to each sink."""

    request_ref: str
    status: RequestStatus
    total_parts: int
    accepted_parts: int
    rejected_parts: int
    total_bytes: int
    rejections: tuple[RejectionInfo, ...] = field(default_factory=tuple)

    def to_receipt_dict(self) -> dict[str, Any]:
        return {
            "request_ref": self.request_ref,
            "status": self.status.value,
            "total_parts": self.total_parts,
            "accepted_parts": self.accepted_parts,
            "rejected_parts": self.rejected_parts,
            "total_bytes": self.total_bytes,
            "rejections": tuple(item.to_receipt_dict() for item in self.rejections),
        }

    def to_log_dict(self) -> dict[str, Any]:
        record = self.to_receipt_dict()
        record["rejections"] = tuple(item.to_log_dict() for item in self.rejections)
        return record
