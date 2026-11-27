"""Offline chain-of-custody review for renamed and re-sealed Office files.

The reviewer deliberately separates three observations that are easy to
conflate in a handover log:

* the protection state reported by :meth:`msoffcrypto.format.base.BaseOfficeFile.is_encrypted`;
* the SHA-256 digest of the bytes that were actually delivered; and
* the delivery event's time window.

Only the public :class:`msoffcrypto.OfficeFile` entry point is used to observe
protection.  Callers supply the handover events and any receipts/acks they
already hold.  A repeated delivery is retained in the report but is not turned
into an additional protection state or a fake before/after link.  When the
evidence cannot select one narrative, all defensible interpretations are kept
and the receipt records that would settle the link are listed separately.
"""

from __future__ import annotations

import hashlib
import io
import itertools
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from msoffcrypto import OfficeFile


PROTECTED = "protected"
PLAIN = "plain"
UNKNOWN = "unknown"

CONFIRMED = "confirmed"
PROVISIONAL = "provisional"
AMBIGUOUS = "ambiguous"
INVALID = "invalid"


def _mapping_value(mapping: Mapping[str, Any], *names: str) -> Any:
    """Return the first present, non-None value for a set of aliases."""
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return None


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    raise TypeError(f"expected a mapping or record object, got {type(value).__name__}")


def _as_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_TRUE_PROTECTION = {
    "1",
    "true",
    "yes",
    "y",
    "on",
    "protected",
    "encrypted",
    "sealed",
    "locked",
    "受保护",
    "已加密",
    "加密",
    "已封存",
}
_FALSE_PROTECTION = {
    "0",
    "false",
    "no",
    "n",
    "off",
    "plain",
    "plaintext",
    "unprotected",
    "encrypted=false",
    "clear",
    "open",
    "unsealed",
    "未保护",
    "未加密",
    "明文",
    "已解封",
}
_UNKNOWN_PROTECTION = {"", "unknown", "indeterminate", "unavailable", "n/a", "未知", "不确定"}


def _coerce_protection(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return PROTECTED if value else PLAIN
    if isinstance(value, (int, float)):
        return PROTECTED if value else PLAIN
    text = str(value).strip().lower()
    if text in _UNKNOWN_PROTECTION:
        return UNKNOWN
    if text in _TRUE_PROTECTION:
        return PROTECTED
    if text in _FALSE_PROTECTION:
        return PLAIN
    return None


def _normalize_digest(value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = str(value).strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    if text.startswith("sha-256:"):
        text = text[8:]
    if len(text) == 64 and all(character in "0123456789abcdef" for character in text):
        return text
    return text or None


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_source(source: Any) -> tuple[bytes, str]:
    if isinstance(source, (str, Path)):
        path = Path(source)
        return path.read_bytes(), str(path)
    if isinstance(source, (bytes, bytearray)):
        return bytes(source), "<bytes>"
    if hasattr(source, "read"):
        position = None
        try:
            position = source.tell()
        except Exception:
            position = None
        if position is not None:
            try:
                source.seek(0)
            except Exception:
                pass
        data = source.read()
        if position is not None:
            try:
                source.seek(position)
            except Exception:
                pass
        name = getattr(source, "name", "<file-like>")
        return data, str(name)
    raise TypeError("evidence must be a path, bytes, or a binary file handle")


@dataclass(frozen=True)
class EvidenceObservation:
    """The public protection observation plus a digest of the delivered bytes."""

    source: str
    digest: str | None
    protection: str
    encrypted: bool | None
    format: str | None = None
    type: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def observe_evidence(source: Any) -> EvidenceObservation:
    """Observe one delivered Office artifact without changing caller state.

    ``OfficeFile`` and ``is_encrypted()`` are the same public entry points used
    by the CLI compatibility helper.  The file digest is taken over the exact
    delivered bytes, before any parsing, so a re-seal with new salt or key
    material remains visible even when both versions are protected.
    """
    data: bytes | None = None
    label = str(source) if isinstance(source, (str, Path)) else "<unavailable>"
    digest = None
    encrypted: bool | None = None
    file_format = None
    file_type = None
    error = None

    try:
        data, label = _read_source(source)
        digest = _digest_bytes(data)
        office_file = OfficeFile(io.BytesIO(data))
        encrypted = bool(office_file.is_encrypted())
        file_format = getattr(office_file, "format", None)
        file_type = getattr(office_file, "type", None)
    except Exception as exc:  # FileFormatError is an expected observation result
        error = f"{type(exc).__name__}: {exc}"
        if data is not None:
            digest = _digest_bytes(data)

    protection = UNKNOWN if encrypted is None else (PROTECTED if encrypted else PLAIN)
    return EvidenceObservation(
        source=label,
        digest=digest,
        protection=protection,
        encrypted=encrypted,
        format=file_format,
        type=file_type,
        error=error,
    )


@dataclass
class HandoffEvent:
    """A caller-supplied delivery/handover event."""

    event_id: str
    artifact: str | None
    document_id: str | None = None
    filename: str | None = None
    sequence: int | None = None
    timestamp: datetime | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    claimed_protection: str | None = None
    claimed_digest: str | None = None
    delivery_id: str | None = None
    previous_event_id: str | None = None
    duplicate_of: str | None = None
    explicit_duplicate: bool = False
    ingest_index: int = 0
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def timestamp_text(self) -> str | None:
        return _mapping_value(self.raw, "timestamp", "event_time", "occurred_at", "handed_at", "delivered_at", "at")


@dataclass
class ReceiptRecord:
    """A signature/receipt record that can settle one or more link readings."""

    receipt_id: str
    event_ids: tuple[str, ...] = ()
    delivery_id: str | None = None
    decision: str | None = None
    signer: str | None = None
    signed_at: datetime | None = None
    digest: str | None = None
    protection: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    signature_valid: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def _normalize_event(value: Any, index: int) -> HandoffEvent:
    if isinstance(value, HandoffEvent):
        value.ingest_index = index
        return value
    mapping = _as_mapping(value)
    event_id = str(
        _mapping_value(mapping, "event_id", "id", "handoff_id", "delivery_event_id")
        or f"handoff-{index + 1}"
    )
    artifact = _mapping_value(
        mapping,
        "artifact",
        "path",
        "file",
        "source_path",
        "evidence_path",
        "source",
        "location",
        "object_path",
        "object",
    )
    filename = _mapping_value(mapping, "filename", "file_name", "name", "artifact_name")
    if artifact is None and filename is not None:
        artifact = str(filename)
    document_id = _mapping_value(
        mapping,
        "document_id",
        "doc_id",
        "logical_id",
        "case_id",
        "evidence_id",
        "document",
        "item_id",
        "artifact_id",
    )
    timestamp = _as_datetime(
        _mapping_value(mapping, "timestamp", "event_time", "time", "when", "occurred_at", "handed_at", "delivered_at", "at")
    )
    window = _mapping_value(mapping, "window", "time_window", "validity_window")
    window_start_value = _mapping_value(
        mapping, "window_start", "valid_from", "authorized_from", "not_before", "from_time"
    )
    window_end_value = _mapping_value(
        mapping, "window_end", "valid_to", "authorized_until", "not_after", "to_time", "deadline"
    )
    if isinstance(window, Mapping):
        window_start_value = window_start_value or _mapping_value(window, "start", "from", "begin")
        window_end_value = window_end_value or _mapping_value(window, "end", "to", "until", "finish")
    elif isinstance(window, (list, tuple)) and len(window) == 2:
        window_start_value = window_start_value or window[0]
        window_end_value = window_end_value or window[1]
    window_start = _as_datetime(
        window_start_value
    )
    window_end = _as_datetime(
        window_end_value
    )
    claimed_protection = _coerce_protection(
        _mapping_value(
            mapping,
            "claimed_protection",
            "protection",
            "protection_state",
            "protected_state",
            "protected",
            "encrypted",
            "is_encrypted",
            "state",
        )
    )
    claimed_digest = _normalize_digest(
        _mapping_value(
            mapping,
            "claimed_digest",
            "evidence_digest",
            "file_digest",
            "sha256_digest",
            "digest",
            "checksum",
            "hash",
            "sha256",
            "content_digest",
        )
    )
    delivery_id = _mapping_value(
        mapping,
        "delivery_id",
        "delivery_token",
        "delivery_key",
        "handoff_id",
        "idempotency_key",
        "transport_id",
    )
    previous_event_id = _mapping_value(
        mapping,
        "previous_event_id",
        "predecessor",
        "predecessor_id",
        "previous",
        "from_event_id",
        "parent_event_id",
        "extends_event_id",
    )
    duplicate_of = _mapping_value(mapping, "duplicate_of", "duplicate_event_id", "extends")
    explicit_duplicate = bool(
        _mapping_value(mapping, "duplicate", "is_duplicate", "repeat_delivery", "redelivery", "resent")
    )

    return HandoffEvent(
        event_id=event_id,
        artifact=str(artifact) if artifact is not None else None,
        document_id=str(document_id) if document_id is not None else None,
        filename=str(filename) if filename is not None else None,
        sequence=_as_int(_mapping_value(mapping, "sequence", "seq", "order", "ordinal")),
        timestamp=timestamp,
        window_start=window_start,
        window_end=window_end,
        claimed_protection=claimed_protection,
        claimed_digest=claimed_digest,
        delivery_id=str(delivery_id) if delivery_id is not None else None,
        previous_event_id=str(previous_event_id) if previous_event_id is not None else None,
        duplicate_of=str(duplicate_of) if duplicate_of is not None else None,
        explicit_duplicate=explicit_duplicate,
        ingest_index=index,
        raw=mapping,
    )


def _normalize_receipt(value: Any, index: int) -> ReceiptRecord:
    if isinstance(value, ReceiptRecord):
        return value
    mapping = _as_mapping(value)
    receipt_id = str(
        _mapping_value(mapping, "receipt_id", "id", "ack_id", "signature_id")
        or f"receipt-{index + 1}"
    )
    covers = _mapping_value(
        mapping,
        "event_ids",
        "events",
        "covers",
        "event_id",
        "for_event",
        "covers_events",
    )
    if covers is None:
        before_id = _mapping_value(mapping, "before_event_id", "from_event_id", "previous_event_id")
        after_id = _mapping_value(mapping, "after_event_id", "to_event_id", "next_event_id")
        covers = [item for item in (before_id, after_id) if item is not None]
    if isinstance(covers, str):
        covers = [covers]
    event_ids = tuple(str(item) for item in (covers or []))

    window = _mapping_value(mapping, "window", "time_window", "validity_window")
    window_start_value = _mapping_value(
        mapping, "window_start", "valid_from", "authorized_from", "not_before"
    )
    window_end_value = _mapping_value(
        mapping, "window_end", "valid_to", "authorized_until", "not_after", "deadline"
    )
    if isinstance(window, Mapping):
        window_start_value = window_start_value or _mapping_value(window, "start", "from", "begin")
        window_end_value = window_end_value or _mapping_value(window, "end", "to", "until", "finish")
    elif isinstance(window, (list, tuple)) and len(window) == 2:
        window_start_value = window_start_value or window[0]
        window_end_value = window_end_value or window[1]

    return ReceiptRecord(
        receipt_id=receipt_id,
        event_ids=event_ids,
        delivery_id=_string_or_none(
            _mapping_value(
                mapping,
                "delivery_id",
                "delivery_token",
                "delivery_key",
                "handoff_id",
                "idempotency_key",
                "transport_id",
            )
        ),
        decision=_string_or_none(
            _mapping_value(mapping, "decision", "result", "action", "verdict")
        ),
        signer=_string_or_none(
            _mapping_value(mapping, "signer", "signed_by", "acknowledged_by", "role", "reviewer")
        ),
        signed_at=_as_datetime(
            _mapping_value(mapping, "signed_at", "timestamp", "received_at", "acknowledged_at", "at")
        ),
        digest=_normalize_digest(
            _mapping_value(
                mapping,
                "digest",
                "evidence_digest",
                "accepted_digest",
                "file_digest",
                "sha256_digest",
                "checksum",
                "hash",
                "sha256",
                "content_digest",
            )
        ),
        protection=_coerce_protection(
            _mapping_value(
                mapping,
                "protection",
                "protection_state",
                "protected_state",
                "protected",
                "encrypted",
                "is_encrypted",
                "state",
            )
        ),
        window_start=_as_datetime(window_start_value),
        window_end=_as_datetime(window_end_value),
        signature_valid=_coerce_optional_bool(
            _mapping_value(mapping, "signature_valid", "verified", "valid", "cryptographically_valid")
        ),
        raw=mapping,
    )


def _string_or_none(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def _coerce_optional_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "valid", "ok", "verified"}:
        return True
    if text in {"0", "false", "no", "invalid", "failed", "error"}:
        return False
    return None


def _resolve_artifact(event: HandoffEvent, base_dir: Any) -> str | None:
    if event.artifact is None:
        return None
    path = Path(event.artifact)
    if base_dir is not None and not path.is_absolute():
        path = Path(base_dir) / path
    return str(path)


def _event_summary(event: HandoffEvent, observation: EvidenceObservation, canonical: bool) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "document_id": event.document_id,
        "filename": event.filename,
        "artifact": event.artifact,
        "sequence": event.sequence,
        "timestamp": _format_datetime(event.timestamp),
        "window_start": _format_datetime(event.window_start),
        "window_end": _format_datetime(event.window_end),
        "claimed_protection": event.claimed_protection,
        "claimed_digest": event.claimed_digest,
        "delivery_id": event.delivery_id,
        "previous_event_id": event.previous_event_id,
        "duplicate_of": event.duplicate_of,
        "canonical": canonical,
        "observation": observation.to_dict(),
    }


def _window_check(event: HandoffEvent) -> dict[str, Any]:
    if event.timestamp is None:
        if event.window_start is None and event.window_end is None:
            return {"ok": None, "reason": "timestamp_and_window_missing"}
        return {"ok": None, "reason": "timestamp_missing"}
    if event.window_start is None and event.window_end is None:
        return {"ok": None, "reason": "window_not_declared", "timestamp": _format_datetime(event.timestamp)}
    if event.window_start is not None and event.window_end is not None and event.window_start > event.window_end:
        return {"ok": False, "reason": "window_start_after_end"}
    if event.window_start is not None and event.timestamp < event.window_start:
        return {"ok": False, "reason": "before_window_start", "timestamp": _format_datetime(event.timestamp)}
    if event.window_end is not None and event.timestamp > event.window_end:
        return {"ok": False, "reason": "after_window_end", "timestamp": _format_datetime(event.timestamp)}
    return {"ok": True, "reason": "inside_window", "timestamp": _format_datetime(event.timestamp)}


def _seconds(value: Any) -> float | None:
    if value is None:
        return None
    if hasattr(value, "total_seconds"):
        return float(value.total_seconds())
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _status_check(event: HandoffEvent, observation: EvidenceObservation) -> dict[str, Any]:
    claimed = event.claimed_protection
    observed = observation.protection
    if observation.error is not None and observation.encrypted is None:
        return {"ok": False, "reason": "observation_failed", "claimed": claimed, "observed": observed}
    if claimed is None:
        return {"ok": None, "reason": "claim_missing", "claimed": None, "observed": observed}
    if claimed == UNKNOWN or observed == UNKNOWN:
        return {"ok": None, "reason": "state_unknown", "claimed": claimed, "observed": observed}
    return {
        "ok": claimed == observed,
        "reason": "match" if claimed == observed else "claim_differs_from_observation",
        "claimed": claimed,
        "observed": observed,
    }


def _digest_check(event: HandoffEvent, observation: EvidenceObservation) -> dict[str, Any]:
    claimed = _normalize_digest(event.claimed_digest)
    observed = _normalize_digest(observation.digest)
    if claimed is None:
        return {"ok": None, "reason": "claim_missing", "claimed": None, "observed": observed}
    if observed is None:
        return {"ok": False, "reason": "observation_failed", "claimed": claimed, "observed": None}
    return {
        "ok": claimed == observed,
        "reason": "match" if claimed == observed else "claim_differs_from_observation",
        "claimed": claimed,
        "observed": observed,
    }


def _same_observation(left: EvidenceObservation, right: EvidenceObservation) -> bool:
    return (
        left.digest is not None
        and left.digest == right.digest
        and left.protection == right.protection
    )


def _same_document(left: HandoffEvent, right: HandoffEvent) -> bool:
    if left.document_id is None or right.document_id is None:
        return True
    return left.document_id == right.document_id


def _duplicate_target(
    event: HandoffEvent,
    canonical_events: Sequence[HandoffEvent],
    observations: Mapping[str, EvidenceObservation],
) -> tuple[HandoffEvent | None, str, bool]:
    """Return (target, reason, is_conflict)."""
    target = None
    reason = ""
    explicit = False

    if event.duplicate_of:
        explicit = True
        if event.duplicate_of in {"*", "latest", "previous"}:
            target = canonical_events[-1] if canonical_events else None
        else:
            target = next((item for item in canonical_events if item.event_id == event.duplicate_of), None)
        reason = "explicit_duplicate_of"
    elif event.explicit_duplicate:
        explicit = True
        target = canonical_events[-1] if canonical_events else None
        reason = "explicit_duplicate_flag"

    if target is None and event.delivery_id:
        target = next(
            (item for item in reversed(canonical_events) if item.delivery_id == event.delivery_id),
            None,
        )
        if target is not None:
            reason = "same_delivery_id"

    if target is None and event.document_id is not None:
        for candidate in reversed([item for item in canonical_events if item.document_id == event.document_id]):
            same_name = (
                event.filename is not None
                and candidate.filename is not None
                and event.filename == candidate.filename
            )
            same_artifact = event.artifact is not None and event.artifact == candidate.artifact
            if not (same_name or same_artifact):
                continue
            if _same_observation(observations[event.event_id], observations[candidate.event_id]):
                target = candidate
                reason = "same_name_same_bytes_same_protection"
                break

    if target is None:
        return None, "unresolved_duplicate_marker" if explicit else "", False

    left_observation = observations[event.event_id]
    right_observation = observations[target.event_id]
    if not _same_observation(left_observation, right_observation):
        return target, reason + "_but_observation_differs", True
    if not _same_document(event, target):
        return target, reason + "_but_document_differs", True
    return target, reason, False


def _duplicate_claim_conflicts(event: HandoffEvent, target: HandoffEvent) -> list[str]:
    conflicts = []
    if (
        event.claimed_protection is not None
        and target.claimed_protection is not None
        and event.claimed_protection != target.claimed_protection
    ):
        conflicts.append("claimed_protection")
    if (
        event.claimed_digest is not None
        and target.claimed_digest is not None
        and event.claimed_digest != target.claimed_digest
    ):
        conflicts.append("claimed_digest")
    return conflicts


_DECISION_ALIASES: dict[str, set[str]] = {
    "reseal": {
        "reseal",
        "re_seal",
        "re-seal",
        "approved_reseal",
        "approve_reseal",
        "reseal_approved",
        "approval_reseal",
        "reapproved_seal",
        "复封",
        "批准复封",
        "同意复封",
    },
    "seal": {"seal", "protect", "encrypt", "approve_seal", "approved_seal", "seal_approved", "封存", "加密", "批准封存"},
    "unseal": {"unseal", "release", "decrypt", "unprotect", "approve_unseal", "approved_unseal", "解封", "批准解封"},
    "rename": {
        "rename",
        "renamed",
        "same_document",
        "continuity",
        "identity",
        "same_content",
        "renamed_same_content",
        "改名",
        "同一文档",
    },
    "duplicate": {"duplicate", "duplicate_delivery", "repeat", "redelivery", "重复送达", "重复交接"},
    "replacement": {
        "replace",
        "replacement",
        "different_document",
        "new_document",
        "substituted",
        "更换",
        "不同文档",
        "替换",
    },
    "late": {"late", "late_delivery", "after_window", "out_of_window", "迟到", "窗口外"},
    "clock": {"clock", "clock_skew", "reordered", "order_error", "时钟", "乱序"},
}


def _decision_category(receipt: ReceiptRecord, before: HandoffEvent, after: HandoffEvent) -> str | None:
    text = (receipt.decision or "").strip().lower()
    if text:
        for category, aliases in _DECISION_ALIASES.items():
            if text in aliases:
                return category
        if text in {"approved", "approval", "authorized", "accepted", "批准", "同意"}:
            if before.claimed_protection == PROTECTED and after.claimed_protection == PROTECTED:
                return "reseal"
            if before.claimed_protection == PLAIN and after.claimed_protection == PROTECTED:
                return "seal"
            if before.claimed_protection == PROTECTED and after.claimed_protection == PLAIN:
                return "unseal"
            return "rename"
    if receipt.raw.get("duplicate_of") or receipt.raw.get("duplicate_delivery"):
        return "duplicate"
    return None


def _receipt_covers(
    receipt: ReceiptRecord,
    before: HandoffEvent,
    after: HandoffEvent,
    before_observation: EvidenceObservation | None = None,
    after_observation: EvidenceObservation | None = None,
) -> tuple[bool, str]:
    before_digest = (
        _normalize_digest(before_observation.digest) if before_observation is not None else None
    ) or before.claimed_digest
    after_digest = (
        _normalize_digest(after_observation.digest) if after_observation is not None else None
    ) or after.claimed_digest
    if receipt.event_ids:
        covered = set(receipt.event_ids)
        if covered & {"*", "all", "link"}:
            return True, "wildcard_scope"
        if before.event_id in covered and after.event_id in covered:
            return True, "both_events"
        if after.event_id in covered and receipt.digest in {after_digest, None}:
            return True, "after_event"
        if before.event_id in covered and receipt.digest in {before_digest, None}:
            return True, "before_event"
        return False, "unrelated_event_scope"
    if receipt.digest is not None:
        if receipt.digest in {before_digest, after_digest}:
            return True, "event_digest"
        return False, "unrelated_digest_scope"
    if receipt.delivery_id is not None and receipt.delivery_id in {before.delivery_id, after.delivery_id}:
        return True, "delivery_id_scope"
    return False, "no_link_scope"


def _receipt_time_check(receipt: ReceiptRecord, before: HandoffEvent, after: HandoffEvent) -> dict[str, Any]:
    if receipt.signed_at is None:
        return {"ok": None, "reason": "signed_at_missing"}
    if receipt.window_start is not None and receipt.signed_at < receipt.window_start:
        return {"ok": False, "reason": "before_receipt_window"}
    if receipt.window_end is not None and receipt.signed_at > receipt.window_end:
        return {"ok": False, "reason": "after_receipt_window"}
    if before.timestamp is not None and receipt.signed_at < before.timestamp:
        return {"ok": False, "reason": "before_link_start"}
    if after.timestamp is not None and receipt.signed_at > after.timestamp:
        return {"ok": False, "reason": "after_link_end"}
    if before.timestamp is None or after.timestamp is None:
        return {"ok": None, "reason": "link_time_unknown"}
    return {"ok": True, "reason": "inside_link_window"}


def _receipt_summary(
    receipt: ReceiptRecord,
    before: HandoffEvent,
    after: HandoffEvent,
    before_observation: EvidenceObservation | None = None,
    after_observation: EvidenceObservation | None = None,
) -> dict[str, Any]:
    covers, scope_reason = _receipt_covers(receipt, before, after, before_observation, after_observation)
    time_check = _receipt_time_check(receipt, before, after)
    signature_ok = receipt.signature_valid is not False
    signer_ok = receipt.signer is not None
    accepted = covers and signature_ok and signer_ok and time_check["ok"] is True
    reasons = []
    if not covers:
        reasons.append(scope_reason)
    if not signer_ok:
        reasons.append("signer_missing")
    if not signature_ok:
        reasons.append("signature_invalid")
    if time_check["ok"] is not True:
        reasons.append(time_check["reason"])
    return {
        "receipt_id": receipt.receipt_id,
        "event_ids": list(receipt.event_ids),
        "delivery_id": receipt.delivery_id,
        "decision": receipt.decision,
        "category": _decision_category(receipt, before, after),
        "signer": receipt.signer,
        "signed_at": _format_datetime(receipt.signed_at),
        "digest": receipt.digest,
        "protection": receipt.protection,
        "covers_link": covers,
        "scope_reason": scope_reason,
        "time_check": time_check,
        "signature_ok": signature_ok,
        "accepted": accepted,
        "reasons": reasons,
    }


_CANDIDATE_LABELS = {
    "approved_reseal_same_document": "获准复封同一文档",
    "replacement_protected_document": "替换为另一受保护文档",
    "rename_same_content": "改名但字节未变",
    "duplicate_delivery": "同一交付重复送达",
    "replacement_same_bytes": "另一文档恰好同摘要",
    "approved_seal_same_document": "获准首次封存同一文档",
    "approved_unseal_same_document": "获准解封同一文档",
    "edited_same_document": "同一明文文档继续编辑",
    "replacement_plain_document": "替换为另一明文文档",
    "status_claim_error": "交接状态声明与公开保护观察不符",
    "evidence_digest_mismatch": "交接摘要与实际字节不符",
    "document_identity_discontinuity": "文档身份前后不连续",
    "out_of_window_delivery": "送达落在声明时间窗之外",
    "clock_skew_or_reordering": "时钟偏差或顺序记录错误",
    "unknown_protection_state": "保护状态无法判定",
    "evidence_unavailable": "证物无法读取",
}


_REQUIRED_DECISION = {
    "approved_reseal_same_document": "reseal",
    "replacement_protected_document": "replacement",
    "rename_same_content": "rename",
    "duplicate_delivery": "duplicate",
    "replacement_same_bytes": "replacement",
    "approved_seal_same_document": "seal",
    "approved_unseal_same_document": "unseal",
    "edited_same_document": "rename",
    "replacement_plain_document": "replacement",
    "out_of_window_delivery": "late",
    "clock_skew_or_reordering": "clock",
}


def _candidate(
    candidate_id: str,
    state: str,
    reasons: Iterable[str],
    decisive_receipts: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "label": _CANDIDATE_LABELS.get(candidate_id, candidate_id),
        "state": state,
        "reasons": list(reasons),
        "decisive_receipts": [item["receipt_id"] for item in decisive_receipts],
    }


def _supporting_receipts(
    candidate_id: str,
    receipts: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    category = _REQUIRED_DECISION.get(candidate_id)
    if category is None:
        return []
    return [
        receipt
        for receipt in receipts
        if receipt["accepted"] and receipt["category"] == category
    ]


def _interpretations(
    before: HandoffEvent,
    after: HandoffEvent,
    before_observation: EvidenceObservation,
    after_observation: EvidenceObservation,
    checks: Mapping[str, Any],
    receipts: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    same_bytes = before_observation.digest is not None and before_observation.digest == after_observation.digest
    same_protection = before_observation.protection == after_observation.protection
    name_changed = before.filename != after.filename
    status_ok = checks["before_status"]["ok"] is True and checks["after_status"]["ok"] is True
    digest_ok = checks["before_digest"]["ok"] is True and checks["after_digest"]["ok"] is True
    time_ok = checks["time"]["ok"] is True

    if checks["before_status"]["ok"] is False or checks["after_status"]["ok"] is False:
        candidates.append(_candidate("status_claim_error", "supported", ["public_protection_observation_differs"]))
    if checks["before_digest"]["ok"] is False or checks["after_digest"]["ok"] is False:
        candidates.append(_candidate("evidence_digest_mismatch", "supported", ["delivered_bytes_do_not_match_claim"]))
    if before_observation.error or after_observation.error:
        candidates.append(_candidate("evidence_unavailable", "supported", ["public_observation_or_fixture_read_failed"]))

    if same_bytes and same_protection:
        candidates.append(_candidate("rename_same_content", "possible", ["same_digest_and_same_protection"]))
        candidates.append(_candidate("duplicate_delivery", "possible", ["same_digest_and_same_protection"]))
        candidates.append(_candidate("replacement_same_bytes", "possible", ["identical_bytes_do_not_prove_identity"]))
        if not name_changed:
            candidates[0] = _candidate("duplicate_delivery", "possible", ["same_name_same_bytes_same_state"])
    elif before_observation.protection == UNKNOWN or after_observation.protection == UNKNOWN:
        candidates.append(_candidate("unknown_protection_state", "possible", ["public_protection_observation_unavailable"]))
    elif before_observation.protection == PROTECTED and after_observation.protection == PROTECTED:
        candidates.append(_candidate("approved_reseal_same_document", "possible", ["protected_bytes_changed"]))
        candidates.append(_candidate("replacement_protected_document", "possible", ["different_protected_bytes"]))
    elif before_observation.protection == PLAIN and after_observation.protection == PROTECTED:
        candidates.append(_candidate("approved_seal_same_document", "possible", ["plain_to_protected"]))
        candidates.append(_candidate("replacement_protected_document", "possible", ["different_protected_bytes"]))
    elif before_observation.protection == PROTECTED and after_observation.protection == PLAIN:
        candidates.append(_candidate("approved_unseal_same_document", "possible", ["protected_to_plain"]))
        candidates.append(_candidate("replacement_plain_document", "possible", ["different_plain_bytes"]))
    else:
        candidates.append(_candidate("edited_same_document", "possible", ["plain_bytes_changed"]))
        candidates.append(_candidate("replacement_plain_document", "possible", ["different_plain_bytes"]))

    if checks["time"]["ok"] is False or checks["before_window"].get("ok") is False or checks["after_window"].get("ok") is False:
        candidates.append(_candidate("out_of_window_delivery", "possible", ["event_outside_declared_window"]))
        candidates.append(_candidate("clock_skew_or_reordering", "possible", ["times_or_order_disagree_with_window"]))

    for candidate in candidates:
        supporting = _supporting_receipts(candidate["candidate_id"], receipts)
        if supporting:
            candidate["state"] = "supported"
            candidate["reasons"] = ["decisive_receipt_present"]
            candidate["decisive_receipts"] = [item["receipt_id"] for item in supporting]

    # A receipt that names both versions and states a decision excludes the
    # competing readings.  This is what turns an ambiguous link into a settled
    # one without discarding the alternatives from the audit trail.
    accepted_categories = {item["category"] for item in receipts if item["accepted"]}
    exclusion_map = {
        "reseal": {"replacement_protected_document"},
        "seal": {"replacement_protected_document"},
        "unseal": {"replacement_plain_document"},
        "rename": {"duplicate_delivery", "replacement_same_bytes", "replacement_plain_document"},
        "duplicate": {"rename_same_content", "replacement_same_bytes", "replacement_plain_document"},
        "replacement": {
            "approved_reseal_same_document",
            "approved_seal_same_document",
            "approved_unseal_same_document",
            "edited_same_document",
            "rename_same_content",
            "duplicate_delivery",
        },
    }
    for category in accepted_categories:
        for candidate in candidates:
            if candidate["candidate_id"] in exclusion_map.get(category, set()) and candidate["state"] == "possible":
                candidate["state"] = "excluded"
                candidate["reasons"] = [f"valid_{category}_receipt_names_both_versions"]

    if not status_ok and not any(candidate["state"] == "supported" for candidate in candidates):
        candidates.append(_candidate("status_claim_error", "supported", ["status_claim_not_proven"]))
    if not digest_ok and not any(candidate["state"] == "supported" for candidate in candidates):
        candidates.append(_candidate("evidence_digest_mismatch", "supported", ["digest_claim_not_proven"]))
    if not time_ok and not candidates:
        candidates.append(_candidate("out_of_window_delivery", "possible", ["time_window_not_proven"]))

    return candidates


def _link_checks(
    before: HandoffEvent,
    after: HandoffEvent,
    before_observation: EvidenceObservation,
    after_observation: EvidenceObservation,
    max_gap_seconds: float | None,
) -> dict[str, Any]:
    before_status = _status_check(before, before_observation)
    after_status = _status_check(after, after_observation)
    before_digest = _digest_check(before, before_observation)
    after_digest = _digest_check(after, after_observation)
    before_window = _window_check(before)
    after_window = _window_check(after)

    if before.timestamp is None or after.timestamp is None:
        order = {"ok": None, "reason": "timestamp_missing"}
        gap = {"ok": None, "reason": "timestamp_missing"}
    else:
        ordered = before.timestamp <= after.timestamp
        order = {
            "ok": ordered,
            "reason": "ordered" if ordered else "after_precedes_before",
            "before": _format_datetime(before.timestamp),
            "after": _format_datetime(after.timestamp),
        }
        seconds = (after.timestamp - before.timestamp).total_seconds()
        if max_gap_seconds is None:
            gap = {"ok": None, "reason": "max_gap_not_configured", "seconds": seconds}
        else:
            gap = {
                "ok": seconds <= max_gap_seconds,
                "reason": "inside_max_gap" if seconds <= max_gap_seconds else "gap_exceeds_limit",
                "seconds": seconds,
                "limit_seconds": max_gap_seconds,
            }

    false_time = order["ok"] is False or before_window.get("ok") is False or after_window.get("ok") is False or gap["ok"] is False
    if false_time:
        time_ok: bool | None = False
    elif order["ok"] is True and before_window.get("ok") is True and after_window.get("ok") is True:
        time_ok = True if gap["ok"] is not False else False
    else:
        time_ok = None

    return {
        "before_status": before_status,
        "after_status": after_status,
        "before_digest": before_digest,
        "after_digest": after_digest,
        "before_window": before_window,
        "after_window": after_window,
        "order": order,
        "gap": gap,
        "time": {"ok": time_ok},
    }


def _required_receipts(
    link_id: str,
    before: HandoffEvent,
    after: HandoffEvent,
    before_observation: EvidenceObservation,
    after_observation: EvidenceObservation,
    interpretations: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    required = []
    for candidate in interpretations:
        if candidate["state"] != "possible" or candidate["candidate_id"] not in _REQUIRED_DECISION:
            continue
        category = _REQUIRED_DECISION[candidate["candidate_id"]]
        required.append(
            {
                "link_id": link_id,
                "candidate_id": candidate["candidate_id"],
                "decision": category,
                "event_ids": [before.event_id, after.event_id],
                "delivery_id": after.delivery_id or before.delivery_id,
                "signer_required": True,
                "signed_at_window": [
                    _format_datetime(before.timestamp),
                    _format_datetime(after.timestamp),
                ],
                "digest": after_observation.digest or after.claimed_digest or before_observation.digest,
                "protection": after_observation.protection,
                "would_settle": candidate["candidate_id"],
            }
        )
    return required


def _link_status(
    before_observation: EvidenceObservation,
    after_observation: EvidenceObservation,
    checks: Mapping[str, Any],
    interpretations: Sequence[dict[str, Any]],
) -> str:
    if before_observation.error or after_observation.error:
        return INVALID
    if checks["before_status"]["ok"] is False or checks["after_status"]["ok"] is False:
        return INVALID
    if checks["before_digest"]["ok"] is False or checks["after_digest"]["ok"] is False:
        return INVALID
    if checks["order"]["ok"] is False:
        return INVALID
    if checks["time"]["ok"] is False:
        return AMBIGUOUS

    supported = [item for item in interpretations if item["state"] == "supported"]
    possible = [item for item in interpretations if item["state"] == "possible"]
    if supported:
        return CONFIRMED if not possible else AMBIGUOUS
    if len(possible) == 1:
        return PROVISIONAL
    return AMBIGUOUS


def _review_link(
    link_id: str,
    before: HandoffEvent,
    after: HandoffEvent,
    before_observation: EvidenceObservation,
    after_observation: EvidenceObservation,
    receipts: Sequence[ReceiptRecord],
    max_gap_seconds: float | None,
) -> dict[str, Any]:
    checks = _link_checks(before, after, before_observation, after_observation, max_gap_seconds)
    receipt_summaries = [
        _receipt_summary(receipt, before, after, before_observation, after_observation)
        for receipt in receipts
    ]
    interpretations = _interpretations(
        before,
        after,
        before_observation,
        after_observation,
        checks,
        receipt_summaries,
    )
    status = _link_status(before_observation, after_observation, checks, interpretations)
    required = _required_receipts(
        link_id,
        before,
        after,
        before_observation,
        after_observation,
        interpretations,
    )
    if before.document_id is not None and after.document_id is not None and before.document_id != after.document_id:
        status = INVALID
        interpretations.insert(
            0,
            _candidate(
                "document_identity_discontinuity",
                "supported",
                ["document_id_changed_between_events"],
            ),
        )
    decisive = [item for item in receipt_summaries if item["covers_link"]]
    return {
        "link_id": link_id,
        "before_event_id": before.event_id,
        "after_event_id": after.event_id,
        "document_id": after.document_id or before.document_id,
        "relation": _relation_name(before_observation, after_observation),
        "status": status,
        "checks": checks,
        "interpretations": interpretations,
        "decisive_receipts": decisive,
        "required_receipts": required,
    }


def _relation_name(
    before_observation: EvidenceObservation,
    after_observation: EvidenceObservation,
) -> str:
    if before_observation.digest is not None and before_observation.digest == after_observation.digest:
        if before_observation.protection == after_observation.protection:
            return "same_bytes_same_protection"
        return f"same_bytes_{before_observation.protection}_to_{after_observation.protection}"
    return f"changed_bytes_{before_observation.protection}_to_{after_observation.protection}"


def _embedded_receipts(events: Sequence[HandoffEvent]) -> list[Any]:
    receipts: list[Any] = []
    for event in events:
        for key in ("receipts", "receipt", "acknowledgements", "acks", "signatures"):
            value = event.raw.get(key)
            if value is None:
                continue
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                if isinstance(item, Mapping):
                    receipt = dict(item)
                    receipt.setdefault("event_id", event.event_id)
                    receipts.append(receipt)
                else:
                    receipts.append({"receipt_id": str(item), "event_id": event.event_id})
    return receipts


def _unique_receipts(values: Iterable[Any]) -> list[ReceiptRecord]:
    normalized: dict[str, ReceiptRecord] = {}
    for index, value in enumerate(values):
        receipt = _normalize_receipt(value, index)
        normalized[receipt.receipt_id] = receipt
    return list(normalized.values())


def _order_events(events: Sequence[HandoffEvent]) -> list[HandoffEvent]:
    if events and all(event.sequence is not None for event in events):
        return sorted(events, key=lambda event: (event.sequence, event.ingest_index))
    return list(events)


def _canonical_links(events: Sequence[HandoffEvent]) -> list[tuple[HandoffEvent, HandoffEvent]]:
    """Prefer explicit predecessor links; otherwise use canonical adjacency."""
    by_id = {event.event_id: event for event in events}
    explicit = []
    for event in events:
        if event.previous_event_id and event.previous_event_id in by_id:
            before = by_id[event.previous_event_id]
            if before is not event:
                explicit.append((before, event))
    if explicit:
        pairs = list(explicit)
    else:
        pairs = list(zip(events, events[1:]))
    # Avoid duplicate pairs if an explicit link also happens to be adjacent.
    unique = []
    seen = set()
    for before, after in pairs:
        key = (before.event_id, after.event_id)
        if key not in seen:
            seen.add(key)
            unique.append((before, after))
    return unique


def _event_equivalence_summary(
    event: HandoffEvent,
    target: HandoffEvent,
    reason: str,
    dropped: bool,
    conflicts: Sequence[str],
) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "canonical_event_id": target.event_id,
        "reason": reason,
        "dropped": dropped,
        "claim_conflicts": list(conflicts),
        "delivery_id": event.delivery_id,
        "protection_state_added": False if dropped else "conflict_requires_review",
    }


@dataclass
class CustodyReview:
    """Result of one deterministic review pass over handover events."""

    status: str
    events: list[dict[str, Any]]
    protection_states: list[dict[str, Any]]
    duplicates: list[dict[str, Any]]
    links: list[dict[str, Any]]
    solutions: list[dict[str, Any]]
    receipts: list[dict[str, Any]]
    decisive_receipts: list[dict[str, Any]]
    required_receipts: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "events": self.events,
            "protection_states": self.protection_states,
            "duplicates": self.duplicates,
            "links": self.links,
            "solutions": self.solutions,
            "receipts": self.receipts,
            "decisive_receipts": self.decisive_receipts,
            "required_receipts": self.required_receipts,
        }

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, **kwargs)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


def _overall_status(links: Sequence[Mapping[str, Any]]) -> str:
    if not links:
        return PROVISIONAL
    if any(link["status"] == INVALID for link in links):
        return INVALID
    if any(link["status"] == AMBIGUOUS for link in links):
        return AMBIGUOUS
    if any(link["status"] == PROVISIONAL for link in links):
        return PROVISIONAL
    return CONFIRMED


def _build_solutions(links: Sequence[Mapping[str, Any]], status: str) -> list[dict[str, Any]]:
    if not links:
        return [{"solution_id": "s1", "status": PROVISIONAL, "links": {}, "decisive_receipts": []}]

    choices = []
    for link in links:
        candidates = [
            item for item in link["interpretations"] if item["state"] in {"supported", "possible"}
        ]
        choices.append([(link["link_id"], item) for item in candidates])

    solutions = []
    for index, combination in enumerate(itertools.islice(itertools.product(*choices), 64), start=1):
        selected = {link_id: candidate["candidate_id"] for link_id, candidate in combination}
        fully_supported = all(candidate["state"] == "supported" for _, candidate in combination)
        solutions.append(
            {
                "solution_id": f"s{index}",
                "status": CONFIRMED if fully_supported else "possible",
                "links": selected,
                "decisive_receipts": sorted(
                    {
                        receipt_id
                        for _, candidate in combination
                        for receipt_id in candidate.get("decisive_receipts", [])
                    }
                ),
            }
        )
    if not solutions:
        solutions.append({"solution_id": "s1", "status": status, "links": {}, "decisive_receipts": []})
    return solutions


def _receipt_raw_summary(receipt: ReceiptRecord) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "event_ids": list(receipt.event_ids),
        "delivery_id": receipt.delivery_id,
        "decision": receipt.decision,
        "signer": receipt.signer,
        "signed_at": _format_datetime(receipt.signed_at),
        "digest": receipt.digest,
        "protection": receipt.protection,
        "signature_valid": receipt.signature_valid,
    }


def review_handoffs(
    events: Any,
    receipts: Iterable[Any] | None = None,
    *,
    base_dir: Any = None,
    max_gap_seconds: Any = None,
) -> CustodyReview:
    """Review caller-supplied handover events against public protection observations.

    ``events`` may be a sequence of mappings/objects or a payload mapping with
    ``events`` and ``receipts`` members.  Events are interpreted in arrival
    order unless every event declares an integer ``sequence``.  The same
    ``delivery_id`` (or an explicit ``duplicate_of`` marker) identifies a
    repeated delivery when the two observations are byte-identical and have the
    same public protection state; such an event is not counted as a new state.
    """
    if isinstance(events, Mapping) and any(key in events for key in ("events", "handoffs", "deliveries")):
        payload = dict(events)
        if receipts is None:
            receipts = payload.get("receipts") or payload.get("acks") or payload.get("acknowledgements")
        if base_dir is None:
            base_dir = payload.get("base_dir") or payload.get("base")
        if max_gap_seconds is None:
            max_gap_seconds = _mapping_value(payload, "max_gap_seconds", "max_gap")
        events = payload.get("events") or payload.get("handoffs") or payload.get("deliveries") or []
    if isinstance(events, Mapping):
        events = [events]

    normalized_events = [
        _normalize_event(value, index) for index, value in enumerate(events)
    ]
    explicit_receipts = list(receipts or [])
    embedded = _embedded_receipts(normalized_events)
    normalized_receipts = _unique_receipts([*explicit_receipts, *embedded])
    ordered_events = _order_events(normalized_events)
    max_gap = _seconds(max_gap_seconds)

    observation_cache: dict[str, EvidenceObservation] = {}
    observations: dict[str, EvidenceObservation] = {}
    for event in ordered_events:
        resolved = _resolve_artifact(event, base_dir)
        if resolved is None:
            observation = EvidenceObservation(
                source="<missing>",
                digest=None,
                protection=UNKNOWN,
                encrypted=None,
                error="ArtifactMissing: no artifact path was supplied",
            )
        else:
            if resolved not in observation_cache:
                observation_cache[resolved] = observe_evidence(resolved)
            observation = observation_cache[resolved]
        observations[event.event_id] = observation

    canonical_events: list[HandoffEvent] = []
    duplicates: list[dict[str, Any]] = []
    for event in ordered_events:
        target, reason, conflict = _duplicate_target(event, canonical_events, observations)
        if target is None:
            if reason:
                duplicates.append(
                    {
                        "event_id": event.event_id,
                        "canonical_event_id": None,
                        "reason": reason,
                        "dropped": False,
                        "claim_conflicts": [],
                        "delivery_id": event.delivery_id,
                        "protection_state_added": "kept_for_review",
                    }
                )
            canonical_events.append(event)
            continue

        conflicts = _duplicate_claim_conflicts(event, target)
        dropped = not conflict
        duplicates.append(
            _event_equivalence_summary(event, target, reason, dropped, conflicts)
        )
        if conflict:
            canonical_events.append(event)

    dropped_ids = {item["event_id"] for item in duplicates if item["dropped"]}
    event_rows = [
        _event_summary(event, observations[event.event_id], event.event_id not in dropped_ids)
        for event in ordered_events
    ]

    states: dict[tuple[str | None, str, str], dict[str, Any]] = {}
    for event in canonical_events:
        observation = observations[event.event_id]
        key = (event.document_id, observation.protection, observation.digest or observation.error or UNKNOWN)
        if key not in states:
            states[key] = {
                "state_id": f"state-{len(states) + 1}",
                "document_id": event.document_id,
                "protection": observation.protection,
                "digest": observation.digest,
                "event_ids": [],
                "duplicate_event_ids": [],
            }
        states[key]["event_ids"].append(event.event_id)
    for duplicate in duplicates:
        if not duplicate["dropped"]:
            continue
        target = next(
            (event for event in canonical_events if event.event_id == duplicate["canonical_event_id"]),
            None,
        )
        if target is None:
            continue
        observation = observations[target.event_id]
        key = (target.document_id, observation.protection, observation.digest or observation.error or UNKNOWN)
        if key in states:
            states[key]["duplicate_event_ids"].append(duplicate["event_id"])

    links = []
    for index, (before, after) in enumerate(_canonical_links(canonical_events), start=1):
        link_id = f"link-{index}"
        links.append(
            _review_link(
                link_id,
                before,
                after,
                observations[before.event_id],
                observations[after.event_id],
                normalized_receipts,
                max_gap,
            )
        )

    decisive: dict[str, dict[str, Any]] = {}
    required: dict[tuple[str, str], dict[str, Any]] = {}
    for link in links:
        for receipt in link["decisive_receipts"]:
            item = dict(receipt)
            item["link_id"] = link["link_id"]
            decisive[f"{link['link_id']}:{receipt['receipt_id']}"] = item
        for requirement in link["required_receipts"]:
            required[(link["link_id"], requirement["candidate_id"])] = requirement

    status = _overall_status(links)
    return CustodyReview(
        status=status,
        events=event_rows,
        protection_states=list(states.values()),
        duplicates=duplicates,
        links=links,
        solutions=_build_solutions(links, status),
        receipts=[_receipt_raw_summary(receipt) for receipt in normalized_receipts],
        decisive_receipts=list(decisive.values()),
        required_receipts=list(required.values()),
    )


def review_custody_chain(
    events: Any,
    receipts: Iterable[Any] | None = None,
    **options: Any,
) -> CustodyReview:
    """Readable alias for :func:`review_handoffs`."""
    return review_handoffs(events, receipts, **options)


review_chain = review_custody_chain
review_custody = review_custody_chain
review_events = review_handoffs
observe_protection = observe_evidence
observe_file = observe_evidence
CustodyChainReview = CustodyReview
