"""Offline review for legacy signature to DSSE conversions.

A migration record contains a legacy signed object and the DSSE envelope that
was produced from it.  The reviewer uses an explicit field mapping to check
whether the original content, media type, and signing purpose are still covered
by cryptographic evidence.
"""

from __future__ import annotations

import argparse
import binascii
import copy
import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from securesystemslib._internal.utils import b64dec
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import Error as SSLibError
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import Key, Signature

CLAIM_CONTENT = "content"
CLAIM_MEDIA_TYPE = "media_type"
CLAIM_SIGNING_PURPOSE = "signing_purpose"
REQUIRED_CLAIMS = (
    CLAIM_CONTENT,
    CLAIM_MEDIA_TYPE,
    CLAIM_SIGNING_PURPOSE,
)

DISPOSITION_REUSABLE = "reusable"
DISPOSITION_RESIGN_CANDIDATE = "resign_candidate"
DISPOSITION_REJECTED = "rejected"

DEFAULT_FIELD_MAPPING: dict[str, dict[str, Any]] = {
    CLAIM_CONTENT: {
        "source": "/legacy/signed/content",
        "source_encoding": "utf-8",
        "target": "payload",
    },
    CLAIM_MEDIA_TYPE: {
        "source": "/legacy/signed/media_type",
        "source_encoding": "utf-8",
        "target": "payload_type",
    },
    CLAIM_SIGNING_PURPOSE: {
        "source": "/legacy/signed/usage",
        "source_encoding": "utf-8",
        "target": "payload_json",
        "target_path": "/usage",
        "target_encoding": "utf-8",
    },
}


def _pointer_parts(path: str | Sequence[str] | None) -> tuple[str, ...]:
    if path is None:
        return ()
    if isinstance(path, str):
        if not path:
            return ()
        if path.startswith("/"):
            return tuple(
                part.replace("~1", "/").replace("~0", "~")
                for part in path[1:].split("/")
            )
        return tuple(path.split("."))
    return tuple(path)


def _lookup(data: Any, path: str | Sequence[str] | None) -> tuple[bool, Any]:
    current = data
    for part in _pointer_parts(path):
        if isinstance(current, Mapping):
            if part not in current:
                return False, None
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            try:
                index = int(part)
            except ValueError:
                return False, None
            if index < 0 or index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def _as_bytes(value: Any, encoding: str | None = None) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)

    normalized = (encoding or "utf-8").lower().replace("-", "").replace("_", "")
    if normalized in {"utf8", "text", "identity"}:
        return str(value).encode("utf-8")
    if normalized == "base64":
        return b64dec(str(value))
    if normalized == "hex":
        return bytes.fromhex(str(value))
    if normalized == "canonicaljson":
        encoded = encode_canonical(value)
        if encoded is None:  # pragma: no cover
            raise TypeError("canonical encoding returned no result")
        return encoded.encode("utf-8")
    if normalized == "json":
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    raise ValueError(f"unsupported field encoding: {encoding}")


def _digest(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _text_hex_preview(data: bytes | None, limit: int = 128) -> str | None:
    if data is None or len(data) > limit:
        return None
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return data.hex()


def _coerce_key(keyid: str, key_like: Key | Mapping[str, Any]) -> Key:
    if isinstance(key_like, Key):
        return key_like

    key_dict = copy.deepcopy(dict(key_like))
    explicit_keyid = key_dict.pop("keyid", None)
    selected_keyid = keyid or explicit_keyid
    if not selected_keyid:
        raise ValueError("verification key is missing keyid")
    return Key.from_dict(str(selected_keyid), key_dict)


def _select_key(
    record: Mapping[str, Any],
    signature: Signature | None,
    trusted_keys: Mapping[str, Key | Mapping[str, Any]] | None,
) -> Key | None:
    keyid = signature.keyid if signature is not None else ""

    sources: list[Mapping[str, Any] | Key] = []
    if trusted_keys and keyid and keyid in trusted_keys:
        sources.append(trusted_keys[keyid])
    if trusted_keys and "" in trusted_keys:
        sources.append(trusted_keys[""])
    if isinstance(record.get("key"), (Mapping, Key)):
        sources.append(record["key"])  # type: ignore[arg-type]
    record_keys = record.get("keys")
    if isinstance(record_keys, Mapping) and keyid in record_keys:
        sources.append(record_keys[keyid])

    for source in sources:
        key = _coerce_key(keyid, source)
        if not keyid or key.keyid == keyid:
            return key

    if sources:
        return _coerce_key(keyid, sources[0])
    return None


def _legacy_signature(record: Mapping[str, Any]) -> Signature:
    legacy = record.get("legacy")
    if not isinstance(legacy, Mapping):
        raise ValueError("record is missing legacy object")

    signature_dict = copy.deepcopy(dict(legacy["signature"]))
    if "signature" in signature_dict and "sig" not in signature_dict:
        signature_dict["sig"] = signature_dict.pop("signature")

    encoding = legacy.get("signature_encoding")
    if encoding is None and signature_dict.get("sig_encoding") is not None:
        encoding = signature_dict.pop("sig_encoding")
    else:
        signature_dict.pop("sig_encoding", None)

    if str(encoding or "hex").lower() == "base64":
        signature_dict["sig"] = b64dec(signature_dict["sig"]).hex()

    return Signature.from_dict(signature_dict)


def _serialize_legacy_signed(legacy: Mapping[str, Any]) -> bytes:
    """Serialize the structured legacy signed object per its declared format."""

    signed = legacy.get("signed")
    if signed is None:
        raise ValueError("legacy record has no signed bytes or signed object")

    output_format = legacy.get("signing_format", "canonical-json")
    if output_format in {"canonical-json", "canonical_json"}:
        encoded = encode_canonical(signed)
        if encoded is None:  # pragma: no cover
            raise TypeError("canonical encoding returned no result")
        return encoded.encode("utf-8")
    if output_format == "json":
        return json.dumps(
            signed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    if output_format == "identity":
        return _as_bytes(signed)

    raise ValueError(f"unsupported legacy signing format: {output_format}")


def _legacy_signed_bytes(record: Mapping[str, Any]) -> bytes:
    legacy = record["legacy"]
    if "signed_bytes_b64" in legacy:
        return b64dec(legacy["signed_bytes_b64"])
    if "signed_bytes_hex" in legacy:
        return bytes.fromhex(legacy["signed_bytes_hex"])
    return _serialize_legacy_signed(legacy)


def _target_bytes(  # noqa: PLR0911
    envelope: Envelope,
    mapping: Mapping[str, Any],
) -> tuple[bytes | None, bool, str | None, list[str]]:
    """Return mapped bytes, whether DSSE signs them, location, and errors."""
    kind = mapping.get("target", "envelope_field")
    reasons: list[str] = []

    try:
        if kind == "payload":
            return envelope.payload, True, "payload", reasons

        if kind == "payload_type":
            return envelope.payload_type.encode("utf-8"), True, "payloadType", reasons

        if kind == "pae":
            return envelope.pae(), True, "pae", reasons

        if kind == "payload_json":
            payload = json.loads(envelope.payload.decode("utf-8"))
            found, value = _lookup(payload, mapping.get("target_path"))
            if not found:
                return None, True, "payload_json", ["target_missing"]
            return (
                _as_bytes(value, mapping.get("target_encoding", "utf-8")),
                True,
                "payload_json",
                reasons,
            )

        if kind == "unsigned_extension":
            found, value = _lookup(
                envelope.unrecognized_fields, mapping.get("target_path")
            )
            if not found:
                return None, False, "unsigned_extension", ["target_missing"]
            return (
                _as_bytes(value, mapping.get("target_encoding", "utf-8")),
                False,
                "unsigned_extension",
                reasons,
            )

        if kind in {"envelope_field", "envelope_path"}:
            envelope_dict = envelope.to_dict()
            found, value = _lookup(envelope_dict, mapping.get("target_path"))
            if not found:
                return None, False, "envelope_field", ["target_missing"]
            path = _pointer_parts(mapping.get("target_path"))
            signed_location = path[:1] == ("payloadType",)
            if path[:1] == ("payload",):
                value = b64dec(value)
                signed_location = True
            return (
                _as_bytes(value, mapping.get("target_encoding")),
                signed_location,
                "envelope_field",
                reasons,
            )

    except (
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
        binascii.Error,
        TypeError,
    ) as exc:
        reasons.append(f"target_encoding_error:{type(exc).__name__}")
        return None, False, str(kind), reasons

    raise ValueError(f"unsupported mapping target: {kind}")


@dataclass
class ClaimEvidence:
    """Byte-exact evidence for one mapped field."""

    claim: str
    mapped: bool = False
    source_present: bool = False
    target_present: bool = False
    exact_match: bool = False
    source_signed: bool = False
    target_signed: bool = False
    source_attested: bool = False
    target_attested: bool = False
    attested: bool = False
    source_sha256: str | None = None
    target_sha256: str | None = None
    source_byte_length: int | None = None
    target_byte_length: int | None = None
    source_utf8_hex: str | None = None
    target_utf8_hex: str | None = None
    target_location: str | None = None
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.__dict__)


@dataclass
class ConversionReview:
    """Review result for one legacy/envelope migration pair."""

    id: str
    disposition: str = ""
    legacy_signature_valid: bool | None = None
    envelope_signature_valid: bool | None = None
    legacy_preimage_consistent: bool | None = None
    signature_portable: bool = False
    verification_record_reusable: bool = False
    resign_required: bool = False
    already_resigned: bool = False
    claims: dict[str, ClaimEvidence] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    @property
    def can_reuse_record(self) -> bool:
        return self.disposition == DISPOSITION_REUSABLE

    @property
    def needs_resign(self) -> bool:
        return (
            self.disposition == DISPOSITION_RESIGN_CANDIDATE
            and not self.already_resigned
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["can_reuse_record"] = self.can_reuse_record
        result["needs_resign"] = self.needs_resign
        return result


def _mapping_for_claim(record: Mapping[str, Any], claim: str) -> dict[str, Any] | None:
    declared = record.get("field_mapping") or record.get("mapping") or {}
    if claim in declared:
        mapping = declared[claim]
        if mapping is None:
            return None
        if not isinstance(mapping, Mapping):
            raise ValueError(f"mapping for {claim} must be an object")
        merged = copy.deepcopy(DEFAULT_FIELD_MAPPING.get(claim, {}))
        merged.update(mapping)
        return merged

    if record.get("use_default_mapping", True) and claim in DEFAULT_FIELD_MAPPING:
        return copy.deepcopy(DEFAULT_FIELD_MAPPING[claim])
    return None


def _evaluate_claim(  # noqa: PLR0912, PLR0913, PLR0915
    record: Mapping[str, Any],
    envelope: Envelope | None,
    claim: str,
    legacy_valid: bool | None,
    envelope_valid: bool | None,
    preimage_consistent: bool | None,
) -> ClaimEvidence:
    evidence = ClaimEvidence(claim=claim)
    try:
        mapping = _mapping_for_claim(record, claim)
    except ValueError as exc:
        evidence.reasons.append(str(exc))
        return evidence

    if mapping is None or mapping is False:
        evidence.reasons.append("mapping_missing")
        return evidence
    evidence.mapped = True

    source_path = mapping.get("source")
    source_found, source_value = _lookup(record, source_path)
    evidence.source_present = source_found
    source_bytes: bytes | None = None
    if source_found:
        try:
            source_bytes = _as_bytes(
                source_value, mapping.get("source_encoding", "utf-8")
            )
        except (ValueError, UnicodeError, binascii.Error, TypeError) as exc:
            evidence.reasons.append(f"source_encoding_error:{type(exc).__name__}")

    if source_bytes is not None:
        evidence.source_sha256 = _digest(source_bytes)
        evidence.source_byte_length = len(source_bytes)
        evidence.source_utf8_hex = _text_hex_preview(source_bytes)

    source_in_signed = _pointer_parts(source_path)[:2] == ("legacy", "signed")
    evidence.source_signed = bool(
        source_in_signed or mapping.get("source_signed") is True
    )
    if source_found and source_bytes is not None and not evidence.source_signed:
        evidence.reasons.append("source_not_in_signed_object")

    target_bytes: bytes | None = None
    if envelope is not None:
        try:
            target_bytes, target_signed, location, reasons = _target_bytes(
                envelope, mapping
            )
            evidence.target_signed = target_signed
            evidence.target_location = location
            evidence.reasons.extend(reasons)
            evidence.target_present = target_bytes is not None and not reasons
        except ValueError as exc:
            evidence.reasons.append(str(exc))
    else:
        evidence.reasons.append("envelope_unavailable")

    if target_bytes is not None:
        evidence.target_sha256 = _digest(target_bytes)
        evidence.target_byte_length = len(target_bytes)
        evidence.target_utf8_hex = _text_hex_preview(target_bytes)

    if source_bytes is not None and target_bytes is not None:
        evidence.exact_match = hmac.compare_digest(source_bytes, target_bytes)
        if not evidence.exact_match:
            evidence.reasons.append("value_mismatch")
    elif (
        evidence.mapped and evidence.source_present and evidence.target_present is False
    ):
        if "target_missing" not in evidence.reasons:
            evidence.reasons.append("target_missing")

    evidence.source_attested = bool(
        evidence.source_signed
        and source_bytes is not None
        and legacy_valid is True
        and preimage_consistent is not False
    )
    if evidence.source_signed and preimage_consistent is False:
        evidence.reasons.append("legacy_preimage_mismatch")
    evidence.target_attested = bool(
        evidence.target_signed and target_bytes is not None and envelope_valid is True
    )
    evidence.attested = bool(
        evidence.exact_match and evidence.source_attested and evidence.target_attested
    )
    if not evidence.attested and not evidence.reasons:
        evidence.reasons.append("proof_incomplete")
    return evidence


def review_conversion(  # noqa: PLR0912, PLR0915
    record: Mapping[str, Any],
    trusted_keys: Mapping[str, Key | Mapping[str, Any]] | None = None,
) -> ConversionReview:
    """Review one legacy object/DSSE envelope migration record."""
    review = ConversionReview(id=str(record.get("id", "unnamed")))
    envelope: Envelope | None = None
    legacy_signature: Signature | None = None
    key: Key | None = None
    legacy_bytes: bytes | None = None
    preimage_consistent: bool | None = None

    try:
        legacy_signature = _legacy_signature(record)
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        review.reasons.append(f"legacy_signature_unreadable:{type(exc).__name__}")

    try:
        key = _select_key(record, legacy_signature, trusted_keys)
        if key is None:
            review.reasons.append("no_verification_key")
    except (KeyError, ValueError, TypeError) as exc:
        review.reasons.append(f"key_unreadable:{type(exc).__name__}")

    try:
        legacy_bytes = _legacy_signed_bytes(record)
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        review.reasons.append(f"legacy_signed_bytes_unreadable:{type(exc).__name__}")

    legacy = record.get("legacy")
    signing_format = (
        legacy.get("signing_format") if isinstance(legacy, Mapping) else None
    )
    if (
        legacy_bytes is not None
        and isinstance(legacy, Mapping)
        and legacy.get("signed") is not None
        and signing_format != "dsse-pae"
    ):
        try:
            expected_bytes = _serialize_legacy_signed(legacy)
            preimage_consistent = hmac.compare_digest(expected_bytes, legacy_bytes)
            if not preimage_consistent:
                review.reasons.append("legacy_signed_bytes_mismatch")
        except (ValueError, TypeError, binascii.Error) as exc:
            preimage_consistent = False
            review.reasons.append(f"legacy_preimage_unreadable:{type(exc).__name__}")
    review.legacy_preimage_consistent = preimage_consistent

    if legacy_signature is not None and key is not None and legacy_bytes is not None:
        try:
            key.verify_signature(legacy_signature, legacy_bytes)
            review.legacy_signature_valid = True
        except (SSLibError, ValueError, TypeError):
            review.legacy_signature_valid = False
            review.reasons.append("legacy_signature_invalid")
    else:
        review.legacy_signature_valid = None

    try:
        envelope = Envelope.from_dict(copy.deepcopy(record["envelope"]))
    except (
        KeyError,
        ValueError,
        TypeError,
        binascii.Error,
        UnicodeError,
    ) as exc:
        review.reasons.append(f"envelope_unreadable:{type(exc).__name__}")

    if envelope is not None and key is not None:
        try:
            envelope.verify([key], 1)
            review.envelope_signature_valid = True
        except (SSLibError, ValueError, TypeError):
            review.envelope_signature_valid = False
            review.reasons.append("envelope_signature_invalid")
    else:
        review.envelope_signature_valid = None

    if (
        envelope is not None
        and key is not None
        and legacy_signature is not None
        and review.legacy_signature_valid is True
    ):
        try:
            key.verify_signature(legacy_signature, envelope.pae())
            review.signature_portable = True
        except (SSLibError, ValueError, TypeError):
            review.signature_portable = False

    if (
        signing_format == "dsse-pae"
        and envelope is not None
        and legacy_bytes is not None
    ):
        review.legacy_preimage_consistent = hmac.compare_digest(
            legacy_bytes, envelope.pae()
        )
        if not review.legacy_preimage_consistent:
            review.reasons.append("legacy_pae_mismatch")

    for claim in REQUIRED_CLAIMS:
        review.claims[claim] = _evaluate_claim(
            record,
            envelope,
            claim,
            review.legacy_signature_valid,
            review.envelope_signature_valid,
            review.legacy_preimage_consistent,
        )

    all_attested = all(review.claims[claim].attested for claim in REQUIRED_CLAIMS)
    if review.legacy_signature_valid is False:
        review.disposition = DISPOSITION_REJECTED
    elif (
        review.legacy_signature_valid is True
        and review.envelope_signature_valid is True
        and review.legacy_preimage_consistent is not False
        and all_attested
    ):
        review.disposition = DISPOSITION_REUSABLE
        review.verification_record_reusable = True
    else:
        review.disposition = DISPOSITION_RESIGN_CANDIDATE
        review.already_resigned = review.envelope_signature_valid is True
        review.resign_required = not review.already_resigned

    return review


@dataclass
class ReviewReport:
    """Aggregate review results while retaining each fixture conclusion."""

    reviews: list[ConversionReview] = field(default_factory=list)

    @property
    def reusable(self) -> list[str]:
        return [r.id for r in self.reviews if r.disposition == DISPOSITION_REUSABLE]

    @property
    def resign_candidates(self) -> list[str]:
        return [
            r.id for r in self.reviews if r.disposition == DISPOSITION_RESIGN_CANDIDATE
        ]

    @property
    def resign_required(self) -> list[str]:
        return [r.id for r in self.reviews if r.needs_resign]

    @property
    def rejected(self) -> list[str]:
        return [r.id for r in self.reviews if r.disposition == DISPOSITION_REJECTED]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total": len(self.reviews),
                "reusable": self.reusable,
                "resign_candidates": self.resign_candidates,
                "resign_required": self.resign_required,
                "rejected": self.rejected,
            },
            "reviews": [review.to_dict() for review in self.reviews],
        }


def _records_from_data(data: Any) -> list[Mapping[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, Mapping):
        for key in ("cases", "records", "fixtures", "conversions"):
            if isinstance(data.get(key), list):
                return data[key]
        if "legacy" in data and "envelope" in data:
            return [data]
    raise ValueError("review input must be a record, list, or fixture collection")


def review_conversions(
    data: Any,
    trusted_keys: Mapping[str, Key | Mapping[str, Any]] | None = None,
) -> ReviewReport:
    """Review many records without merging same-looking fixtures."""

    return ReviewReport(
        [review_conversion(record, trusted_keys) for record in _records_from_data(data)]
    )


def review_file(
    path: str | Path,
    trusted_keys: Mapping[str, Key | Mapping[str, Any]] | None = None,
) -> ReviewReport:
    """Load a JSON fixture or manifest and review all records in it."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return review_conversions(data, trusted_keys)


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point: ``python -m securesystemslib.conversion_review``."""

    parser = argparse.ArgumentParser(
        description="Review legacy signature to DSSE conversion fixtures."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)

    reviews: list[ConversionReview] = []
    for path in args.paths:
        reviews.extend(review_file(path).reviews)

    report = ReviewReport(reviews)
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))

    if args.strict and (
        not report.reviews or report.resign_candidates or report.rejected
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
