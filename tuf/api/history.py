"""Offline historical TUF metadata review and replay API."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from tuf.api.metadata import (
    LengthOrHashMismatchError,
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.api.serialization import DeserializationError

REPORT_SCHEMA = "tuf-historical-audit-report/v1"
# patch-ok
REQUEST_SCHEMA = "tuf-historical-audit-request/v1"
CASEBOOK_SCHEMA = "tuf-historical-casebook/v1"


def _utc(value: datetime | str | None, field_name: str) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(text)
    else:
        msg = f"{field_name} must be an ISO string or datetime"
        raise TypeError(msg)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return _utc(value, "datetime").isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


@dataclass(frozen=True)
class Reason:
    """A machine-readable explanation for an audit outcome."""

    code: str
    message: str
    severity: str = "error"
    evidence_hashes: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "evidence_hashes": list(self.evidence_hashes),
            "details": self.details,
        }


@dataclass
class Step:
    """One verification step and the evidence it consumed."""

    name: str
    status: str = "passed"
    evidence_hashes: list[str] = field(default_factory=list)
    reasons: list[Reason] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def evidence(self, *hashes: str | None) -> None:
        """Add content hashes without duplicates."""
        for item in hashes:
            if item and item not in self.evidence_hashes:
                self.evidence_hashes.append(item)

    def reason(self, reason: Reason) -> None:
        """Attach a reason to this step."""
        self.reasons.append(reason)
        self.evidence(*reason.evidence_hashes)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "name": self.name,
            "status": self.status,
            "evidence_hashes": self.evidence_hashes,
            "reasons": [item.to_dict() for item in self.reasons],
            "details": self.details,
        }


@dataclass(frozen=True)
class TrustAnchor:
    """Out-of-band trusted starting Root metadata."""

    data: bytes
    sha256: str | None = None
    collected_at: datetime | str | None = None
    source: str = "trust-anchor"

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            msg = "trust anchor data must be bytes"
            raise TypeError(msg)
        if self.collected_at is not None:
            object.__setattr__(
                self,
                "collected_at",
                _utc(self.collected_at, "trust_anchor.collected_at"),
            )


@dataclass(frozen=True)
class CollectedMetadata:
    """Raw metadata bytes with the time at which they were collected."""

    data: bytes
    collected_at: datetime | str
    record_id: str | None = None
    source: str = "archive"
    sequence: int | None = None
    log_id: str = "collection-log"
    name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            msg = "collected metadata data must be bytes"
            raise TypeError(msg)
        object.__setattr__(
            self,
            "collected_at",
            _utc(self.collected_at, "collected_at"),
        )


@dataclass(frozen=True)
class TargetSpec:
    """Target path and optional raw target bytes."""

    path: str
    data: bytes | None = None
    require_bytes: bool = False

    def __post_init__(self) -> None:
        if self.data is not None and not isinstance(self.data, bytes):
            msg = "target data must be bytes or None"
            raise TypeError(msg)


@dataclass(frozen=True)
class AuditRequest:
    """All offline inputs needed for dual historical/current review."""

    trust_anchor: TrustAnchor
    records: tuple[CollectedMetadata, ...]
    target: TargetSpec
    as_of: datetime
    current_time: datetime
    request_id: str | None = None

    def __post_init__(self) -> None:
        anchor = self.trust_anchor
        if isinstance(anchor, bytes):
            anchor = TrustAnchor(anchor)
        elif not isinstance(anchor, TrustAnchor):
            msg = "trust_anchor must be bytes or TrustAnchor"
            raise TypeError(msg)

        raw_records = self.records
        records: tuple[CollectedMetadata, ...]
        if isinstance(raw_records, CollectedMetadata):
            records = (raw_records,)
        else:
            records = tuple(
                item
                if isinstance(item, CollectedMetadata)
                else CollectedMetadata(**item)
                for item in raw_records
            )

        target = self.target
        if isinstance(target, str):
            target = TargetSpec(target)
        elif isinstance(target, dict):
            target = TargetSpec(**target)
        elif not isinstance(target, TargetSpec):
            msg = "target must be a path, dict, or TargetSpec"
            raise TypeError(msg)

        object.__setattr__(self, "trust_anchor", anchor)
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "as_of", _utc(self.as_of, "as_of"))
        object.__setattr__(
            self,
            "current_time",
            _utc(self.current_time, "current_time"),
        )


@dataclass
class AuditReport:
    """Deterministic dual-view audit report."""

    schema_version: str
    request_schema: str
    request_digest: str
    request_id: str | None
    as_of: str
    current_time: str
    historical: dict[str, Any]
    current: dict[str, Any]
    records: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    report_hash: str = ""

    def to_dict(self, include_hash: bool = True) -> dict[str, Any]:
        """Return JSON-serializable report data."""
        result = {
            "schema_version": self.schema_version,
            "request_schema": self.request_schema,
            "request_digest": self.request_digest,
            "request_id": self.request_id,
            "as_of": self.as_of,
            "current_time": self.current_time,
            "historical": self.historical,
            "current": self.current,
            "records": self.records,
            "evidence": self.evidence,
        }
        if include_hash:
            result["report_hash"] = self.report_hash
        return result

class _Ledger:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    def add(self, data: bytes, kind: str) -> str:
        digest = _sha256(data)
        item = self._items.setdefault(
            digest,
            {
                "sha256": digest,
                "algorithm": "sha256",
                "length": len(data),
                "kinds": set[str](),
            },
        )
        item["kinds"].add(kind)
        return digest

    def evidence(self) -> list[dict[str, Any]]:
        result = []
        for digest in sorted(self._items):
            item = self._items[digest]
            result.append(
                {
                    "sha256": digest,
                    "algorithm": "sha256",
                    "length": item["length"],
                    "kinds": sorted(item["kinds"]),
                }
            )
        return result


@dataclass
class _Material:
    record_id: str
    source: str
    name: str | None
    data: bytes
    collected_at: datetime | None
    sequence: int | None
    log_id: str | None
    raw_hash: str
    md: Metadata[Any] | None = None
    signed_hash: str | None = None
    role: str | None = None
    version: int | None = None
    expires: datetime | None = None
    parse_reason: Reason | None = None
    is_anchor: bool = False


def _parse_material(
    data: bytes,
    ledger: _Ledger,
    *,
    record_id: str,
    source: str,
    name: str | None,
    collected_at: datetime | None,
    sequence: int | None = None,
    log_id: str | None = None,
    is_anchor: bool = False,
) -> _Material:
    raw_hash = ledger.add(
        data, "trust-anchor-raw" if is_anchor else "metadata-raw"
    )
    try:
        md = Metadata.from_bytes(data)
    except Exception as exc:  # noqa: BLE001 - malformed input is audit evidence
        cause = exc.__cause__ if exc.__cause__ is not None else exc
        reason = Reason(
            "metadata_parse_error",
            f"{type(cause).__name__}: {cause}",
            "rejection",
            (raw_hash,),
            {"record_id": record_id, "source": source},
        )
        return _Material(
            record_id=record_id,
            source=source,
            name=name,
            data=data,
            collected_at=collected_at,
            sequence=sequence,
            log_id=log_id,
            raw_hash=raw_hash,
            parse_reason=reason,
            is_anchor=is_anchor,
        )

    signed_hash = ledger.add(md.signed_bytes, "metadata-signed-bytes")
    signed = md.signed
    return _Material(
        record_id=record_id,
        source=source,
        name=name,
        data=data,
        collected_at=collected_at,
        sequence=sequence,
        log_id=log_id,
        raw_hash=raw_hash,
        md=md,
        signed_hash=signed_hash,
        role=signed.type,
        version=signed.version,
        expires=signed.expires,
        is_anchor=is_anchor,
    )


def audit(request: AuditRequest | dict[str, Any]) -> AuditReport:
    """Run historical and current-policy reviews over offline materials."""
    req = request if isinstance(request, AuditRequest) else request_from_dict(request)

    ledger = _Ledger()
    anchor = _parse_material(
        req.trust_anchor.data,
        ledger,
        record_id="trust-anchor",
        source=req.trust_anchor.source,
        name="1.root.json",
        collected_at=req.trust_anchor.collected_at,
        is_anchor=True,
    )

    materials: list[_Material] = []
    for index, record in enumerate(req.records, start=1):
        record_id = record.record_id or f"record-{index}"
        materials.append(
            _parse_material(
                record.data,
                ledger,
                record_id=record_id,
                source=record.source,
                name=record.name,
                collected_at=record.collected_at,
                sequence=record.sequence,
                log_id=record.log_id,
            )
        )

    target_hash: str | None = None
    if req.target.data is not None:
        target_hash = ledger.add(req.target.data, "target-raw")

    request_dict = request_to_dict(req)
    request_digest = "sha256:" + _sha256(_canonical_bytes(request_dict))

    historical = _audit_view(
        mode="historical",
        reference_time=req.as_of,
        request=req,
        anchor=anchor,
        materials=materials,
        ledger=ledger,
        target_hash=target_hash,
    )
    current = _audit_view(
        mode="current",
        reference_time=req.current_time,
        request=req,
        anchor=anchor,
        materials=materials,
        ledger=ledger,
        target_hash=target_hash,
    )

    record_rows = [_record_row(item) for item in materials]
    report = AuditReport(
        schema_version=REPORT_SCHEMA,
        request_schema=REQUEST_SCHEMA,
        request_digest=request_digest,
        request_id=req.request_id,
        as_of=_iso(req.as_of),
        current_time=_iso(req.current_time),
        historical=historical,
        current=current,
        records=record_rows,
        evidence=ledger.evidence(),
    )
    report.report_hash = "sha256:" + _sha256(
        _canonical_bytes(report.to_dict(include_hash=False))
    )
    return report


def audit_dict(request: AuditRequest | dict[str, Any]) -> dict[str, Any]:
    """Convenience wrapper returning a JSON-serializable audit report."""
    return audit(request).to_dict()


def _record_row(material: _Material) -> dict[str, Any]:
    return {
        "record_id": material.record_id,
        "source": material.source,
        "name": material.name,
        "collected_at": _iso(material.collected_at)
        if material.collected_at is not None
        else None,
        "sequence": material.sequence,
        "log_id": material.log_id,
        "raw_sha256": material.raw_hash,
        "signed_sha256": material.signed_hash,
        "role": material.role,
        "version": material.version,
        "expires": _iso(material.expires) if material.expires else None,
        "parse_error": material.parse_reason.to_dict()
        if material.parse_reason
        else None,
    }


class _ViewAuditor:
    def __init__(
        self,
        *,
        mode: str,
        reference_time: datetime,
        req: AuditRequest,
        anchor: _Material,
        materials: list[_Material],
        target_hash: str | None,
    ) -> None:
        self.mode = mode
        self.reference_time = reference_time
        self.req = req
        self.anchor = anchor
        self.materials = materials
        self.target_hash = target_hash
        self.available: list[_Material] = []
        self.steps: list[Step] = []
        self.accepted: list[Reason] = []
        self.rejections: list[Reason] = []
        self.unprovable: list[Reason] = []
        self.warnings: list[Reason] = []
        self.excluded: list[dict[str, Any]] = []
        self.root_chain: list[dict[str, Any]] = []
        self.root_history: list[Root] = []
        self.final_root: Root | None = None
        self.final_root_mat: _Material | None = None
        self.timestamp_mat: _Material | None = None
        self.snapshot_mat: _Material | None = None
        self.targets_mat: _Material | None = None
        self.target_file: Any | None = None
        self.terminal: str | None = None
        self.completeness_unprovable = False
        self._reason_keys: set[tuple[str, ...]] = set()

    def run(self) -> dict[str, Any]:
        self._check_collection_log()
        self._verify_anchor()
        self._verify_root_chain()
        self._check_root_expiry()
        self._verify_timestamp()
        self._verify_snapshot()
        self._verify_targets_metadata()
        self._verify_target_artifact()

        if self.terminal is not None:
            verdict = self.terminal
        elif self.completeness_unprovable:
            verdict = "unprovable"
        else:
            verdict = "accepted"

        return {
            "mode": self.mode,
            "reference_time": _iso(self.reference_time),
            "verdict": verdict,
            "steps": [step.to_dict() for step in self.steps],
            "accepted_reasons": [item.to_dict() for item in self.accepted],
            "rejection_reasons": [item.to_dict() for item in self.rejections],
            "unprovable_reasons": [
                item.to_dict() for item in self.unprovable
            ],
            "warnings": [item.to_dict() for item in self.warnings],
            "excluded_records": self.excluded,
            "root_chain": self.root_chain,
        }

    def _add_step(self, step: Step) -> None:
        self.steps.append(step)
        for reason in step.reasons:
            key = (
                reason.code,
                reason.message,
                reason.severity,
                reason.evidence_hashes,
                _canonical_bytes(reason.details).decode("utf-8"),
            )
            if key in self._reason_keys:
                continue
            self._reason_keys.add(key)
            if reason.severity == "success":
                self.accepted.append(reason)
            elif reason.severity == "rejection":
                self.rejections.append(reason)
            elif reason.severity == "indeterminate":
                self.unprovable.append(reason)
            elif reason.severity == "warning":
                self.warnings.append(reason)

    def _skip(self, name: str, code: str, message: str) -> None:
        prerequisite: list[str] = []
        if self.final_root_mat is not None:
            prerequisite = [self.final_root_mat.raw_hash]
        step = Step(name, "skipped", prerequisite)
        step.reason(Reason(code, message, "info", tuple(prerequisite)))
        self._add_step(step)

    def _check_collection_log(self) -> None:
        step = Step("collection_log")
        self.available = []

        for material in self.materials:
            collected_at = material.collected_at
            if collected_at is not None and collected_at <= self.reference_time:
                self.available.append(material)
                continue

            collected_text = _iso(collected_at) if collected_at else None
            self.excluded.append(
                {
                    "record_id": material.record_id,
                    "raw_sha256": material.raw_hash,
                    "collected_at": collected_text,
                    "reason": "collected_after_reference_time",
                }
            )
            step.evidence(material.raw_hash)
            step.reason(
                Reason(
                    "future_material_excluded",
                    "Material collected after the review time was not used.",
                    "info",
                    (material.raw_hash,),
                    {
                        "record_id": material.record_id,
                        "collected_at": collected_text,
                        "reference_time": _iso(self.reference_time),
                    },
                )
            )

        by_hash: dict[str, list[_Material]] = {}
        for material in self.materials:
            by_hash.setdefault(material.raw_hash, []).append(material)

        for raw_hash, duplicates in sorted(by_hash.items()):
            times = {
                _iso(item.collected_at)
                for item in duplicates
                if item.collected_at is not None
            }
            if len(times) <= 1:
                continue

            crosses_cutoff = any(
                item in self.available for item in duplicates
            ) and any(item not in self.available for item in duplicates)
            severity = "indeterminate" if crosses_cutoff else "warning"
            if crosses_cutoff:
                step.status = "unverifiable"
                self.completeness_unprovable = True
            step.reason(
                Reason(
                    "conflicting_collection_times",
                    "Same raw metadata has conflicting collection times.",
                    severity,
                    (raw_hash,),
                    {"collection_times": sorted(times)},
                )
            )

        logs: dict[str, list[_Material]] = {}
        for material in self.available:
            if material.sequence is not None and material.log_id is not None:
                logs.setdefault(material.log_id, []).append(material)

        if not logs:
            step.reason(
                Reason(
                    "collection_sequence_absent",
                    "No sequence numbers were supplied; log completeness is not provable.",
                    "info",
                )
            )

        for log_id, entries in sorted(logs.items()):
            by_sequence: dict[int, list[_Material]] = {}
            for material in entries:
                if material.sequence is not None:
                    by_sequence.setdefault(material.sequence, []).append(material)

            sequences = sorted(by_sequence)
            for previous, current in zip(sequences, sequences[1:]):
                if current == previous + 1:
                    continue
                missing = list(range(previous + 1, current))
                step.status = "unverifiable"
                self.completeness_unprovable = True
                step.reason(
                    Reason(
                        "collection_log_gap",
                        "Collection log sequence is not contiguous.",
                        "indeterminate",
                        tuple(
                            item.raw_hash
                            for seq in (previous, current)
                            for item in by_sequence[seq]
                        ),
                        {
                            "log_id": log_id,
                            "previous_sequence": previous,
                            "next_sequence": current,
                            "missing_sequences": missing,
                        },
                    )
                )

            for sequence, group in sorted(by_sequence.items()):
                hashes = {item.raw_hash for item in group}
                if len(hashes) <= 1:
                    continue
                step.status = "unverifiable"
                self.completeness_unprovable = True
                step.reason(
                    Reason(
                        "conflicting_sequence_records",
                        "One collection sequence contains different raw records.",
                        "indeterminate",
                        tuple(sorted(hashes)),
                        {"log_id": log_id, "sequence": sequence},
                    )
                )

        self._add_step(step)


    def _role_result_details(self, result: Any) -> dict[str, Any]:
        return {
            "threshold": result.threshold,
            "signed_keyids": sorted(result.signed),
            "unsigned_keyids": sorted(result.unsigned),
            "missing": result.missing,
        }

    def _root_result_details(self, result: Any) -> dict[str, Any]:
        return {
            "previous_root": self._role_result_details(result.first),
            "new_root": self._role_result_details(result.second),
        }

    def _verify_anchor(self) -> None:
        if self.terminal is not None:
            self._skip("trust_anchor", "audit_stopped", "Earlier step failed.")
            return

        step = Step("trust_anchor")
        step.evidence(self.anchor.raw_hash, self.anchor.signed_hash)
        anchor_time = self.req.trust_anchor.collected_at
        if anchor_time is not None and anchor_time > self.reference_time:
            step.status = "unverifiable"
            step.reason(
                Reason(
                    "trust_anchor_not_available_at_reference_time",
                    "Trust anchor was not available at the review time.",
                    "indeterminate",
                    (self.anchor.raw_hash,),
                    {
                        "collected_at": _iso(anchor_time),
                        "reference_time": _iso(self.reference_time),
                    },
                )
            )
            self.terminal = "unprovable"
            self._add_step(step)
            return

        expected_pin = self.req.trust_anchor.sha256
        if expected_pin:
            pin = expected_pin.removeprefix("sha256:").lower()
            if pin != self.anchor.raw_hash:
                step.status = "failed"
                step.reason(
                    Reason(
                        "trust_anchor_pin_mismatch",
                        "Supplied trust anchor hash does not match the bytes.",
                        "rejection",
                        (self.anchor.raw_hash,),
                        {"expected_sha256": pin},
                    )
                )
                self.terminal = "rejected"
                self._add_step(step)
                return

        if self.anchor.parse_reason is not None or self.anchor.md is None:
            step.status = "failed"
            if self.anchor.parse_reason is not None:
                step.reason(self.anchor.parse_reason)
            self.terminal = "rejected"
            self._add_step(step)
            return

        root = cast("Root", self.anchor.md.signed)
        result = root.get_verification_result(
            Root.type,
            self.anchor.md.signed_bytes,
            self.anchor.md.signatures,
        )
        details = self._role_result_details(result)
        if not result.verified:
            step.status = "failed"
            step.reason(
                Reason(
                    "trust_anchor_self_signature_failed",
                    "Trust anchor does not meet its own root signature threshold.",
                    "rejection",
                    (self.anchor.raw_hash, self.anchor.signed_hash or ""),
                    details,
                )
            )
            self.terminal = "rejected"
            self._add_step(step)
            return

        step.reason(
            Reason(
                "trust_anchor_self_signed",
                "Trust anchor is parseable and self-signed by its root keys.",
                "success",
                (self.anchor.raw_hash, self.anchor.signed_hash or ""),
                details,
            )
        )
        self.final_root = root
        self.final_root_mat = self.anchor
        self.root_history = [root]
        self.root_chain.append(
            {
                "version": root.version,
                "source": self.anchor.source,
                "raw_sha256": self.anchor.raw_hash,
                "signed_sha256": self.anchor.signed_hash,
            }
        )
        self._add_step(step)


    def _verify_root_chain(self) -> None:
        if self.terminal is not None:
            self._skip("root_rotation", "audit_stopped", "Earlier step failed.")
            return
        if self.final_root is None or self.final_root_mat is None:
            return

        root_materials = [
            item
            for item in self.available
            if item.role == Root.type and item.md is not None
        ]
        max_version = max(
            (item.version or self.final_root.version for item in root_materials),
            default=self.final_root.version,
        )
        expected = self.final_root.version + 1

        while expected <= max_version:
            candidates = [
                item for item in root_materials if item.version == expected
            ]
            step = Step(f"root_v{expected}")
            if not candidates:
                higher = sorted(
                    {
                        item.version
                        for item in root_materials
                        if item.version is not None and item.version > expected
                    }
                )
                evidence = tuple(
                    item.raw_hash
                    for item in root_materials
                    if item.version in higher
                )
                step.status = "unverifiable"
                step.evidence(self.final_root_mat.raw_hash, *evidence)
                step.reason(
                    Reason(
                        "missing_intermediate_root",
                        "The sequential Root version needed for rotation is absent.",
                        "indeterminate",
                        evidence,
                        {"missing_version": expected, "higher_versions": higher},
                    )
                )
                step.reason(
                    Reason(
                        "discontinuous_root_chain",
                        "Available Root versions do not form a continuous chain.",
                        "indeterminate",
                        evidence,
                        {"expected_version": expected},
                    )
                )
                self.terminal = "unprovable"
                self._add_step(step)
                return

            valid: list[tuple[_Material, Any]] = []
            previous_root = self.final_root
            for material in candidates:
                if material.md is None or material.signed_hash is None:
                    continue
                step.evidence(material.raw_hash, material.signed_hash)
                new_root = cast("Root", material.md.signed)
                try:
                    result = new_root.get_root_verification_result(
                        previous_root,
                        material.md.signed_bytes,
                        material.md.signatures,
                    )
                except ValueError as exc:
                    step.reason(
                        Reason(
                            "root_verification_error",
                            str(exc),
                            "rejection",
                            (material.raw_hash, material.signed_hash),
                        )
                    )
                    continue

                details = self._root_result_details(result)
                if not result.first.verified:
                    step.reason(
                        Reason(
                            "root_previous_threshold_failed",
                            "New Root was not signed by enough keys from prior Root.",
                            "rejection",
                            (material.raw_hash, material.signed_hash),
                            details,
                        )
                    )
                if not result.second.verified:
                    step.reason(
                        Reason(
                            "root_new_threshold_failed",
                            "New Root was not signed by enough keys from new Root.",
                            "rejection",
                            (material.raw_hash, material.signed_hash),
                            details,
                        )
                    )
                if result.verified:
                    valid.append((material, result))

            if not valid:
                step.status = "failed"
                step.reason(
                    Reason(
                        "root_rotation_signature_failed",
                        "No candidate Root version satisfied both trust thresholds.",
                        "rejection",
                        tuple(item.raw_hash for item in candidates),
                        {"version": expected},
                    )
                )
                self.terminal = "rejected"
                self._add_step(step)
                return

            valid_payloads = {
                material.signed_hash for material, _ in valid
            }
            if len(valid_payloads) > 1:
                evidence = tuple(
                    sorted(
                        {
                            material.raw_hash
                            for material, _ in valid
                        }
                    )
                )
                step.status = "conflict"
                step.reason(
                    Reason(
                        "conflicting_root_records",
                        "Multiple distinct valid Root metadata files have one version.",
                        "indeterminate",
                        evidence,
                        {"version": expected, "signed_sha256": sorted(valid_payloads)},
                    )
                )
                self.terminal = "unprovable"
                self._add_step(step)
                return

            chosen, result = valid[0]
            chosen_root = cast("Root", chosen.md.signed)
            step.status = "passed"
            step.reason(
                Reason(
                    "root_version_verified",
                    "Root version is sequential and satisfies both rotation thresholds.",
                    "success",
                    (chosen.raw_hash, chosen.signed_hash or ""),
                    self._root_result_details(result),
                )
            )
            self._add_step(step)
            self.final_root = chosen_root
            self.final_root_mat = chosen
            self.root_history.append(chosen_root)
            self.root_chain.append(
                {
                    "version": chosen_root.version,
                    "source": chosen.source,
                    "record_id": chosen.record_id,
                    "raw_sha256": chosen.raw_hash,
                    "signed_sha256": chosen.signed_hash,
                }
            )
            expected += 1

    def _check_root_expiry(self) -> None:
        if self.terminal is not None:
            self._skip("root_validity", "audit_stopped", "Earlier step failed.")
            return
        if self.final_root is None or self.final_root_mat is None:
            return

        root = self.final_root
        material = self.final_root_mat
        step = Step("root_validity")
        step.evidence(material.raw_hash, material.signed_hash)
        if root.is_expired(self.reference_time):
            step.status = "failed"
            step.reason(
                Reason(
                    "root_expired",
                    "Final Root metadata is expired at the review time.",
                    "rejection",
                    (material.raw_hash, material.signed_hash or ""),
                    {
                        "root_version": root.version,
                        "expires": _iso(root.expires),
                        "reference_time": _iso(self.reference_time),
                    },
                )
            )
            self.terminal = "rejected"
        else:
            step.reason(
                Reason(
                    "root_valid_at_reference_time",
                    "Final Root version is within its signed validity interval.",
                    "success",
                    (material.raw_hash, material.signed_hash or ""),
                    {
                        "root_version": root.version,
                        "expires": _iso(root.expires),
                        "reference_time": _iso(self.reference_time),
                    },
                )
            )
        self._add_step(step)


    def _top_level_signature_ok(
        self, role: str, material: _Material, step: Step
    ) -> bool:
        if self.final_root is None or material.md is None:
            return False

        result = self.final_root.get_verification_result(
            role,
            material.md.signed_bytes,
            material.md.signatures,
        )
        if result.verified:
            return True

        final_keyids = set(self.final_root.roles[role].keyids)
        for keyid in sorted(material.md.signatures):
            if keyid in final_keyids:
                continue
            historically_authorized = any(
                role in old_root.roles
                and keyid in old_root.roles[role].keyids
                for old_root in self.root_history
            )
            if historically_authorized and self.mode == "current":
                code = "key_revoked_under_current_root"
                message = "Signing key was rotated out of the current Root."
            elif historically_authorized:
                code = "key_revoked_before_reference_time"
                message = "Signing key had already been revoked at review time."
            else:
                code = "signing_key_not_authorized"
                message = "Signing key is not authorized by Root."
            step.reason(
                Reason(
                    code,
                    message,
                    "rejection",
                    (material.raw_hash, material.signed_hash or ""),
                    {"role": role, "keyid": keyid},
                )
            )

        step.reason(
            Reason(
                "insufficient_signatures",
                "Metadata does not meet the configured signature threshold.",
                "rejection",
                (material.raw_hash, material.signed_hash or ""),
                self._role_result_details(result),
            )
        )
        return False

    def _verify_timestamp(self) -> None:
        if self.terminal is not None:
            self._skip("timestamp", "audit_stopped", "Earlier step failed.")
            return

        step = Step("timestamp")
        candidates = [
            item
            for item in self.available
            if item.role == Timestamp.type and item.md is not None
        ]
        for item in candidates:
            step.evidence(item.raw_hash, item.signed_hash)

        if not candidates:
            step.status = "unverifiable"
            step.reason(
                Reason(
                    "timestamp_metadata_missing",
                    "No collected Timestamp metadata is available.",
                    "indeterminate",
                )
            )
            self.terminal = "unprovable"
            self._add_step(step)
            return

        valid: list[_Material] = []
        for material in candidates:
            if self._top_level_signature_ok(Timestamp.type, material, step):
                valid.append(material)

        if not valid:
            step.status = "failed"
            step.reason(
                Reason(
                    "no_valid_timestamp_signature",
                    "No Timestamp record has a valid Root signature.",
                    "rejection",
                    tuple(h for item in candidates for h in (item.raw_hash,)),
                )
            )
            self.terminal = "rejected"
            self._add_step(step)
            return

        highest_version = max(item.version or 0 for item in valid)
        latest = [item for item in valid if item.version == highest_version]
        payloads = {item.signed_hash for item in latest}
        if len(payloads) > 1:
            step.status = "conflict"
            step.reason(
                Reason(
                    "conflicting_timestamp_records",
                    "Multiple valid Timestamp records have the same version.",
                    "indeterminate",
                    tuple(sorted(h for h in payloads if h is not None)),
                    {"version": highest_version},
                )
            )
            self.terminal = "unprovable"
            self._add_step(step)
            return

        material = latest[0]
        timestamp = cast("Timestamp", material.md.signed)
        if timestamp.is_expired(self.reference_time):
            step.status = "failed"
            step.reason(
                Reason(
                    "metadata_expired",
                    "Timestamp metadata has expired for the review time.",
                    "rejection",
                    (material.raw_hash, material.signed_hash or ""),
                    {
                        "role": Timestamp.type,
                        "version": timestamp.version,
                        "expires": _iso(timestamp.expires),
                        "reference_time": _iso(self.reference_time),
                        "collected_at": _iso(material.collected_at)
                        if material.collected_at
                        else None,
                    },
                )
            )
            self.terminal = "rejected"
            self._add_step(step)
            return

        step.status = "passed"
        step.reason(
            Reason(
                "timestamp_verified",
                "Timestamp is Root-signed, current by version, and unexpired.",
                "success",
                (material.raw_hash, material.signed_hash or ""),
                {
                    "version": timestamp.version,
                    "expires": _iso(timestamp.expires),
                    "snapshot_version": timestamp.snapshot_meta.version,
                },
            )
        )
        self.timestamp_mat = material
        self._add_step(step)


    def _verify_snapshot(self) -> None:
        if self.terminal is not None or self.timestamp_mat is None:
            self._skip("snapshot", "audit_stopped", "Timestamp was not verified.")
            return

        step = Step("snapshot")
        timestamp_md = self.timestamp_mat.md
        assert timestamp_md is not None
        timestamp = cast("Timestamp", timestamp_md.signed)
        meta = timestamp.snapshot_meta
        step.evidence(self.timestamp_mat.raw_hash, self.timestamp_mat.signed_hash)

        candidates = [
            item for item in self.available if item.role == Snapshot.type
        ]
        for item in candidates:
            step.evidence(item.raw_hash, item.signed_hash)

        exact = [item for item in candidates if item.version == meta.version]
        if not exact:
            if candidates:
                code = "snapshot_version_mismatch"
                status = "failed"
                severity = "rejection"
                message = "No snapshot matches the version signed by timestamp."
            else:
                code = "snapshot_metadata_missing"
                status = "unverifiable"
                severity = "indeterminate"
                message = "Snapshot metadata referenced by timestamp is missing."
            hashes = tuple(item.raw_hash for item in candidates)
            step.status = status
            step.reason(
                Reason(
                    code,
                    message,
                    severity,
                    hashes,
                    {
                        "expected_version": meta.version,
                        "available_versions": sorted(
                            item.version for item in candidates if item.version
                        ),
                    },
                )
            )
            self.terminal = "rejected" if status == "failed" else "unprovable"
            self._add_step(step)
            return

        valid: list[_Material] = []
        root = self.final_root
        assert root is not None
        for item in exact:
            if item.md is None or item.signed_hash is None:
                continue
            item_ok = True
            try:
                meta.verify_length_and_hashes(item.data)
            except LengthOrHashMismatchError as exc:
                item_ok = False
                step.reason(
                    Reason(
                        "snapshot_hash_mismatch",
                        f"Snapshot bytes do not match timestamp meta: {exc}",
                        "rejection",
                        (item.raw_hash, item.signed_hash),
                    )
                )

            result = root.get_verification_result(
                Snapshot.type,
                item.md.signed_bytes,
                item.md.signatures,
            )
            if not result.verified:
                item_ok = False
                self._add_signature_failure_reasons(step, Snapshot.type, item, result)

            snapshot = cast("Snapshot", item.md.signed)
            if snapshot.is_expired(self.reference_time):
                item_ok = False
                step.reason(
                    Reason(
                        "metadata_expired",
                        "Snapshot metadata is expired at the review time.",
                        "rejection",
                        (item.raw_hash, item.signed_hash),
                        {
                            "role": Snapshot.type,
                            "version": snapshot.version,
                            "expires": _iso(snapshot.expires),
                            "reference_time": _iso(self.reference_time),
                        },
                    )
                )

            if item_ok:
                valid.append(item)

        if not valid:
            step.status = "failed"
            step.reason(
                Reason(
                    "snapshot_verification_failed",
                    "No snapshot candidate passed hash, signature, and expiry checks.",
                    "rejection",
                    tuple(item.raw_hash for item in exact),
                )
            )
            self.terminal = "rejected"
            self._add_step(step)
            return

        payloads = {item.signed_hash for item in valid}
        if len(payloads) > 1:
            step.status = "conflict"
            step.reason(
                Reason(
                    "conflicting_snapshot_records",
                    "Multiple valid snapshot payloads have the same referenced version.",
                    "indeterminate",
                    tuple(h for h in payloads if h is not None),
                )
            )
            self.terminal = "unprovable"
            self._add_step(step)
            return

        chosen = valid[0]
        self.snapshot_mat = chosen
        step.status = "passed"
        step.reason(
            Reason(
                "snapshot_verified",
                "Snapshot hash, version, root signature, and expiry are valid.",
                "success",
                (chosen.raw_hash, chosen.signed_hash or ""),
            )
        )
        self._add_step(step)


    def _verify_targets_metadata(self) -> None:
        if self.terminal is not None:
            self._skip("targets", "audit_stopped", "Earlier verification failed.")
            return

        if self.snapshot_mat is None or self.final_root is None:
            self._skip("targets", "snapshot_unavailable", "No verified snapshot.")
            return

        step = Step("targets")
        snapshot = cast("Snapshot", self.snapshot_mat.md.signed)
        meta = snapshot.meta.get("targets.json")
        step.evidence(self.snapshot_mat.raw_hash, self.snapshot_mat.signed_hash)
        if meta is None:
            step.status = "failed"
            step.reason(
                Reason(
                    "targets_metadata_not_listed",
                    "Verified snapshot does not list targets.json.",
                    "rejection",
                    (self.snapshot_mat.raw_hash,),
                )
            )
            self.terminal = "rejected"
            self._add_step(step)
            return

        candidates = [
            item
            for item in self.available
            if item.role == Targets.type
            and item.md is not None
            and item.version == meta.version
            and item.name in (None, "targets.json")
        ]
        for material in candidates:
            step.evidence(material.raw_hash, material.signed_hash)

        if not candidates:
            step.status = "unverifiable"
            step.reason(
                Reason(
                    "targets_metadata_missing",
                    "Snapshot references a targets metadata version that was not collected.",
                    "indeterminate",
                    (self.snapshot_mat.raw_hash,),
                    {"expected_version": meta.version},
                )
            )
            self.terminal = "unprovable"
            self._add_step(step)
            return

        valid: list[_Material] = []
        for material in candidates:
            material_ok = True
            try:
                meta.verify_length_and_hashes(material.data)
            except LengthOrHashMismatchError as exc:
                material_ok = False
                step.reason(
                    Reason(
                        "targets_hash_mismatch",
                        f"Targets bytes do not match snapshot metadata: {exc}",
                        "rejection",
                        (material.raw_hash,),
                        {"expected_version": meta.version},
                    )
                )

            assert material.md is not None
            result = self.final_root.get_verification_result(
                Targets.type,
                material.md.signed_bytes,
                material.md.signatures,
            )
            if not result.verified:
                material_ok = False
                self._authorization_reasons(Targets.type, material, step)
                step.reason(
                    Reason(
                        "insufficient_targets_signatures",
                        "Targets metadata does not meet the root targets threshold.",
                        "rejection",
                        (material.raw_hash, material.signed_hash or ""),
                        self._role_result_details(result),
                    )
                )

            targets = cast("Targets", material.md.signed)
            if targets.is_expired(self.reference_time):
                material_ok = False
                step.reason(
                    Reason(
                        "metadata_expired",
                        "Targets metadata is expired at the review time.",
                        "rejection",
                        (material.raw_hash, material.signed_hash or ""),
                        {
                            "role": Targets.type,
                            "version": material.version,
                            "expires": _iso(targets.expires),
                            "reference_time": _iso(self.reference_time),
                            "collected_at": _iso(material.collected_at)
                            if material.collected_at
                            else None,
                        },
                    )
                )

            if material_ok:
                valid.append(material)

        if not valid:
            step.status = "failed"
            self.terminal = "rejected"
            self._add_step(step)
            return

        payload_hashes = {item.signed_hash for item in valid}
        if len(payload_hashes) > 1:
            step.status = "conflict"
            step.reason(
                Reason(
                    "conflicting_targets_records",
                    "Multiple distinct valid targets metadata records have the same version.",
                    "indeterminate",
                    tuple(h for h in payload_hashes if h is not None),
                    {"version": meta.version},
                )
            )
            self.terminal = "unprovable"
            self._add_step(step)
            return

        chosen = valid[0]
        self.targets_mat = chosen
        step.status = "passed"
        step.reason(
            Reason(
                "targets_verified",
                "Targets hash, version, root signature, and expiry are valid.",
                "success",
                (chosen.raw_hash, chosen.signed_hash or ""),
            )
        )
        self._add_step(step)

    def _verify_target_artifact(self) -> None:
        if self.terminal is not None:
            self._skip("target_artifact", "audit_stopped", "Earlier verification failed.")
            return
        if self.targets_mat is None:
            self._skip("target_artifact", "targets_unavailable", "No verified targets metadata.")
            return

        assert self.targets_mat.md is not None
        targets = cast("Targets", self.targets_mat.md.signed)
        step = Step("target_artifact")
        step.evidence(self.targets_mat.raw_hash, self.targets_mat.signed_hash, self.target_hash)
        target_file = targets.targets.get(self.req.target.path)
        if target_file is None:
            step.status = "failed"
            step.reason(
                Reason(
                    "target_path_not_found",
                    "Verified targets metadata does not list the requested target path.",
                    "rejection",
                    (self.targets_mat.raw_hash,),
                    {"target_path": self.req.target.path},
                )
            )
            self.terminal = "rejected"
            self._add_step(step)
            return

        step.details["expected_sha256"] = target_file.hashes.get("sha256")
        if self.req.target.data is None:
            if self.req.target.require_bytes:
                step.status = "unverifiable"
                step.reason(
                    Reason(
                        "target_bytes_missing",
                        "Target bytes were required but not supplied for offline hash replay.",
                        "indeterminate",
                        (self.targets_mat.raw_hash,),
                        {"target_path": self.req.target.path},
                    )
                )
                self.terminal = "unprovable"
            else:
                step.status = "passed"
                step.reason(
                    Reason(
                        "target_reference_confirmed",
                        "Signed targets metadata confirms the historical target hash.",
                        "success",
                        (self.targets_mat.raw_hash,),
                        {
                            "target_path": self.req.target.path,
                            "expected_sha256": target_file.hashes.get("sha256"),
                        },
                    )
                )
            self._add_step(step)
            return

        try:
            target_file.verify_length_and_hashes(self.req.target.data)
        except LengthOrHashMismatchError as exc:
            step.status = "failed"
            step.reason(
                Reason(
                    "target_hash_mismatch",
                    f"Supplied target bytes do not match signed targets metadata: {exc}",
                    "rejection",
                    (self.target_hash or "",),
                    {"target_path": self.req.target.path},
                )
            )
            self.terminal = "rejected"
            self._add_step(step)
            return

        step.status = "passed"
        step.reason(
            Reason(
                "target_hash_verified",
                "Supplied target bytes match the signed length and hashes.",
                "success",
                (self.target_hash or "", self.targets_mat.raw_hash),
                {"target_path": self.req.target.path},
            )
        )
        self._add_step(step)


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def request_to_dict(request: AuditRequest) -> dict[str, Any]:
    """Serialize an audit request to deterministic JSON-safe data."""
    anchor = request.trust_anchor
    target = request.target
    return {
        "schema": REQUEST_SCHEMA,
        "request_id": request.request_id,
        "as_of": _iso(request.as_of),
        "current_time": _iso(request.current_time),
        "trust_anchor": {
            "data_base64": _b64encode(anchor.data),
            "sha256": anchor.sha256,
            "collected_at": _iso(anchor.collected_at)
            if anchor.collected_at
            else None,
            "source": anchor.source,
        },
        "target": {
            "path": target.path,
            "data_base64": _b64encode(target.data)
            if target.data is not None
            else None,
            "require_bytes": target.require_bytes,
        },
        "records": [
            {
                "data_base64": _b64encode(record.data),
                "collected_at": _iso(record.collected_at),
                "record_id": record.record_id,
                "source": record.source,
                "sequence": record.sequence,
                "log_id": record.log_id,
                "name": record.name,
            }
            for record in request.records
        ],
    }


def _audit_view(*, mode, reference_time, request, anchor, materials, ledger, target_hash):
    return _ViewAuditor(mode=mode, reference_time=reference_time, req=request, anchor=anchor, materials=materials, target_hash=target_hash).run()


def _history_module_main():
    from tuf.api.history_codec import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_history_module_main())
