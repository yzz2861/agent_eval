"""Offline reconciliation for signed approvals and repository receipts."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, is_dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from securesystemslib import exceptions
from securesystemslib.dsse import Envelope
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import Key, Signature


class FindingCode(StrEnum):
    DEFINITE_EXCESS = "definite_excess"
    POSSIBLE_EXCESS = "possible_excess"
    POST_REVOCATION = "post_revocation_use"
    UNORDERABLE = "unorderable_use"
    REVOCATION_NO_ORDER = "revocation_without_order"
    DUPLICATE = "duplicate_delivery"
    ID_CONFLICT = "receipt_id_conflict"
    UNKNOWN_APPROVAL = "unknown_approval"
    UNKNOWN_ARTIFACT = "unknown_artifact"
    UNKNOWN_COVERAGE = "unknown_coverage"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_RECORD = "invalid_record"


class UseState(StrEnum):
    BEFORE_REVOCATION = "pre_revocation"
    AFTER_REVOCATION = "post_revocation"
    INDETERMINATE = "order_indeterminate"
    ACTIVE = "no_revocation"


def _mapping(value: Any) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        return {k: getattr(value, k) for k in value.__dataclass_fields__}
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError(f"expected mapping, got {type(value).__name__}")


def _norm_name(value: Any) -> str:
    return "".join(ch for ch in str(value).lower() if ch not in "_- ")


def _get(data: Mapping[str, Any], *names: str) -> Any:
    normalized = {_norm_name(k): v for k, v in data.items()}
    for name in names:
        if name in data:
            return data[name]
        key = _norm_name(name)
        if key in normalized:
            return normalized[key]
    return None


def _first(*values: Any) -> Any:
    return next((v for v in values if v is not None), None)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set, frozenset)) else [value]


def _canonical(value: Any) -> bytes:
    text = encode_canonical(value)
    if text is None:  # pragma: no cover
        raise exceptions.FormatError("cannot canonicalize record")
    return text.encode()


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _order_key(value: Any) -> tuple[str, Any] | None:  # noqa: PLR0911
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return ("number", value)
    if isinstance(value, datetime):
        return ("datetime", value.timestamp()) if value.tzinfo else ("naive", value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return ("number", int(text))
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            return (
                ("datetime", parsed.timestamp()) if parsed.tzinfo else ("naive", parsed)
            )
        return ("text", text) if text else None
    if isinstance(value, (list, tuple)):
        parts = [_order_key(v) for v in value]
        return ("tuple", tuple(parts)) if all(parts) else None
    return None


def _compare_order(left: Any, right: Any) -> int | None:
    a, b = _order_key(left), _order_key(right)
    if a is None or b is None or a[0] != b[0]:
        return None
    try:
        return 0 if a[1] == b[1] else (-1 if a[1] < b[1] else 1)
    except TypeError:
        return None


def _jsonable(value: Any) -> Any:  # noqa: PLR0911
    if isinstance(value, StrEnum):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(_mapping(value))
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(_jsonable(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    severity: str = "warning"
    approval_id: str | None = None
    artifact_id: str | None = None
    repository_id: str | None = None
    receipt_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: _jsonable(v) for k, v in _mapping(self).items()}


@dataclass(frozen=True)
class UnknownScope:
    scope_id: str
    repository_id: str | None
    complete: bool
    known_receipts: int
    additional_uses_min: int
    additional_uses_max: int | None
    reason: str
    segment_id: str | None = None
    approval_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {k: _jsonable(v) for k, v in _mapping(self).items()}
        data["unbounded"] = self.additional_uses_max is None
        return data


@dataclass
class Receipt:
    approval_id: str | None
    repository_id: str
    artifact_id: str
    receipt_id: str | None
    event_id: str | None
    order: Any
    fingerprint: str
    data: dict[str, Any]


@dataclass
class Consumption:
    event_key: str
    approval_id: str
    artifact_id: str
    state: UseState
    order: Any = None
    repositories: set[str] = field(default_factory=set)
    receipt_ids: set[str] = field(default_factory=set)
    duplicates: set[str] = field(default_factory=set)
    event_ids: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_key": self.event_key,
            "approval_id": self.approval_id,
            "artifact_id": self.artifact_id,
            "state": str(self.state),
            "order": _jsonable(self.order),
            "repositories": sorted(self.repositories),
            "repository_ids": sorted(self.repositories),
            "receipt_ids": sorted(self.receipt_ids),
            "duplicate_receipt_ids": sorted(self.duplicates),
            "duplicates": sorted(self.duplicates),
            "event_ids": sorted(self.event_ids),
            "reasons": self.reasons,
        }


@dataclass
class ApprovalLedger:
    approval_id: str
    quota: int
    basis: str = "artifact"
    revoked: bool = False
    revocation: dict[str, Any] | None = None
    consumptions: list[Consumption] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    unknown_scopes: list[UnknownScope] = field(default_factory=list)
    allowed_artifacts: set[str] | None = None

    @property
    def event_count(self) -> int:
        return len({x.event_key for x in self.consumptions})

    @property
    def artifact_count(self) -> int:
        return len({x.artifact_id for x in self.consumptions})

    @property
    def observed_uses(self) -> int:
        return self.event_count if self.basis == "event" else self.artifact_count

    @property
    def duplicate_count(self) -> int:
        return sum(len(x.duplicates) for x in self.consumptions)

    @property
    def definite_excess(self) -> int:
        return max(0, self.observed_uses - self.quota)

    excess = definite_excess

    @property
    def over_quota(self) -> bool:
        return self.definite_excess > 0

    @property
    def ambiguous_uses(self) -> int:
        return sum(item.state == UseState.INDETERMINATE for item in self.consumptions)

    @property
    def revoked_uses(self) -> int:
        return sum(
            item.state == UseState.AFTER_REVOCATION for item in self.consumptions
        )

    @property
    def authorized_uses(self) -> int:
        return sum(
            item.state in {UseState.ACTIVE, UseState.BEFORE_REVOCATION}
            for item in self.consumptions
        )

    def balance(self) -> dict[str, Any]:
        unknown_max: int | None = 0
        for scope in self.unknown_scopes:
            if scope.additional_uses_max is None:
                unknown_max = None
                break
            if unknown_max is not None:
                unknown_max += scope.additional_uses_max
        remaining = max(0, self.quota - self.observed_uses)
        worst = (
            None
            if unknown_max is None
            else max(0, self.observed_uses + unknown_max - self.quota)
        )
        return {
            "quota": self.quota,
            "basis": self.basis,
            "observed_uses": self.observed_uses,
            "used": self.observed_uses,
            "distinct_events": self.event_count,
            "distinct_artifacts": self.artifact_count,
            "duplicate_deliveries": self.duplicate_count,
            "duplicates": self.duplicate_count,
            "ambiguous_uses": self.ambiguous_uses,
            "post_revocation_uses": self.revoked_uses,
            "authorized_uses": self.authorized_uses,
            "remaining_before_unknown": remaining,
            "definite_excess": self.definite_excess,
            "excess": self.definite_excess,
            "over_quota": self.over_quota,
            "unknown_additional_uses_min": 0,
            "unknown_additional_uses_max": unknown_max,
            "worst_case_excess": worst,
            "possible_excess": self.definite_excess == 0
            and (unknown_max is None or worst > 0),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "quota": self.quota,
            "basis": self.basis,
            "revoked": self.revoked,
            "revocation": _jsonable(self.revocation),
            "balance": self.balance(),
            "consumptions": [x.to_dict() for x in self.consumptions],
            "findings": [x.to_dict() for x in self.findings],
            "unknown_scopes": [x.to_dict() for x in self.unknown_scopes],
            "allowed_artifacts": sorted(self.allowed_artifacts)
            if self.allowed_artifacts
            else None,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


@dataclass
class ReconciliationReport:
    ledgers: dict[str, ApprovalLedger] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    unknown_scopes: list[UnknownScope] = field(default_factory=list)
    invalid_records: list[dict[str, Any]] = field(default_factory=list)
    verified_records: int = 0

    @property
    def ok(self) -> bool:
        return not self.invalid_records and not any(
            x.severity in {"error", "critical"} for x in self.findings
        )

    @property
    def definite_excess(self) -> int:
        return sum(ledger.definite_excess for ledger in self.ledgers.values())

    excess = definite_excess

    @property
    def over_quota(self) -> bool:
        return self.definite_excess > 0

    @property
    def complete(self) -> bool:
        unresolved = {
            FindingCode.UNORDERABLE,
            FindingCode.REVOCATION_NO_ORDER,
            FindingCode.POSSIBLE_EXCESS,
            FindingCode.UNKNOWN_COVERAGE,
        }
        unresolved_clear = not any(
            finding.code in unresolved for finding in self.findings
        )
        return self.ok and not self.unknown_scopes and unresolved_clear

    @property
    def status(self) -> str:  # noqa: PLR0911
        codes = {x.code for x in self.findings}
        if FindingCode.DEFINITE_EXCESS in codes:
            return "definite_excess"
        if self.invalid_records or FindingCode.INVALID_SIGNATURE in codes:
            return "invalid_records"
        if {
            FindingCode.UNKNOWN_APPROVAL,
            FindingCode.UNKNOWN_ARTIFACT,
            FindingCode.ID_CONFLICT,
        } & codes:
            return "invalid_input"
        if FindingCode.POST_REVOCATION in codes:
            return "revocation_violation"
        if FindingCode.UNORDERABLE in codes:
            return "order_indeterminate"
        if self.unknown_scopes:
            return "unknown_scope"
        return "within_quota"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "summary": {
                "approvals": len(self.ledgers),
                "definite_excess": self.definite_excess,
                "excess": self.definite_excess,
                "over_quota": self.over_quota,
                "complete": self.complete,
                "ok": self.ok,
                "findings": len(self.findings),
                "unknown_scopes": len(self.unknown_scopes),
                "invalid_records": len(self.invalid_records),
                "verified_records": self.verified_records,
            },
            "ledgers": {k: v.to_dict() for k, v in sorted(self.ledgers.items())},
            "findings": [x.to_dict() for x in self.findings],
            "unknown_scopes": [x.to_dict() for x in self.unknown_scopes],
            "invalid_records": _jsonable(self.invalid_records),
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def explain(self) -> str:
        lines = ["Offline consumption reconciliation"]
        known = set(self.ledgers)
        for approval_id, ledger in sorted(self.ledgers.items()):
            b = ledger.balance()
            upper = (
                "unbounded"
                if b["unknown_additional_uses_max"] is None
                else b["unknown_additional_uses_max"]
            )
            lines.append(
                f"- {approval_id}: quota={b['quota']} observed={b['observed_uses']} "
                f"duplicates={b['duplicate_deliveries']} "
                f"excess={b['definite_excess']} unknown_max={upper}"
            )
            for item in ledger.consumptions:
                repos = sorted(item.repositories)
                lines.append(
                    f"  * {item.artifact_id} {item.state} "
                    f"repos={repos} dup={len(item.duplicates)}"
                )
            for finding in ledger.findings:
                lines.append(f"  ! {finding.code}: {finding.message}")
            for scope in ledger.unknown_scopes:
                if scope.approval_id is None:
                    continue
                upper = (
                    "unbounded"
                    if scope.additional_uses_max is None
                    else scope.additional_uses_max
                )
                reason = scope.reason
                lines.append(
                    f"  ? unknown scope {scope.scope_id}: extra=[0,{upper}] {reason}"
                )
        for finding in self.findings:
            if finding.code == FindingCode.UNKNOWN_COVERAGE:
                continue
            if finding.approval_id is None or finding.approval_id not in known:
                lines.append(f"! {finding.code}: {finding.message}")
        for scope in self.unknown_scopes:
            upper = (
                "unbounded"
                if scope.additional_uses_max is None
                else scope.additional_uses_max
            )
            reason = scope.reason
            lines.append(
                f"? archive unknown scope {scope.scope_id}: extra=[0,{upper}] {reason}"
            )
        return "\n".join(lines)


def _failure(
    report: ReconciliationReport, kind: str, raw: Any, error: Exception | str
) -> None:
    report.invalid_records.append(
        {"kind": kind, "error": str(error), "record": _jsonable(raw)}
    )
    report.findings.append(
        Finding(
            FindingCode.INVALID_RECORD,
            f"{kind} could not be processed: {error}",
            "error",
            details={"kind": kind},
        )
    )


def _add_finding(
    report: ReconciliationReport,
    ledger: ApprovalLedger,
    finding: Finding,
) -> None:
    report.findings.append(finding)
    ledger.findings.append(finding)


def _approval_ref(data: Mapping[str, Any]) -> str | None:
    value = _get(
        data,
        "approval_id",
        "grant_id",
        "ticket_id",
        "allowance_id",
        "quota_id",
        "target_id",
        "signature_id",
        "approval",
        "grant",
    )
    return None if value is None else str(value)


def _approval_id(data: Mapping[str, Any]) -> str | None:
    value = _approval_ref(data)
    if value is None:
        value = _get(data, "id")
    return None if value is None else str(value)


def _normalize_approval(raw: Any) -> tuple[str, int, set[str] | None]:
    data = _mapping(raw)
    approval_id = _approval_id(data)
    if not approval_id:
        raise ValueError("approval is missing id")
    quota = _first(
        _get(data, "quota"),
        _get(data, "max_uses"),
        _get(data, "allowed_uses"),
        _get(data, "use_limit"),
        _get(data, "limit"),
        _get(data, "uses"),
        1,
    )
    if isinstance(quota, bool) or not isinstance(quota, int) or quota < 0:
        raise ValueError("quota must be a non-negative integer")
    allowed: set[str] | None = None
    raw_artifacts = _get(
        data, "allowed_artifacts", "artifact_ids", "artifacts", "artifact_allowlist"
    )
    if raw_artifacts is not None:
        allowed = set()
        for artifact in _as_list(raw_artifacts):
            if isinstance(artifact, Mapping):
                artifact_id = _artifact_id(artifact)
                if artifact_id:
                    allowed.add(artifact_id)
            elif artifact is not None:
                allowed.add(str(artifact))
    return approval_id, quota, allowed


def _artifact_id(data: Mapping[str, Any]) -> str:
    artifact = _get(data, "artifact", "artifact_identity", "subject")
    if isinstance(artifact, str):
        return artifact
    if isinstance(artifact, Mapping):
        value = _first(
            _get(artifact, "digest", "sha256", "hash"),
            _get(artifact, "artifact_id", "id", "uri", "name"),
        )
        if isinstance(value, Mapping):
            algorithm = _get(value, "algorithm") or "sha256"
            digest = _get(value, "digest", "value", "hex")
            if digest is not None:
                value = f"{algorithm}:{digest}"
        if value is not None:
            return str(value)
    value = _first(
        _get(data, "artifact_id"),
        _get(data, "artifact_digest"),
        _get(data, "digest"),
        _get(data, "sha256"),
        _get(data, "artifact_uri"),
        _get(data, "artifact_name"),
        _get(data, "name"),
    )
    if value is None:
        raise ValueError("receipt is missing artifact identity")
    if "sha256" in {_norm_name(k) for k in data} and ":" not in str(value):
        return f"sha256:{value}"
    return str(value)


def _normalize_receipt(raw: Any) -> Receipt:
    data = _mapping(raw)
    repository = _first(
        _get(data, "repository_id"),
        _get(data, "repo_id"),
        _get(data, "repository"),
        _get(data, "repo"),
        _get(data, "source"),
        _get(data, "origin"),
    )
    if repository is None:
        raise ValueError("receipt is missing repository id")
    receipt_id = _first(
        _get(data, "receipt_id"),
        _get(data, "delivery_id"),
        _get(data, "message_id"),
        _get(data, "id"),
    )
    event_id = _first(
        _get(data, "event_id"),
        _get(data, "use_id"),
        _get(data, "consumption_id"),
        _get(data, "nonce"),
    )
    order = _first(
        _get(data, "order"),
        _get(data, "sequence"),
        _get(data, "seq"),
        _get(data, "offset"),
        _get(data, "timestamp"),
        _get(data, "time"),
        _get(data, "occurred_at"),
        _get(data, "created_at"),
    )
    return Receipt(
        approval_id=_approval_ref(data),
        repository_id=str(repository),
        artifact_id=_artifact_id(data),
        receipt_id=None if receipt_id is None else str(receipt_id),
        event_id=None if event_id is None else str(event_id),
        order=order,
        fingerprint=_fingerprint(data),
        data=data,
    )


def _revocation_order(data: Mapping[str, Any] | None) -> Any:
    if data is None:
        return None
    return _first(
        _get(data, "order"),
        _get(data, "sequence"),
        _get(data, "revoked_at"),
        _get(data, "timestamp"),
    )


def _classify(
    order: Any, revocation: Mapping[str, Any] | None
) -> tuple[UseState, list[str]]:
    if revocation is None:
        return UseState.ACTIVE, ["no revocation"]
    compare = _compare_order(order, _revocation_order(revocation))
    if compare is None:
        return UseState.INDETERMINATE, [
            "use and revocation order is unavailable or incomparable"
        ]
    if compare < 0:
        return UseState.BEFORE_REVOCATION, ["use precedes revocation"]
    if compare > 0:
        return UseState.AFTER_REVOCATION, ["use follows revocation"]
    return UseState.INDETERMINATE, ["same order position is not a strict order"]


def _event_key(receipt: Receipt, basis: str = "artifact") -> str:
    if receipt.event_id is not None:
        return f"event:{receipt.event_id}"
    if basis == "artifact":
        return f"artifact:{receipt.approval_id}:{receipt.artifact_id}"
    return f"artifact-event:{receipt.artifact_id}:{receipt.fingerprint}"


def _coverage_scopes(coverage: Any, receipts: Sequence[Receipt]) -> list[UnknownScope]:
    if coverage is None:
        return []
    values = (
        list(coverage)
        if isinstance(coverage, Sequence) and not isinstance(coverage, (str, bytes))
        else [coverage]
    )
    counts: dict[str, int] = defaultdict(int)
    for receipt in receipts:
        counts[receipt.repository_id] += 1

    scopes: list[UnknownScope] = []
    for index, raw in enumerate(values):
        data = _mapping(raw)
        repository = _first(
            _get(data, "repository_id"),
            _get(data, "repo_id"),
            _get(data, "repository"),
            _get(data, "repo"),
        )
        repository_id = None if repository is None else str(repository)
        complete_value = _first(
            _get(data, "complete"), _get(data, "is_complete"), _get(data, "full")
        )
        partial = _first(_get(data, "partial"), _get(data, "segment_only"))
        complete = True if complete_value is None else bool(complete_value)
        if partial is not None:
            complete = not bool(partial)
        if complete:
            continue
        known = _first(_get(data, "observed_count"), _get(data, "known_receipts"))
        known_int = (
            int(known) if known is not None else counts.get(repository_id or "", 0)
        )
        missing = _first(
            _get(data, "missing_count"),
            _get(data, "missing"),
            _get(data, "unknown_count"),
        )
        total = _first(_get(data, "total_count"), _get(data, "total"))
        if missing is None and total is not None:
            try:
                missing = max(0, int(total) - known_int)
            except (TypeError, ValueError):
                missing = None
        if missing is not None:
            try:
                missing = max(0, int(missing))
            except (TypeError, ValueError):
                missing = None
        segment_id = _first(
            _get(data, "segment_id"),
            _get(data, "cursor"),
            _get(data, "page"),
            _get(data, "id"),
        )
        approval_id = _approval_ref(data)
        scope_id = str(_first(_get(data, "scope_id"), segment_id, f"coverage-{index}"))
        reason = str(
            _first(
                _get(data, "reason"),
                _get(data, "note"),
                "partial segment; absence is not evidence",
            )
        )
        scopes.append(
            UnknownScope(
                scope_id=scope_id,
                repository_id=repository_id,
                segment_id=None if segment_id is None else str(segment_id),
                approval_id=approval_id,
                complete=False,
                known_receipts=known_int,
                additional_uses_min=0,
                additional_uses_max=missing,
                reason=reason,
                details=data,
            )
        )
    return scopes


def _records(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [value]
    return list(value)


_APPROVAL_KEYS = (
    "approvals",
    "grants",
    "approval_records",
    "quotas",
    "tickets",
    "permits",
)
_RECEIPT_KEYS = (
    "receipts",
    "usage_receipts",
    "consumption_receipts",
    "usages",
    "consumptions",
    "events",
)
_REVOCATION_KEYS = ("revocations", "cancellations", "revocation_records")
_COVERAGE_KEYS = (
    "coverage",
    "segments",
    "repository_reports",
    "repositories",
    "repo_reports",
    "partial_reports",
)


def _coverage_values(coverage: Any) -> list[Any]:
    if coverage is None:
        return []
    if isinstance(coverage, Sequence) and not isinstance(coverage, (str, bytes)):
        return list(coverage)
    return [coverage]


def _receipts_from_coverage(coverage: Any) -> list[Any]:
    receipts: list[Any] = []
    for raw_scope in _coverage_values(coverage):
        try:
            scope = _mapping(raw_scope)
        except TypeError:
            continue
        repository = _first(
            _get(scope, "repository_id"),
            _get(scope, "repo_id"),
            _get(scope, "repository"),
            _get(scope, "repo"),
        )
        nested = _first(
            _get(scope, "receipts"),
            _get(scope, "usage_receipts"),
            _get(scope, "consumption_receipts"),
            _get(scope, "entries"),
            _get(scope, "records"),
        )
        for raw_receipt in _as_list(nested):
            if isinstance(raw_receipt, Mapping) and repository is not None:
                item = dict(raw_receipt)
                has_repo = any(
                    _get(item, key) is not None
                    for key in ("repository_id", "repo_id", "repository", "repo")
                )
                if not has_repo:
                    item["repository_id"] = repository
                receipts.append(item)
            else:
                receipts.append(raw_receipt)
        for raw_segment in _as_list(_get(scope, "segments")):
            receipts.extend(_receipts_from_coverage(raw_segment))
    return receipts


def _extract_archive(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    archive_keys = (*_APPROVAL_KEYS, *_RECEIPT_KEYS, *_COVERAGE_KEYS)
    if any(_get(value, key) is not None for key in archive_keys):
        return dict(value)
    if _approval_ref(value) or _get(value, "quota", "max_uses") is not None:
        return None
    return None


def reconcile_consumption(  # noqa: PLR0912, PLR0915, PLR0913
    approvals: Any = None,
    receipts: Any = None,
    revocations: Iterable[Any] | None = None,
    coverage: Any | None = None,
    *,
    quota_basis: str = "artifact",
    segments: Any | None = None,
    repository_reports: Any | None = None,
    archive: Mapping[str, Any] | None = None,
) -> ReconciliationReport:
    if quota_basis not in {"artifact", "event"}:
        raise ValueError("quota_basis must be 'artifact' or 'event'")

    source = archive if archive is not None else _extract_archive(approvals)
    if source is not None:
        approvals = _first(*(_get(source, key) for key in _APPROVAL_KEYS)) or []
        if receipts is None:
            receipts = _first(*(_get(source, key) for key in _RECEIPT_KEYS)) or []
        if revocations is None:
            revocations = _first(*(_get(source, key) for key in _REVOCATION_KEYS))
        if coverage is None and segments is None and repository_reports is None:
            coverage = _first(*(_get(source, key) for key in _COVERAGE_KEYS))

    if isinstance(approvals, Mapping) and _extract_archive(approvals) is None:
        approvals = [approvals]
    if isinstance(receipts, Mapping):
        receipts = [receipts]
    if isinstance(revocations, Mapping):
        revocations = [revocations]

    report = ReconciliationReport()

    for raw in _records(approvals):
        try:
            approval_id, quota, allowed = _normalize_approval(raw)
        except Exception as error:
            _failure(report, "approval", raw, error)
            continue
        if approval_id in report.ledgers:
            _failure(report, "approval", raw, f"duplicate approval id {approval_id}")
            continue
        report.ledgers[approval_id] = ApprovalLedger(
            approval_id, quota, quota_basis, allowed_artifacts=allowed
        )

    revoked: dict[str, dict[str, Any]] = {}
    for raw in _records(revocations):
        try:
            data = _mapping(raw)
            approval_id = _approval_ref(data)
            if not approval_id:
                raise ValueError("revocation is missing approval id")
            current = revoked.get(approval_id)
            if current is None:
                revoked[approval_id] = data
                continue
            if (
                _compare_order(_revocation_order(data), _revocation_order(current))
                is not None
            ):
                if (
                    _compare_order(_revocation_order(data), _revocation_order(current))
                    >= 0
                ):
                    revoked[approval_id] = data
            elif _revocation_order(current) is None:
                revoked[approval_id] = data
        except Exception as error:
            _failure(report, "revocation", raw, error)

    coverage_input = _first(coverage, segments, repository_reports)
    receipt_values = [*_records(receipts), *_receipts_from_coverage(coverage_input)]

    normalized: list[Receipt] = []
    for raw in receipt_values:
        try:
            normalized.append(_normalize_receipt(raw))
        except Exception as error:
            _failure(report, "receipt", raw, error)

    report.unknown_scopes.extend(_coverage_scopes(coverage_input, normalized))
    by_approval: dict[str, list[Receipt]] = defaultdict(list)
    for receipt in normalized:
        if not receipt.approval_id or receipt.approval_id not in report.ledgers:
            report.findings.append(
                Finding(
                    FindingCode.UNKNOWN_APPROVAL,
                    "receipt does not reference a known valid approval",
                    "error",
                    artifact_id=receipt.artifact_id,
                    repository_id=receipt.repository_id,
                    receipt_id=receipt.receipt_id,
                    details={"approval_id": receipt.approval_id},
                )
            )
            continue
        by_approval[receipt.approval_id].append(receipt)

    for approval_id, ledger in report.ledgers.items():
        revocation = revoked.get(approval_id)
        if revocation is not None:
            ledger.revoked = True
            ledger.revocation = _jsonable(revocation)
            if _order_key(_revocation_order(revocation)) is None:
                _add_finding(
                    report,
                    ledger,
                    Finding(
                        FindingCode.REVOCATION_NO_ORDER,
                        "revocation is explicit but has no comparable order",
                        "warning",
                        approval_id,
                    ),
                )

        seen: dict[str, str] = {}
        events: dict[str, Consumption] = {}
        for receipt in by_approval.get(approval_id, []):
            delivery_key = receipt.receipt_id or f"fingerprint:{receipt.fingerprint}"
            is_duplicate = (
                receipt.receipt_id is not None and receipt.receipt_id in seen
            ) or (receipt.receipt_id is None and delivery_key in seen)
            if is_duplicate:
                previous_fingerprint = seen[delivery_key]
                if (
                    receipt.receipt_id is not None
                    and previous_fingerprint != receipt.fingerprint
                ):
                    _add_finding(
                        report,
                        ledger,
                        Finding(
                            FindingCode.ID_CONFLICT,
                            "same receipt id has different contents",
                            "error",
                            approval_id=approval_id,
                            receipt_id=receipt.receipt_id,
                            repository_id=receipt.repository_id,
                        ),
                    )
                    continue
                event_key = _event_key(receipt, quota_basis)
                state, reasons = _classify(receipt.order, revocation)
                consumption = events.setdefault(
                    event_key,
                    Consumption(
                        event_key,
                        approval_id,
                        receipt.artifact_id,
                        state,
                        receipt.order,
                        reasons=reasons,
                    ),
                )
                consumption.duplicates.add(
                    receipt.receipt_id or receipt.fingerprint[:16]
                )
                consumption.repositories.add(receipt.repository_id)
                _add_finding(
                    report,
                    ledger,
                    Finding(
                        FindingCode.DUPLICATE,
                        "same delivery was counted once",
                        "info",
                        approval_id=approval_id,
                        artifact_id=receipt.artifact_id,
                        repository_id=receipt.repository_id,
                        receipt_id=receipt.receipt_id,
                    ),
                )
                continue

            seen[delivery_key] = receipt.fingerprint
            event_key = _event_key(receipt, quota_basis)
            state, reasons = _classify(receipt.order, revocation)
            consumption = events.setdefault(
                event_key,
                Consumption(
                    event_key,
                    approval_id,
                    receipt.artifact_id,
                    state,
                    receipt.order,
                    reasons=reasons,
                ),
            )
            consumption.repositories.add(receipt.repository_id)
            if receipt.receipt_id:
                consumption.receipt_ids.add(receipt.receipt_id)
            if receipt.event_id:
                consumption.event_ids.add(receipt.event_id)
            if (
                ledger.allowed_artifacts is not None
                and receipt.artifact_id not in ledger.allowed_artifacts
            ):
                _add_finding(
                    report,
                    ledger,
                    Finding(
                        FindingCode.UNKNOWN_ARTIFACT,
                        "artifact is not covered by signed approval",
                        "error",
                        approval_id=approval_id,
                        artifact_id=receipt.artifact_id,
                        repository_id=receipt.repository_id,
                        receipt_id=receipt.receipt_id,
                    ),
                )

        ledger.consumptions.extend(
            sorted(events.values(), key=lambda item: (item.artifact_id, item.event_key))
        )
        for item in ledger.consumptions:
            if item.state == UseState.AFTER_REVOCATION:
                _add_finding(
                    report,
                    ledger,
                    Finding(
                        FindingCode.POST_REVOCATION,
                        "consumption is after explicit revocation",
                        "error",
                        approval_id=approval_id,
                        artifact_id=item.artifact_id,
                    ),
                )
            elif item.state == UseState.INDETERMINATE and revocation is not None:
                _add_finding(
                    report,
                    ledger,
                    Finding(
                        FindingCode.UNORDERABLE,
                        "consumption order relative to revocation is unknown",
                        "warning",
                        approval_id=approval_id,
                        artifact_id=item.artifact_id,
                    ),
                )

        if ledger.definite_excess:
            observed = ledger.observed_uses
            quota = ledger.quota
            excess = ledger.definite_excess
            _add_finding(
                report,
                ledger,
                Finding(
                    FindingCode.DEFINITE_EXCESS,
                    f"observed {observed} uses exceed quota {quota} by {excess}",
                    "critical",
                    approval_id=approval_id,
                    details={
                        "observed_uses": observed,
                        "quota": quota,
                        "excess": excess,
                    },
                ),
            )

        ledger.unknown_scopes.extend(
            scope
            for scope in report.unknown_scopes
            if scope.approval_id is None or scope.approval_id == approval_id
        )
        if ledger.balance()["possible_excess"]:
            _add_finding(
                report,
                ledger,
                Finding(
                    FindingCode.POSSIBLE_EXCESS,
                    "partial coverage may hide additional excess",
                    "warning",
                    approval_id=approval_id,
                    details=ledger.balance(),
                ),
            )

    for scope in report.unknown_scopes:
        report.findings.append(
            Finding(
                FindingCode.UNKNOWN_COVERAGE,
                scope.reason,
                "info",
                approval_id=scope.approval_id,
                repository_id=scope.repository_id,
                details=scope.to_dict(),
            )
        )
    return report


reconcile = reconcile_consumption
build_ledger = reconcile_consumption
ConsumptionLedger = ReconciliationReport
Ledger = ReconciliationReport
Reconciliation = ReconciliationReport


def _key_map(keys: Mapping[str, Key] | Sequence[Key]) -> dict[str, Key]:
    if isinstance(keys, Mapping):
        return dict(keys)
    return {key.keyid: key for key in keys}


def _signature(value: Signature | Mapping[str, Any]) -> Signature:
    if isinstance(value, Signature):
        return value
    data = dict(_mapping(value))
    if "sig" not in data and "signature" in data:
        data["sig"] = data.pop("signature")
    return Signature.from_dict(data)


def verify_signed_record(  # noqa: PLR0912
    record: Mapping[str, Any], keys: Mapping[str, Key] | Sequence[Key]
) -> tuple[Any, dict[str, Any]]:
    """Verify a simple canonical-JSON record or a DSSE envelope."""
    data = _mapping(record)
    key_map = _key_map(keys)

    if "payloadType" in data and "signatures" in data:
        envelope = Envelope.from_dict(copy.deepcopy(data))
        accepted = envelope.verify(list(key_map.values()), 1)
        try:
            payload: Any = json.loads(envelope.payload.decode())
        except Exception as error:
            raise exceptions.FormatError("DSSE payload is not JSON") from error
        return payload, {"accepted_keyids": sorted(accepted)}

    payload = _first(_get(data, "payload"), _get(data, "data"), _get(data, "signed"))
    signature_data = _first(
        _get(data, "signature"), _get(data, "signatures"), _get(data, "sig_record")
    )
    if payload is None or signature_data is None:
        raise exceptions.UnverifiedSignatureError(
            "record does not contain payload and signature"
        )

    if isinstance(payload, (bytes, bytearray)):
        payload_bytes = bytes(payload)
        try:
            payload_value: Any = json.loads(payload_bytes.decode())
        except Exception:
            payload_value = payload
    elif isinstance(payload, str):
        try:
            payload_value = json.loads(payload)
        except Exception:
            payload_value = payload
        payload_bytes = payload.encode()
    else:
        payload_value = dict(payload) if isinstance(payload, Mapping) else payload
        payload_bytes = _canonical(payload)

    signatures = (
        signature_data if isinstance(signature_data, list) else [signature_data]
    )
    last_error: Exception | None = None
    for raw_signature in signatures:
        signature = _signature(raw_signature)
        key = key_map.get(signature.keyid)
        if key is None:
            last_error = exceptions.UnverifiedSignatureError(
                f"no trusted key for {signature.keyid}"
            )
            continue
        try:
            key.verify_signature(signature, payload_bytes)
        except exceptions.UnverifiedSignatureError as error:
            last_error = error
            continue
        if isinstance(payload_value, dict):
            payload_value.setdefault("keyid", signature.keyid)
        return payload_value, {"accepted_keyids": [signature.keyid]}

    if last_error is None:
        last_error = exceptions.UnverifiedSignatureError(
            "record does not contain a usable signature"
        )
    raise last_error


def verify_signed_records(
    approvals: Iterable[Any],
    receipts: Iterable[Any] = (),
    revocations: Iterable[Any] | None = None,
    *,
    keys: Mapping[str, Key] | Sequence[Key],
) -> tuple[list[Any], list[Any], list[Any], list[dict[str, Any]]]:
    trusted_approvals: list[Any] = []
    trusted_receipts: list[Any] = []
    trusted_revocations: list[Any] = []
    invalid: list[dict[str, Any]] = []
    groups = (
        ("approval", approvals, trusted_approvals),
        ("receipt", receipts, trusted_receipts),
        ("revocation", revocations or [], trusted_revocations),
    )
    for kind, values, sink in groups:
        for raw in values:
            try:
                payload, _ = verify_signed_record(raw, keys)
                sink.append(payload)
            except Exception as error:
                invalid.append(
                    {"kind": kind, "error": str(error), "record": _jsonable(raw)}
                )
    return trusted_approvals, trusted_receipts, trusted_revocations, invalid


def reconcile_signed_archive(  # noqa: PLR0913
    *,
    keys: Mapping[str, Key] | Sequence[Key],
    approvals: Iterable[Any],
    receipts: Iterable[Any] = (),
    revocations: Iterable[Any] | None = None,
    coverage: Any | None = None,
    quota_basis: str = "artifact",
) -> ReconciliationReport:
    """Verify all signed records offline, then reconcile trusted payloads."""
    approvals, receipts, revocations, invalid = verify_signed_records(
        approvals, receipts, revocations, keys=keys
    )
    report = reconcile_consumption(
        approvals, receipts, revocations, coverage, quota_basis=quota_basis
    )
    report.invalid_records.extend(invalid)
    for item in invalid:
        report.findings.append(
            Finding(
                FindingCode.INVALID_SIGNATURE,
                f"{item['kind']} failed signature verification: {item['error']}",
                "error",
                details={"kind": item["kind"]},
            )
        )
    report.verified_records = len(approvals) + len(receipts) + len(revocations)
    return report


def reconcile_archive(
    archive: Mapping[str, Any] | None = None,
    keys: Mapping[str, Key] | Sequence[Key] | None = None,
    **kwargs: Any,
) -> ReconciliationReport:
    """Reconcile a whole archive mapping, verifying it when keys are supplied."""
    data = dict(archive) if isinstance(archive, Mapping) else {}
    approvals = kwargs.pop(
        "approvals",
        _first(*(_get(data, key) for key in _APPROVAL_KEYS)),
    )
    receipts = kwargs.pop(
        "receipts",
        _first(*(_get(data, key) for key in _RECEIPT_KEYS)),
    )
    revocations = kwargs.pop(
        "revocations",
        _first(*(_get(data, key) for key in _REVOCATION_KEYS)),
    )
    coverage = kwargs.pop(
        "coverage",
        _first(*(_get(data, key) for key in _COVERAGE_KEYS)),
    )
    if keys is not None:
        return reconcile_signed_archive(
            keys=keys,
            approvals=approvals or [],
            receipts=receipts or [],
            revocations=revocations,
            coverage=coverage,
            **kwargs,
        )
    return reconcile_consumption(
        approvals,
        receipts,
        revocations,
        coverage,
        **kwargs,
    )


class ConsumptionReconciler:
    """Incremental builder for an offline consumption reconciliation."""

    def __init__(  # noqa: PLR0913
        self,
        approvals: Iterable[Any] | None = None,
        receipts: Iterable[Any] | None = None,
        revocations: Iterable[Any] | None = None,
        coverage: Any | None = None,
        *,
        keys: Mapping[str, Key] | Sequence[Key] | None = None,
        quota_basis: str = "artifact",
    ) -> None:
        self.approvals = list(approvals or [])
        self.receipts = list(receipts or [])
        self.revocations = list(revocations or [])
        self.coverage = _coverage_values(coverage)
        self.keys = keys
        self.quota_basis = quota_basis

    def add_approval(self, approval: Any) -> ConsumptionReconciler:
        self.approvals.append(approval)
        return self

    add_grant = add_approval

    def add_receipt(self, receipt: Any) -> ConsumptionReconciler:
        self.receipts.append(receipt)
        return self

    add_usage_receipt = add_receipt

    def add_revocation(self, revocation: Any) -> ConsumptionReconciler:
        self.revocations.append(revocation)
        return self

    def add_coverage(self, report: Any) -> ConsumptionReconciler:
        self.coverage.extend(_coverage_values(report))
        return self

    add_segment = add_coverage
    add_partial_report = add_coverage
    add_repository_report = add_coverage

    def verify_with(
        self, keys: Mapping[str, Key] | Sequence[Key]
    ) -> ConsumptionReconciler:
        self.keys = keys
        return self

    def run(self) -> ReconciliationReport:
        if self.keys is not None:
            return reconcile_signed_archive(
                keys=self.keys,
                approvals=self.approvals,
                receipts=self.receipts,
                revocations=self.revocations,
                coverage=self.coverage,
                quota_basis=self.quota_basis,
            )
        return reconcile_consumption(
            self.approvals,
            self.receipts,
            self.revocations,
            self.coverage,
            quota_basis=self.quota_basis,
        )

    reconcile = run
    check = run
    build = run


Reconciler = ConsumptionReconciler
LedgerBuilder = ConsumptionReconciler
offline_consumption_check = reconcile_archive
verify_and_reconcile = reconcile_signed_archive
check_consumption = reconcile_archive
analyze_consumption = reconcile_archive
build_report = reconcile_archive
consumption_check = reconcile_archive
reconcile_signature_usage = reconcile_consumption
signature_usage_ledger = reconcile_consumption
usage_ledger = ReconciliationReport
