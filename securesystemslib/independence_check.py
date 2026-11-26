"""Offline independence checks for multi-group approval signatures."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from securesystemslib.signer import Key, Signature

INDEPENDENCE_SCHEMA_VERSION = "independence-audit/v1"


class IndependenceCheckError(ValueError):
    """Raised when audit evidence cannot be interpreted."""


IndependenceVerificationError = IndependenceCheckError


def canonical_json(value: Any) -> str:
    """Return deterministic JSON used for offline digests."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, set | tuple):
        return list(value)
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Object of type {type(value)!r} is not JSON serializable")


def sha256_digest(value: Any) -> str:
    """SHA-256 hex digest of canonical JSON or raw bytes/string."""
    if isinstance(value, bytes):
        encoded = value
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        encoded = canonical_json(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _first(mapping: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list | tuple | set):
        return list(value)
    return [value]


def _as_records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [
            {"id": key, **(item if isinstance(item, dict) else {"value": item})}
            for key, item in value.items()
        ]
    if isinstance(value, list | tuple):
        return [item for item in value if isinstance(item, dict)]
    raise IndependenceCheckError(f"expected records, got {type(value)!r}")


def _records(bundle: dict[str, Any], *names: str) -> list[dict[str, Any]]:
    for name in names:
        if bundle.get(name) is not None:
            return _as_records(bundle[name])
    return []


def parse_instant(value: Any) -> datetime | None:
    """Parse ISO-8601 text, datetime, or Unix timestamp into UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, int | float):
        parsed = datetime.fromtimestamp(value, tz=UTC)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise IndependenceCheckError(f"invalid timestamp {value!r}") from exc
    else:
        raise IndependenceCheckError(f"unsupported timestamp {type(value)!r}")

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def interval_contains(
    start: datetime | None, end: datetime | None, instant: datetime | None
) -> bool:
    """Half-open interval test; missing endpoints are unbounded."""
    if instant is None:
        return True
    if start is not None and instant < start:
        return False
    return end is None or instant < end


def interval_overlap(
    start_a: datetime | None,
    end_a: datetime | None,
    start_b: datetime | None,
    end_b: datetime | None,
) -> tuple[datetime | None, datetime | None] | None:
    starts = [item for item in (start_a, start_b) if item is not None]
    ends = [item for item in (end_a, end_b) if item is not None]
    start = max(starts) if starts else None
    end = min(ends) if ends else None
    if start is not None and end is not None and start >= end:
        return None
    return start, end


def _alias_key(value: Any) -> str:
    return " ".join(str(value).strip().lower().split())


def _payload_bytes(value: Any, encoding: str | None = None) -> bytes:
    if isinstance(value, bytes):
        return value
    if value is None:
        return b""
    if isinstance(value, dict | list):
        return canonical_json(value).encode("utf-8")

    text = str(value)
    codec = (encoding or "utf-8").lower().replace("-", "")
    if codec in {"base64", "b64"}:
        try:
            return base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise IndependenceCheckError("invalid base64 payload") from exc
    if codec == "hex":
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise IndependenceCheckError("invalid hex payload") from exc
    return text.encode("utf-8")


@dataclass
class Provenance:
    """Pointer to an offline source record for an evidence fact."""

    ref: str | None = None
    detail: str = ""
    locator: str | None = None
    sha256: str | None = None

    @classmethod
    def from_value(  # noqa: PLR0911
        cls, value: Any, context: str = "evidence"
    ) -> Provenance:
        if value is None or value == "":
            return cls(None, f"missing provenance for {context}")
        if isinstance(value, Provenance):
            return value
        if isinstance(value, list | tuple):
            if not value:
                return cls(None, f"missing provenance for {context}")
            return cls.from_value(value[0], context)
        if isinstance(value, str | int):
            return cls(str(value))
        if isinstance(value, dict):
            ref = _first(
                value,
                "ref",
                "source_ref",
                "provenance_ref",
                "source_id",
                "provenance_id",
                "id",
                "source",
            )
            if isinstance(ref, dict):
                nested = cls.from_value(ref, context)
                ref = nested.ref
            return cls(
                ref=None if ref is None else str(ref),
                detail=str(_first(value, "detail", "description", "note", default="")),
                locator=_first(value, "locator", "uri", "url", "path"),
                sha256=_first(value, "sha256", "digest", "content_sha256"),
            )
        return cls(str(value))

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"ref": self.ref, "detail": self.detail}
        if self.locator:
            result["locator"] = self.locator
        if self.sha256:
            result["sha256"] = self.sha256
        return result


@dataclass
class _FlowEdge:
    to: int
    rev: int
    cap: int


class _Dinic:
    def __init__(self, size: int) -> None:
        self.graph: list[list[_FlowEdge]] = [[] for _ in range(size)]

    def add_edge(self, source: int, target: int, capacity: int) -> _FlowEdge:
        forward = _FlowEdge(target, len(self.graph[target]), capacity)
        backward = _FlowEdge(source, len(self.graph[source]), 0)
        self.graph[source].append(forward)
        self.graph[target].append(backward)
        return forward

    def max_flow(self, source: int, sink: int) -> int:
        total = 0
        while True:
            level = [-1] * len(self.graph)
            level[source] = 0
            queue = [source]
            for node in queue:
                for edge in self.graph[node]:
                    if edge.cap > 0 and level[edge.to] < 0:
                        level[edge.to] = level[node] + 1
                        queue.append(edge.to)
            if level[sink] < 0:
                return total

            next_edge = [0] * len(self.graph)

            def dfs(node: int, pushed: int) -> int:
                if node == sink:
                    return pushed
                while next_edge[node] < len(self.graph[node]):
                    edge = self.graph[node][next_edge[node]]
                    if edge.cap > 0 and level[edge.to] == level[node] + 1:
                        sent = dfs(edge.to, min(pushed, edge.cap))
                        if sent:
                            edge.cap -= sent
                            self.graph[edge.to][edge.rev].cap += sent
                            return sent
                    next_edge[node] += 1
                return 0

            while sent := dfs(source, 10**9):
                total += sent


@dataclass
class AuditResult(dict[str, Any]):
    """JSON-compatible independence audit report."""

    schema_version: str
    ok: bool
    independence_verified: bool
    feasible: bool
    satisfiable: bool
    threshold_reachable: bool
    required_seats: int
    assigned_seats: int
    shortfall: int
    assignment: dict[str, list[dict[str, Any]]]
    group_reports: list[dict[str, Any]]
    candidates: list[dict[str, Any]]
    verification_results: list[dict[str, Any]]
    shared_principals: list[dict[str, Any]]
    time_overlaps: list[dict[str, Any]]
    provenance: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    absence: str = "none"
    absent: bool = False
    absences: list[dict[str, Any]] = field(default_factory=list)
    missing_independent_signoffs: int = 0
    valid: bool = False
    independent: bool = False
    success: bool = False
    inputs_digest: str = ""
    report_digest: str = ""
    attestation: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Populate the dict base so json.dumps(result) and Mapping-style
        # consumers see the same JSON-compatible report as to_dict().
        dict.update(self, self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __bool__(self) -> bool:
        return self.feasible


def _key_mapping(bundle: dict[str, Any]) -> dict[str, Any]:
    raw = _first(bundle, "public_keys", "keys", "verification_keys", default={})
    keys: dict[str, Any] = {}
    if isinstance(raw, dict):
        for keyid, value in raw.items():
            keys[str(keyid)] = value
    else:
        for value in _as_list(raw):
            if isinstance(value, Key):
                keys[value.keyid] = value
            elif isinstance(value, dict):
                keys[str(_first(value, "keyid", "key_id", "id"))] = value

    for epoch in _records(
        bundle,
        "key_history",
        "key_rotations",
        "key_ledger",
        "key_epochs",
        "key_lineage",
    ):
        keyid = str(_first(epoch, "keyid", "key_id", "id", default=""))
        public_key = epoch.get("public_key")
        if keyid and keyid not in keys and isinstance(public_key, dict):
            keys[keyid] = public_key
    return keys


def _normalize_groups(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    raw_groups = _first(
        bundle, "approval_groups", "groups", "approvals", "approval_teams", default=[]
    )
    if isinstance(raw_groups, dict):
        raw_groups = [
            {"id": key, **(value if isinstance(value, dict) else {})}
            for key, value in raw_groups.items()
        ]

    groups: list[dict[str, Any]] = []
    for raw in _as_records(raw_groups):
        group_id = str(_first(raw, "id", "group_id", "name", "team", default=""))
        signatures = _records(
            raw, "signatures", "candidates", "approvals", "signed_approvals", "votes"
        )
        groups.append(
            {
                "id": group_id,
                "threshold": max(
                    0,
                    int(
                        _first(
                            raw,
                            "threshold",
                            "required",
                            "required_signatures",
                            "min_signatures",
                            "quorum",
                            default=2,
                        )
                    ),
                ),
                "signatures": signatures,
            }
        )

    by_group = _first(
        bundle,
        "candidate_signatures_by_group",
        "signatures_by_group",
        "candidates_by_group",
        default={},
    )
    if isinstance(by_group, dict):
        existing = {group["id"]: group for group in groups}
        for raw_group_id, candidates in by_group.items():
            group_id = str(raw_group_id)
            records = _as_records(candidates)
            if group_id in existing:
                existing[group_id]["signatures"].extend(records)
            else:
                groups.append({"id": group_id, "threshold": 2, "signatures": records})

    top_level_candidates = _first(
        bundle, "candidate_signatures", "candidates", "signature_candidates", default=[]
    )
    if isinstance(top_level_candidates, dict):
        top_level_candidates = [
            {"group_id": gid, **(value if isinstance(value, dict) else {"sig": value})}
            for gid, value in top_level_candidates.items()
        ]
    for candidate in _as_records(top_level_candidates):
        group_id = str(
            _first(candidate, "group_id", "group", "approval_group", default="")
        )
        if not group_id:
            continue
        for group in groups:
            if group["id"] == group_id:
                group["signatures"].append(candidate)
                break
        else:
            groups.append({"id": group_id, "threshold": 2, "signatures": [candidate]})
    return groups


def verify_signature_results(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Verify candidate signatures using securesystemslib key verification."""
    keys = _key_mapping(bundle)
    default_payload = _first(bundle, "payload", "data", "message")
    default_encoding = _first(
        bundle, "payload_encoding", "data_encoding", default="utf-8"
    )
    results: list[dict[str, Any]] = []
    supplied_by_locator, supplied_by_keyid = _supplied_verification_maps(bundle)
    cryptographic_verification = bundle.get("verify_signatures", True)

    for group in _normalize_groups(bundle):
        for index, candidate in enumerate(group["signatures"]):
            keyid = str(_first(candidate, "keyid", "key_id", default=""))
            signature_hex = _first(
                candidate, "sig", "signature", "signature_hex", default=""
            )
            result: dict[str, Any] = {
                "group_id": group["id"],
                "index": index,
                "keyid": keyid,
                "valid": False,
            }
            supplied = candidate.get(
                "verification_result", candidate.get("verify_result")
            )
            supplied_result = _coerce_verification_result(supplied)
            if supplied_result is None and candidate.get("valid") is not None:
                supplied_result = {"valid": bool(candidate["valid"])}
            if supplied_result is None and candidate.get("verified") is not None:
                supplied_result = {"valid": bool(candidate["verified"])}
            if supplied_result is None:
                supplied_result = supplied_by_locator.get((group["id"], index))
            if supplied_result is None:
                supplied_result = supplied_by_keyid.get(keyid)
            if supplied_result is not None:
                result.update(supplied_result)
                result["valid"] = bool(supplied_result.get("valid"))
                result.setdefault("source", "supplied")

            if cryptographic_verification is False:
                if not result["valid"] and "error" not in result:
                    result["error"] = "no supplied successful verification result"
                results.append(result)
                continue

            key_value = keys.get(keyid)
            if key_value is None:
                if not result["valid"]:
                    result.update(
                        error_type="MissingPublicKey", error=f"no key for {keyid}"
                    )
                results.append(result)
                continue

            try:
                public_key = (
                    key_value
                    if isinstance(key_value, Key)
                    else Key.from_dict(keyid, _key_dict_without_id(key_value))
                )
                signature = _signature_object(candidate, keyid, signature_hex)
                payload_value = _first(
                    candidate,
                    "payload",
                    "data",
                    "message",
                    "signed_data",
                    default=default_payload,
                )
                encoding = _first(
                    candidate,
                    "payload_encoding",
                    "data_encoding",
                    default=default_encoding,
                )
                public_key.verify_signature(
                    signature, _payload_bytes(payload_value, encoding)
                )
                result.update(valid=True, error=None, verified_with="securesystemslib")
            except Exception as exc:
                result.update(
                    valid=False, error_type=type(exc).__name__, error=str(exc)
                )
            results.append(result)
    return results


def _coerce_verification_result(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return {"valid": value}
    if isinstance(value, dict) and "valid" in value:
        return dict(value)
    if isinstance(value, str):
        return {"valid": True, "keyid": value}
    return None


def _supplied_verification_maps(
    bundle: dict[str, Any],
) -> tuple[dict[tuple[str, int], dict[str, Any]], dict[str, dict[str, Any]]]:
    raw = _first(
        bundle,
        "verification_results",
        "signature_verification_results",
        "verified_signatures",
        default=[],
    )
    by_locator: dict[tuple[str, int], dict[str, Any]] = {}
    by_keyid: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for keyid, value in raw.items():
            result = _coerce_verification_result(value) or {"valid": True}
            by_keyid[str(keyid)] = result
        return by_locator, by_keyid

    for item in _as_list(raw):
        if isinstance(item, str):
            by_keyid[item] = {"valid": True, "keyid": item}
            continue
        if not isinstance(item, dict):
            continue
        result = _coerce_verification_result(item) or {"valid": True}
        keyid = result.get("keyid") or item.get("keyid") or item.get("key_id")
        if keyid:
            by_keyid[str(keyid)] = result
        group_id = item.get("group_id", item.get("group"))
        index = item.get("index", item.get("signature_index"))
        if group_id is not None and index is not None:
            by_locator[(str(group_id), int(index))] = result
    return by_locator, by_keyid


def _key_dict_without_id(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IndependenceCheckError(
            "public key must be a securesystemslib Key or dict"
        )
    key_dict = copy.deepcopy(value)
    key_dict.pop("keyid", None)
    key_dict.pop("key_id", None)
    return key_dict


def _signature_object(
    candidate: dict[str, Any], keyid: str, signature_hex: Any
) -> Signature:
    if isinstance(signature_hex, Signature):
        return signature_hex
    sig_dict = copy.deepcopy(candidate)
    for removed in (
        "payload",
        "data",
        "message",
        "signed_data",
        "payload_encoding",
        "data_encoding",
        "verification_result",
        "verify_result",
        "signed_at",
        "timestamp",
        "signed_time",
        "time",
        "kind",
        "signature_kind",
        "signoff_type",
        "label",
        "source",
        "provenance",
    ):
        sig_dict.pop(removed, None)
    sig_dict["keyid"] = keyid
    sig_dict.setdefault("sig", signature_hex)
    return Signature.from_dict(sig_dict)


def _source_registry(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = _first(bundle, "sources", "source_records", "provenance_records", default={})
    sources: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for source_id, value in raw.items():
            sources[str(source_id)] = (
                value if isinstance(value, dict) else {"detail": value}
            )
    for record in _as_records(raw):
        source_id = str(_first(record, "id", "source_id", "ref", default=""))
        if source_id:
            sources.setdefault(source_id, record)
    return sources


def _identity_index(
    bundle: dict[str, Any], missing: list[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[dict[str, Any]]]:
    principals: dict[str, dict[str, Any]] = {}
    aliases: dict[str, str] = {}
    alias_records: list[dict[str, Any]] = []

    def add_alias(alias_value: Any, principal_id: str, source_value: Any) -> None:
        if alias_value is None:
            return
        source = Provenance.from_value(source_value, f"alias {alias_value!r}")
        if source.ref is None:
            missing.append(f"alias {alias_value!r} -> {principal_id}")
        record = {
            "alias": str(alias_value),
            "normalized": _alias_key(alias_value),
            "principal_id": principal_id,
            "source": source.to_dict(),
        }
        alias_records.append(record)
        aliases[record["normalized"]] = principal_id

    for raw in _records(bundle, "principals", "persons", "employees", "identities"):
        principal_id = str(
            _first(raw, "id", "principal_id", "person_id", "employee_id", default="")
        )
        if not principal_id:
            continue
        principals[principal_id] = {
            "id": principal_id,
            "display_name": _first(
                raw, "display_name", "name", "full_name", default=principal_id
            ),
        }
        aliases[_alias_key(principal_id)] = principal_id
        aliases[_alias_key(principals[principal_id]["display_name"])] = principal_id
        for alias in _as_list(raw.get("aliases", raw.get("names"))):
            if isinstance(alias, dict):
                add_alias(
                    _first(alias, "alias", "name", "value"),
                    principal_id,
                    _first(alias, "source", "provenance"),
                )
            else:
                add_alias(alias, principal_id, None)

    raw_aliases = _first(
        bundle, "aliases", "identity_aliases", "person_aliases", default=[]
    )
    if isinstance(raw_aliases, dict):
        raw_aliases = [
            {
                "alias": alias,
                **(value if isinstance(value, dict) else {"principal_id": value}),
            }
            for alias, value in raw_aliases.items()
        ]
    for raw in _as_records(raw_aliases):
        principal_id = str(
            _first(
                raw,
                "principal_id",
                "person_id",
                "employee_id",
                "canonical_id",
                "identity_id",
                default="",
            )
        )
        alias_value = _first(raw, "alias", "name", "value", "alias_name")
        if not principal_id or alias_value is None:
            continue
        principals.setdefault(
            principal_id, {"id": principal_id, "display_name": principal_id}
        )
        add_alias(alias_value, principal_id, _first(raw, "source", "provenance"))

    for principal_id, principal in principals.items():
        aliases.setdefault(_alias_key(principal_id), principal_id)
        aliases.setdefault(_alias_key(principal["display_name"]), principal_id)
    return principals, aliases, alias_records


def _key_epochs(
    bundle: dict[str, Any],
    principals: dict[str, dict[str, Any]],
    missing: list[str],
) -> list[dict[str, Any]]:
    epochs: list[dict[str, Any]] = []
    for item in _records(
        bundle,
        "key_history",
        "key_rotations",
        "key_ledger",
        "key_epochs",
        "key_lineage",
    ):
        keyid = str(_first(item, "keyid", "key_id", "id", default=""))
        principal_value = _first(
            item,
            "principal_id",
            "owner_id",
            "holder_id",
            "employee_id",
            "principal",
            "owner",
            "holder",
        )
        source = Provenance.from_value(
            _first(item, "source", "provenance"), f"key {keyid}"
        )
        if source.ref is None:
            missing.append(f"key_history {keyid}")
        epochs.append(
            {
                "keyid": keyid,
                "principal_value": principal_value,
                "valid_from": parse_instant(
                    _first(item, "valid_from", "start", "not_before", "active_from")
                ),
                "valid_to": parse_instant(
                    _first(item, "valid_to", "end", "not_after", "active_until")
                ),
                "predecessor_keyid": _first(
                    item, "predecessor_keyid", "previous_keyid", "rotates_from"
                ),
                "successor_keyid": _first(
                    item, "successor_keyid", "next_keyid", "rotates_to"
                ),
                "source": source.to_dict(),
            }
        )
    return epochs


def _resolve_principal(
    value: str | None,
    aliases: dict[str, str],
    principals: dict[str, dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    if value is None:
        return None, None
    text = str(value)
    if text in principals:
        return text, None
    normalized = _alias_key(text)
    if normalized in aliases:
        return aliases[normalized], {"alias": text, "normalized": normalized}
    for principal_id, principal in principals.items():
        if normalized == _alias_key(principal.get("display_name")):
            return principal_id, {"alias": text, "normalized": normalized}
    principals.setdefault(text, {"id": text, "display_name": text})
    return text, {"alias": text, "normalized": normalized, "implicit_identifier": True}


def _principal_for_key(
    keyid: str,
    signed_at: datetime | None,
    epochs: list[dict[str, Any]],
    aliases: dict[str, str],
    principals: dict[str, dict[str, Any]],
) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
    evidence: list[dict[str, Any]] = []
    alias_evidence: list[dict[str, Any]] = []
    principal_ids: set[str] = set()

    for epoch in epochs:
        if epoch["keyid"] != keyid:
            continue
        active = interval_contains(epoch["valid_from"], epoch["valid_to"], signed_at)
        principal_id, alias_match = _resolve_principal(
            epoch["principal_value"], aliases, principals
        )
        item = {
            "keyid": keyid,
            "active_at_signature_time": active,
            "valid_from": epoch["valid_from"].isoformat()
            if epoch["valid_from"]
            else None,
            "valid_to": epoch["valid_to"].isoformat() if epoch["valid_to"] else None,
            "predecessor_keyid": epoch["predecessor_keyid"],
            "successor_keyid": epoch["successor_keyid"],
            "source": epoch["source"],
            "principal_id": None,
        }
        evidence.append(item)
        if active and principal_id:
            principal_ids.add(principal_id)
            item["principal_id"] = principal_id
            if alias_match:
                alias_evidence.append(
                    {
                        "used": epoch["principal_value"],
                        "resolved_principal_id": principal_id,
                        **alias_match,
                    }
                )

    if len(principal_ids) == 1:
        return next(iter(principal_ids)), evidence, alias_evidence
    return None, evidence, alias_evidence


def _shifts(
    bundle: dict[str, Any],
    principals: dict[str, dict[str, Any]],
    missing: list[str],
) -> list[dict[str, Any]]:
    shifts: list[dict[str, Any]] = []

    def add_shift(raw: dict[str, Any], principal_value: Any, default_kind: str) -> None:
        if principal_value is None:
            return
        group_id = str(
            _first(raw, "group_id", "group", "approval_group", "team", default="*")
        )
        principal_id = str(
            principal_value.get("id", principal_value)
            if isinstance(principal_value, dict)
            else principal_value
        )
        principals.setdefault(
            principal_id, {"id": principal_id, "display_name": principal_id}
        )
        source = Provenance.from_value(
            _first(raw, "source", "provenance", "roster_source"),
            f"shift {principal_id}@{group_id}",
        )
        if source.ref is None:
            missing.append(f"shift {principal_id}@{group_id}")
        kind = str(
            _first(raw, "kind", "type", "assignment_type", default=default_kind)
        ).lower()
        substitute_for = _first(
            raw, "substitute_for", "absent_principal_id", "covers", "replaced_id"
        )
        shifts.append(
            {
                "group_id": group_id,
                "principal_id": principal_id,
                "start": parse_instant(
                    _first(raw, "start", "starts_at", "valid_from", "from")
                ),
                "end": parse_instant(
                    _first(raw, "end", "ends_at", "valid_to", "to", "until")
                ),
                "kind": kind,
                "substitute_for": None
                if substitute_for is None
                else str(substitute_for),
                "source": source.to_dict(),
            }
        )

    for raw in _records(
        bundle,
        "shifts",
        "rotations",
        "roster",
        "duty_periods",
        "on_call",
        "assignments",
    ):
        members = _first(raw, "members", "on_call", "staff")
        if members is not None:
            for member in _as_list(members):
                add_shift(raw, member, "rotation")
        else:
            add_shift(
                raw,
                _first(
                    raw,
                    "principal_id",
                    "person_id",
                    "employee_id",
                    "on_call_id",
                    "principal",
                    "person",
                    "employee",
                ),
                "rotation",
            )

    for raw in _records(
        bundle,
        "substitutions",
        "substitute_assignments",
        "cover_assignments",
        "acting_assignments",
    ):
        add_shift(
            raw,
            _first(
                raw,
                "substitute_id",
                "acting_principal_id",
                "cover_id",
                "principal_id",
                "person_id",
                "employee_id",
            ),
            "substitute",
        )
    return shifts


def _matching_shifts(
    group_id: str,
    principal_id: str,
    signed_at: datetime | None,
    shifts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    matches = []
    for index, shift in enumerate(shifts):
        if shift["principal_id"] != principal_id:
            continue
        if shift["group_id"] not in {group_id, "*", "all", "shared_on_call"}:
            continue
        if not interval_contains(shift["start"], shift["end"], signed_at):
            continue
        matches.append(
            {
                "shift_index": index,
                "group_id": shift["group_id"],
                "kind": shift["kind"],
                "substitute_for": shift["substitute_for"],
                "start": shift["start"].isoformat() if shift["start"] else None,
                "end": shift["end"].isoformat() if shift["end"] else None,
                "source": shift["source"],
            }
        )
    return matches


def _find_overlaps(shifts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    overlaps = []
    for i, first in enumerate(shifts):
        for j in range(i + 1, len(shifts)):
            second = shifts[j]
            if first["principal_id"] != second["principal_id"]:
                continue
            if first["group_id"] == second["group_id"]:
                continue
            overlap = interval_overlap(
                first["start"], first["end"], second["start"], second["end"]
            )
            if overlap is None:
                continue
            start, end = overlap
            sources = [first["source"], second["source"]]
            refs = sorted({source["ref"] for source in sources if source.get("ref")})
            overlaps.append(
                {
                    "principal_id": first["principal_id"],
                    "shift_indexes": [i, j],
                    "group_ids": sorted({first["group_id"], second["group_id"]}),
                    "overlap_start": start.isoformat() if start else None,
                    "overlap_end": end.isoformat() if end else None,
                    "sources": sources,
                    "source_refs": refs,
                }
            )
    return overlaps


def _solve_assignment(
    groups: list[dict[str, Any]],
    candidate_principals: dict[str, list[str]],
    candidates: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int], int]:
    group_ids = [group["id"] for group in groups]
    thresholds = {group["id"]: max(0, int(group["threshold"])) for group in groups}
    person_ids = sorted({p for ps in candidate_principals.values() for p in ps})

    source_node = 0
    group_nodes = {gid: i + 1 for i, gid in enumerate(group_ids)}
    person_offset = len(group_ids) + 1
    person_nodes = {pid: person_offset + i for i, pid in enumerate(person_ids)}
    sink = person_offset + len(person_ids)
    network = _Dinic(sink + 1)

    for gid in group_ids:
        network.add_edge(source_node, group_nodes[gid], thresholds[gid])
    assignment_edges = []
    for gid in group_ids:
        for pid in candidate_principals.get(gid, []):
            edge = network.add_edge(group_nodes[gid], person_nodes[pid], 1)
            assignment_edges.append((gid, pid, edge))
    for pid in person_ids:
        network.add_edge(person_nodes[pid], sink, 1)

    assigned_seats = network.max_flow(source_node, sink)
    lookup = {
        (item["group_id"], item["principal_id"]): item
        for item in candidates
        if item.get("principal_id")
    }
    assignment: dict[str, list[dict[str, Any]]] = {gid: [] for gid in group_ids}
    for gid, pid, edge in assignment_edges:
        if edge.cap != 0:
            continue
        candidate = lookup.get((gid, pid), {})
        assignment[gid].append(
            {
                "principal_id": pid,
                "keyid": candidate.get("keyid"),
                "signature_index": candidate.get("signature_index"),
                "signed_at": candidate.get("signed_at"),
                "provenance_refs": sorted(set(candidate.get("provenance_refs", []))),
            }
        )
    for gid in group_ids:
        assignment[gid].sort(
            key=lambda item: (item["principal_id"], item.get("keyid") or "")
        )
    counts = {gid: len(items) for gid, items in assignment.items()}
    return assignment, counts, assigned_seats


def audit_independence(  # noqa: PLR0912, PLR0915
    bundle: dict[str, Any],
) -> AuditResult:
    """Verify signatures and compute a globally independent assignment."""
    if not isinstance(bundle, dict):
        raise IndependenceCheckError("bundle must be a dict")

    missing: list[str] = []
    warnings: list[str] = []
    inputs_digest = sha256_digest(bundle)
    sources = _source_registry(bundle)
    principals, aliases, alias_records = _identity_index(bundle, missing)
    epochs = _key_epochs(bundle, principals, missing)
    shifts = _shifts(bundle, principals, missing)
    groups = _normalize_groups(bundle)
    verification = verify_signature_results(bundle)
    verification_lookup = {
        (item["group_id"], item["index"]): item for item in verification
    }

    candidate_rows: list[dict[str, Any]] = []
    candidate_principals: dict[str, list[str]] = {g["id"]: [] for g in groups}

    for group in groups:
        seen: set[str] = set()
        for index, raw_signature in enumerate(group["signatures"]):
            verified = verification_lookup[(group["id"], index)]
            keyid = str(verified.get("keyid") or "")
            signed_at = parse_instant(
                _first(raw_signature, "signed_at", "timestamp", "signed_time", "time")
                or bundle.get("signed_at")
                or bundle.get("as_of")
            )
            row: dict[str, Any] = {
                "group_id": group["id"],
                "signature_index": index,
                "keyid": keyid,
                "signed_at": signed_at.isoformat() if signed_at else None,
                "signature_valid": bool(verified.get("valid")),
                "principal_id": None,
                "eligible": False,
                "reasons": [],
                "alias_evidence": [],
                "key_evidence": [],
                "shift_evidence": [],
                "provenance_refs": [],
            }
            if verified.get("error"):
                row["verification_error"] = verified["error"]
            if not verified.get("valid"):
                row["reasons"].append("signature_invalid")

            principal_id, key_evidence, alias_evidence = _principal_for_key(
                keyid, signed_at, epochs, aliases, principals
            )
            if principal_id is None:
                direct_value = _first(
                    raw_signature,
                    "principal_id",
                    "person_id",
                    "employee_id",
                    "signer_id",
                    "owner_id",
                    "principal",
                    "signer",
                    "owner",
                )
                principal_id, direct_alias = _resolve_principal(
                    None if direct_value is None else str(direct_value),
                    aliases,
                    principals,
                )
                if direct_alias:
                    alias_evidence.append(
                        {
                            "used": direct_value,
                            "resolved_principal_id": principal_id,
                            **direct_alias,
                        }
                    )
            row["key_evidence"] = key_evidence
            row["alias_evidence"] = alias_evidence
            for evidence in key_evidence:
                ref = evidence.get("source", {}).get("ref")
                if ref:
                    row["provenance_refs"].append(ref)
            for evidence in alias_evidence:
                # Alias source is attached to matching alias records below.
                normalized = evidence.get("normalized")
                for record in alias_records:
                    if record.get("normalized") == normalized:
                        ref = record.get("source", {}).get("ref")
                        if ref:
                            row["provenance_refs"].append(ref)

            if principal_id is None:
                row["reasons"].append("no_active_key_history")
            else:
                row["principal_id"] = principal_id
                row["principal_display_name"] = principals.get(principal_id, {}).get(
                    "display_name"
                )
                matches = _matching_shifts(group["id"], principal_id, signed_at, shifts)
                row["shift_evidence"] = matches
                for match in matches:
                    ref = match.get("source", {}).get("ref")
                    if ref:
                        row["provenance_refs"].append(ref)
                if not matches:
                    row["reasons"].append("no_matching_duty_period")
                if verified.get("valid") and matches:
                    row["eligible"] = True
                    if principal_id not in seen:
                        seen.add(principal_id)
                        candidate_principals[group["id"]].append(principal_id)

            if signed_at is None:
                warnings.append(f"{group['id']}[{index}] has no signed_at")
            candidate_rows.append(row)

    for gid, principals in candidate_principals.items():
        candidate_principals[gid] = sorted(set(principals))

    assignment, counts, assigned_seats = _solve_assignment(
        groups, candidate_principals, candidate_rows
    )
    required_seats = sum(group["threshold"] for group in groups)
    shortfall = max(0, required_seats - assigned_seats)
    feasible = shortfall == 0
    absence = "independent_signoff_absent" if shortfall else "none"
    overlaps = _find_overlaps(shifts)
    _attach_overlap_attestations(bundle, overlaps, missing)
    shared = _shared_principals(candidate_principals, overlaps, assignment)
    dangling = _dangling_sources(sources, epochs, shifts, alias_records, overlaps)
    provenance_complete = not missing and not dangling
    invalid_count = sum(1 for item in verification if not item["valid"])
    if invalid_count:
        warnings.append(f"{invalid_count} signature(s) failed verification")

    group_reports = _group_reports(
        groups, candidate_principals, counts, assignment, candidate_rows
    )
    shared_ids = {person["principal_id"] for person in shared}
    absences = [
        {
            "group_id": report["group_id"],
            "shortfall": report["shortfall"],
            "kind": "independent_signoff_absent",
            "blocking_shared_principal_ids": [
                principal_id
                for principal_id in report["eligible_principals"]
                if principal_id in shared_ids
            ],
        }
        for report in group_reports
        if report["shortfall"] > 0
    ]
    provenance_report = {
        "complete": provenance_complete,
        "missing": sorted(set(missing)),
        "dangling_refs": sorted(dangling),
        "sources": sources,
    }
    errors = sorted(
        set(missing + [f"dangling provenance ref: {ref}" for ref in dangling])
    )
    verified = feasible and provenance_complete and invalid_count == 0 and not errors

    digest_body = {
        "schema_version": INDEPENDENCE_SCHEMA_VERSION,
        "feasible": feasible,
        "valid": verified,
        "independent": verified,
        "success": verified,
        "required_seats": required_seats,
        "assigned_seats": assigned_seats,
        "shortfall": shortfall,
        "absence": absence,
        "absent": shortfall > 0,
        "absences": absences,
        "missing_independent_signoffs": shortfall,
        "assignment": assignment,
        "group_reports": group_reports,
        "candidates": candidate_rows,
        "verification_results": verification,
        "shared_principals": shared,
        "time_overlaps": overlaps,
        "provenance": provenance_report,
        "errors": errors,
        "warnings": sorted(set(warnings)),
        "inputs_digest": inputs_digest,
    }
    report_digest = sha256_digest(digest_body)
    attestation = {
        "schema_version": INDEPENDENCE_SCHEMA_VERSION,
        "algorithm": "sha256",
        "inputs_digest": inputs_digest,
        "report_digest": report_digest,
        "offline_recomputable": True,
    }
    return AuditResult(
        schema_version=INDEPENDENCE_SCHEMA_VERSION,
        ok=verified,
        independence_verified=verified,
        feasible=feasible,
        satisfiable=feasible,
        threshold_reachable=feasible,
        required_seats=required_seats,
        assigned_seats=assigned_seats,
        shortfall=shortfall,
        assignment=assignment,
        group_reports=group_reports,
        candidates=candidate_rows,
        verification_results=verification,
        shared_principals=shared,
        time_overlaps=overlaps,
        provenance=provenance_report,
        errors=errors,
        warnings=sorted(set(warnings)),
        absence=absence,
        absent=shortfall > 0,
        absences=absences,
        missing_independent_signoffs=shortfall,
        valid=verified,
        independent=verified,
        success=verified,
        inputs_digest=inputs_digest,
        report_digest=report_digest,
        attestation=attestation,
    )


_BUNDLE_KWARG_ALIASES = {
    "persons": "principals",
    "people": "principals",
    "employees": "principals",
    "identities": "principals",
    "personnel": "principals",
    "people_records": "principals",
    "roster": "shifts",
    "rotations": "shifts",
    "personnel_rotations": "shifts",
    "staff_rotations": "shifts",
    "duty_roster": "shifts",
    "duty_periods": "shifts",
    "on_call": "shifts",
    "key_rotations": "key_history",
    "key_ledger": "key_history",
    "key_epochs": "key_history",
    "key_lineage": "key_history",
    "key_evolution": "key_history",
    "groups": "approval_groups",
    "approval_teams": "approval_groups",
    "signatures_by_group": "candidate_signatures_by_group",
    "candidates_by_group": "candidate_signatures_by_group",
    "public_keys": "public_keys",
    "verification_keys": "public_keys",
    "source_records": "sources",
    "provenance_records": "sources",
    "delegations": "substitutions",
    "acting_assignments": "substitutions",
    "cover_assignments": "substitutions",
}


def _bundle_from_call_args(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    bundle: dict[str, Any] = {}
    if args:
        first = args[0]
        if isinstance(first, dict):
            bundle = copy.deepcopy(first)
        elif isinstance(first, list):
            if first and all(
                isinstance(item, dict)
                and ("signatures" in item or "threshold" in item or "quorum" in item)
                for item in first
            ):
                bundle["approval_groups"] = first
            elif first and all(
                isinstance(item, dict)
                and (
                    "valid_from" in item
                    or "valid_to" in item
                    or "principal_value" in item
                    or "holder" in item
                )
                for item in first
            ):
                bundle["key_history"] = first
            else:
                bundle["shifts"] = first
        else:
            bundle["verification_result"] = first

    for keyword, value in kwargs.items():
        target = _BUNDLE_KWARG_ALIASES.get(keyword, keyword)
        if (
            target in bundle
            and isinstance(bundle[target], list)
            and isinstance(value, list)
        ):
            bundle[target].extend(value)
        else:
            bundle[target] = value

    if len(args) >= 2 and isinstance(args[1], list):  # noqa: PLR2004
        bundle.setdefault("shifts", args[1])
    if len(args) >= 3 and isinstance(args[2], list | dict):  # noqa: PLR2004
        bundle.setdefault("approval_groups", args[2])
    return bundle


def check_independence(*args: Any, **kwargs: Any) -> AuditResult:
    """Audit independence from a bundle or keyword evidence components."""
    return audit_independence(_bundle_from_call_args(args, kwargs))


verify_independence = check_independence
evaluate_independence = check_independence
analyze_independence = check_independence


def attach_independence_check(
    verification_result: Any = None, bundle: dict[str, Any] | None = None, **kwargs: Any
) -> AuditResult:
    """Attach an offline independence check to verification evidence."""
    if bundle is None:
        if isinstance(verification_result, dict):
            bundle = verification_result
            verification_result = None
        else:
            bundle = {}
    bundle = copy.deepcopy(bundle)
    bundle.update(kwargs)
    if isinstance(verification_result, list):
        bundle.setdefault("verification_results", verification_result)
    elif verification_result is not None:
        bundle["supplied_verification_result"] = verification_result
    return audit_independence(bundle)


class IndependenceVerifier:
    """Object-oriented wrapper for audit_independence."""

    def __init__(self, bundle: dict[str, Any] | None = None, **kwargs: Any) -> None:
        self.bundle = copy.deepcopy(bundle) if bundle else {}
        self.bundle.update(kwargs)

    def audit(self, *args: Any, **kwargs: Any) -> AuditResult:
        evidence = copy.deepcopy(self.bundle)
        evidence.update(_bundle_from_call_args(args, kwargs))
        return audit_independence(evidence)

    verify = audit
    check = audit


IndependenceChecker = IndependenceVerifier
IndependenceAuditor = IndependenceVerifier
IndependenceReport = AuditResult


def recompute_independence(bundle: dict[str, Any]) -> AuditResult:
    """Recompute an audit from an offline evidence bundle."""
    return audit_independence(bundle)


def verify_offline_attestation(
    bundle: dict[str, Any], report: AuditResult | dict[str, Any] | None = None
) -> dict[str, Any]:
    """Recompute and compare digests from an offline bundle."""
    if isinstance(report, AuditResult):
        expected = report.attestation
        report_dict = report.to_dict()
    elif isinstance(report, dict):
        expected = report.get("attestation", {})
        report_dict = report
    else:
        expected = {}
        report_dict = {}

    recomputed = audit_independence(bundle)
    actual = recomputed.attestation
    input_matches = (
        expected.get("inputs_digest", actual["inputs_digest"])
        == actual["inputs_digest"]
    )
    report_matches = (
        expected.get("report_digest", actual["report_digest"])
        == actual["report_digest"]
    )
    if report_dict.get("report_digest"):
        report_matches = (
            report_dict["report_digest"] == actual["report_digest"] and report_matches
        )
    return {
        "valid": input_matches and report_matches,
        "input_digest_matches": input_matches,
        "report_digest_matches": report_matches,
        "expected": expected,
        "recomputed": actual,
        "recomputed_report": recomputed.to_dict(),
    }


def _shared_principals(
    candidate_principals: dict[str, list[str]],
    overlaps: list[dict[str, Any]],
    assignment: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    membership: dict[str, set[str]] = {}
    for group_id, principal_ids in candidate_principals.items():
        for principal_id in principal_ids:
            membership.setdefault(principal_id, set()).add(group_id)
    overlap_by_person: dict[str, list[dict[str, Any]]] = {}
    for overlap in overlaps:
        overlap_by_person.setdefault(overlap["principal_id"], []).append(overlap)
    assigned_groups: dict[str, set[str]] = {}
    for group_id, items in assignment.items():
        for item in items:
            assigned_groups.setdefault(item["principal_id"], set()).add(group_id)

    shared = []
    for principal_id, group_ids in sorted(membership.items()):
        if len(group_ids) <= 1:
            continue
        assigned = assigned_groups.get(principal_id, set())
        shared.append(
            {
                "principal_id": principal_id,
                "group_ids": sorted(group_ids),
                "assigned_to_groups": sorted(assigned),
                "dual_group_candidacy": True,
                "would_violate_independence_if_counted_for_both": True,
                "assignment_conflict": len(assigned) > 1,
                # Retained as a stable descriptive key for callers/tests.
                "independence_conflict": True,
                "solver_avoids_duplicate_assignment": len(assigned) <= 1,
                "cross_group_time_overlaps": overlap_by_person.get(principal_id, []),
            }
        )
    return shared


def _attach_overlap_attestations(
    bundle: dict[str, Any], overlaps: list[dict[str, Any]], missing: list[str]
) -> None:
    attestations = _records(
        bundle,
        "time_overlap_attestations",
        "time_overlaps",
        "overlap_attestations",
        "overlap_provenance",
    )
    if not attestations:
        return

    for attestation in attestations:
        principal_id = str(
            _first(attestation, "principal_id", "person_id", "employee_id", default="")
        )
        source = Provenance.from_value(
            _first(attestation, "source", "provenance"),
            f"time overlap for {principal_id}",
        )
        if source.ref is None:
            missing.append(f"time_overlap_attestation {principal_id}")
        group_ids = set(
            _as_list(_first(attestation, "group_ids", "groups", default=[]))
        )
        for overlap in overlaps:
            if principal_id and overlap["principal_id"] != principal_id:
                continue
            if group_ids and not group_ids.intersection(overlap["group_ids"]):
                continue
            source_dict = source.to_dict()
            overlap["attestation_source"] = source_dict
            if source.ref and source.ref not in overlap["source_refs"]:
                overlap["source_refs"].append(source.ref)
                overlap["sources"].append(source_dict)


def _group_reports(
    groups: list[dict[str, Any]],
    candidate_principals: dict[str, list[str]],
    counts: dict[str, int],
    assignment: dict[str, list[dict[str, Any]]],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    reports = []
    for group in groups:
        gid = group["id"]
        threshold = group["threshold"]
        assigned = counts.get(gid, 0)
        reports.append(
            {
                "group_id": gid,
                "threshold": threshold,
                "eligible_principals": candidate_principals.get(gid, []),
                "eligible_count": len(candidate_principals.get(gid, [])),
                "assigned_count": assigned,
                "shortfall": max(0, threshold - assigned),
                "threshold_met": assigned >= threshold,
                "assigned_principal_ids": [
                    item["principal_id"] for item in assignment.get(gid, [])
                ],
                "candidate_signature_count": sum(
                    1 for item in candidates if item["group_id"] == gid
                ),
                "eligible_signature_count": sum(
                    1
                    for item in candidates
                    if item["group_id"] == gid and item["eligible"]
                ),
            }
        )
    return reports


def _dangling_sources(
    sources: dict[str, dict[str, Any]],
    epochs: list[dict[str, Any]],
    shifts: list[dict[str, Any]],
    alias_records: list[dict[str, Any]],
    overlaps: list[dict[str, Any]],
) -> set[str]:
    if not sources:
        return set()
    refs: set[str] = set()
    for epoch in epochs:
        if epoch["source"].get("ref"):
            refs.add(epoch["source"]["ref"])
    for shift in shifts:
        if shift["source"].get("ref"):
            refs.add(shift["source"]["ref"])
    for alias in alias_records:
        if alias["source"].get("ref"):
            refs.add(alias["source"]["ref"])
    for overlap in overlaps:
        refs.update(overlap["source_refs"])
    return {ref for ref in refs if ref not in sources}


def find_independent_assignment(
    bundle_or_groups: dict[str, Any] | list[dict[str, Any]] | None = None,
    candidate_principals: dict[str, list[str]] | None = None,
    **kwargs: Any,
) -> Any:
    """Find an assignment from a bundle or normalized group/candidate data."""
    if (
        candidate_principals is None
        and not kwargs
        and isinstance(bundle_or_groups, dict)
    ):
        return audit_independence(bundle_or_groups).assignment

    groups = bundle_or_groups if isinstance(bundle_or_groups, list) else []
    if isinstance(bundle_or_groups, dict) and candidate_principals is not None:
        groups = _normalize_groups(bundle_or_groups)
    normalized = [
        {
            "id": str(_first(group, "id", "group_id", "name", default=f"group-{i}")),
            "threshold": int(
                _first(group, "threshold", "required", "quorum", default=1)
            ),
        }
        for i, group in enumerate(groups)
        if isinstance(group, dict)
    ]
    candidates = candidate_principals or kwargs.get("candidates", {})
    assignment, _counts, assigned = _solve_assignment(normalized, candidates, [])
    required = sum(group["threshold"] for group in normalized)
    if kwargs.get("include_metadata"):
        return {
            "assignment": assignment,
            "assigned_seats": assigned,
            "required_seats": required,
            "feasible": assigned == required,
            "shortfall": max(0, required - assigned),
        }
    return assignment


find_assignment = find_independent_assignment
solve_assignment = find_independent_assignment


def is_independent(*args: Any, **kwargs: Any) -> bool:
    """Return whether signatures, provenance, and assignment all verify."""
    return check_independence(*args, **kwargs).independence_verified


def assert_independence(*args: Any, **kwargs: Any) -> AuditResult:
    """Return an audit or raise :class:`IndependenceCheckError`."""
    result = check_independence(*args, **kwargs)
    if not result.independence_verified:
        raise IndependenceCheckError(
            f"independence check failed with shortfall={result.shortfall}: "
            + "; ".join(result.errors)
        )
    return result


verify_or_raise = assert_independence


__all__ = [
    "INDEPENDENCE_SCHEMA_VERSION",
    "AuditResult",
    "IndependenceCheckError",
    "IndependenceChecker",
    "IndependenceAuditor",
    "IndependenceReport",
    "IndependenceVerificationError",
    "IndependenceVerifier",
    "attach_independence_check",
    "audit_independence",
    "assert_independence",
    "canonical_json",
    "check_independence",
    "evaluate_independence",
    "find_assignment",
    "find_independent_assignment",
    "solve_assignment",
    "parse_instant",
    "recompute_independence",
    "sha256_digest",
    "verify_independence",
    "verify_or_raise",
    "verify_offline_attestation",
    "verify_signature_results",
    "is_independent",
]
