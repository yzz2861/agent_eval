"""Offline reconciliation for STIX 2.1 Sightings and collection manifests.

Observation identity is deliberately conservative: a STIX id, timestamp, or
``Sighting.count`` is never enough to merge observations.  Exact deduplication
is only possible for integer observation numbers whose manifests establish the
same ``numbering_domain``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from stix2.datastore.filters import Filter
from stix2.datastore.memory import MemoryStore


SCHEMA_VERSION = "observation-reconciliation/v1"
SIGHTING_FILTER = [Filter("type", "=", "sighting")]


def _first(raw: dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return value
    return default


def _as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    return [value]


def _parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _hash(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _integer(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        return int(text)
    except (TypeError, ValueError):
        return None


def _conflict(code: str, message: str, **details: Any) -> dict[str, Any]:
    result = {"code": code, "message": message}
    result.update(details)
    return result


def read_json_file(path: str | Path) -> Any:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text)


def manifest_entries(data: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return manifest records and top-level metadata from a caller file."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)], {}
    if isinstance(data, dict):
        for key in ("manifests", "records", "items", "entries"):
            value = data.get(key)
            if isinstance(value, list):
                metadata = {k: v for k, v in data.items() if k != key}
                return [item for item in value if isinstance(item, dict)], metadata
        if data.get("type") or data.get("package_id") or data.get("manifest_id"):
            return [data], {}
    return [], {}


def load_sighting_source(paths: str | Path | Iterable[str | Path]) -> MemoryStore:
    """Load STIX 2.1 JSON objects/bundles into a stix2 MemoryStore."""
    if isinstance(paths, (str, Path)):
        paths = [paths]

    store = MemoryStore()
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            files = sorted(
                item for item in path.rglob("*")
                if item.is_file() and item.suffix.lower() in {".json", ".jsonl"}
            )
        else:
            files = [path]

        for file_path in files:
            data = read_json_file(file_path)
            if isinstance(data, list) and file_path.suffix.lower() == ".jsonl":
                for item in data:
                    store.sink.add(item, version="2.1")
            else:
                store.sink.add(data, version="2.1")
    return store


def sightings_from_source(source: Any) -> dict[str, dict[str, Any]]:
    if hasattr(source, "query"):
        objects = list(source.query(SIGHTING_FILTER))
    elif callable(source):
        objects = list(source("sighting"))
    else:
        objects = list(source)

    by_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if isinstance(obj, dict):
            data = dict(obj)
        elif hasattr(obj, "serialize"):
            data = json.loads(obj.serialize())
        else:
            data = dict(obj)
        if data.get("type") != "sighting":
            continue
        # The entry is explicitly v2.1-only.  v2.0 Sightings have no
        # spec_version and must not silently enter the same settlement ledger.
        if data.get("spec_version") != "2.1":
            continue
        sighting_id = data.get("id")
        if sighting_id:
            by_id[sighting_id] = data
    return by_id


def normalize_manifest(
    raw: dict[str, Any], index: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], set[str]]:
    conflicts: list[dict[str, Any]] = []
    referenced_ids = {
        str(value)
        for value in _as_list(_first(raw, ["sighting_ids", "sighting_id", "object_ids"], []))
        if value
    }


    raw_id = _first(raw, ["manifest_id", "receipt_id", "settlement_id"])
    manifest_id = str(raw_id) if raw_id else f"manifest--{_hash(raw)}"
    package_id = str(_first(raw, ["package_id", "package", "batch_id"], manifest_id))
    source = _first(raw, ["source", "source_name", "supplier", "producer", "来源", "供数方"])
    if source in (None, ""):
        conflicts.append(_conflict(
            "missing_source",
            "清单缺少来源，不能建立可供审计的供数责任。",
            manifest_id=manifest_id,
            package_id=package_id,
        ))
        return None, conflicts, referenced_ids

    settled_raw = _first(raw, ["settled_at", "settlement_time", "registered_at", "结算登记时间"])
    try:
        settled_at = _parse_timestamp(settled_raw)
    except ValueError:
        settled_at = None
    if settled_at is None:
        conflicts.append(_conflict(
            "missing_or_invalid_settled_at",
            "清单缺少可解析的结算登记时间，不能放入指定结算时点的账本。",
            manifest_id=manifest_id,
            package_id=package_id,
        ))
        return None, conflicts, referenced_ids

    try:
        replaces_from = _parse_timestamp(_first(raw, [
            "replaces_from", "replacement_effective_at", "effective_from", "替换起始时间",
        ]))
    except ValueError:
        replaces_from = None
        conflicts.append(_conflict(
            "invalid_replaces_from",
            "替换起始时间无法解析；该时间只作审计，不影响编号域去重规则。",
            manifest_id=manifest_id,
            package_id=package_id,
        ))

    start = _integer(_first(raw, ["start_number", "start", "first_number", "from_number"]))
    end = _integer(_first(raw, ["end_number", "end", "last_number", "to_number"]))
    if (start is None) != (end is None):
        conflicts.append(_conflict(
            "invalid_number_range",
            "连续编号区间必须同时提供起点和终点。",
            manifest_id=manifest_id,
            package_id=package_id,
            start=start,
            end=end,
        ))
        return None, conflicts, referenced_ids
    if start is not None and end is not None and start > end:
        conflicts.append(_conflict(
            "invalid_number_range",
            "编号区间起点大于终点。",
            manifest_id=manifest_id,
            package_id=package_id,
            start=start,
            end=end,
        ))
        return None, conflicts, referenced_ids

    scope_start = _integer(_first(raw, [
        "scope_start_number", "target_start_number", "planned_start_number",
    ]))
    scope_end = _integer(_first(raw, [
        "scope_end_number", "target_end_number", "planned_end_number",
    ]))
    if (scope_start is None) != (scope_end is None):
        conflicts.append(_conflict(
            "invalid_scope_range",
            "采集范围起点和终点必须同时提供。",
            manifest_id=manifest_id,
            package_id=package_id,
        ))
        return None, conflicts, referenced_ids
    if scope_start is not None and scope_end is not None and scope_start > scope_end:
        conflicts.append(_conflict(
            "invalid_scope_range",
            "采集范围起点大于终点。",
            manifest_id=manifest_id,
            package_id=package_id,
        ))
        return None, conflicts, referenced_ids

    claimed_count = _integer(_first(raw, ["claimed_count", "report_count", "count"]))
    if _first(raw, ["claimed_count", "report_count", "count"]) is not None and claimed_count is None:
        conflicts.append(_conflict(
            "invalid_count",
            "清单中的 count 不是非负整数。",
            manifest_id=manifest_id,
            package_id=package_id,
        ))
        return None, conflicts, referenced_ids

    status_text = str(_first(raw, ["op", "status", "state"], "active")).strip().lower()
    if status_text in {"withdraw", "withdrawn", "revoke", "revoked", "撤回", "撤销"}:
        op = "withdrawn"
    elif status_text in {"active", "add", "added", "registered", "有效", "登记"}:
        op = "active"
    else:
        conflicts.append(_conflict(
            "unknown_status",
            f"未知清单状态 {status_text!r}。",
            manifest_id=manifest_id,
            package_id=package_id,
        ))
        return None, conflicts, referenced_ids

    coverage_text = str(_first(raw, ["coverage", "scope_status", "completeness"], "complete")).lower()
    scope_complete = _first(raw, ["scope_complete", "complete"])
    if isinstance(scope_complete, bool):
        coverage = "complete" if scope_complete else "partial"
    elif coverage_text in {"partial", "incomplete", "missing", "不全", "部分"}:
        coverage = "partial"
    else:
        coverage = "complete"

    revision = _first(raw, ["revision", "version", "rev"])
    revision_int = _integer(revision)
    replaces = [str(item) for item in _as_list(_first(raw, [
        "replaces", "replaces_package_ids", "supersedes", "old_package_ids",
    ], [])) if item]
    sighting_ids = [str(item) for item in _as_list(_first(raw, [
        "sighting_ids", "sighting_id", "object_ids",
    ], [])) if item]

    record = {
        "manifest_id": manifest_id,
        "package_id": package_id,
        "source": str(source),
        "report_group": str(_first(raw, ["report_group", "group", "metric", "weekly_group"], "unassigned")),
        "sighting_ids": sighting_ids,
        "domain": (str(_first(raw, ["numbering_domain", "domain", "number_domain"]))
                   if _first(raw, ["numbering_domain", "domain", "number_domain"]) else None),
        "start": start,
        "end": end,
        "scope_start": scope_start,
        "scope_end": scope_end,
        "claimed_count": claimed_count,
        "settled_at": _iso(settled_at),
        "_settled_dt": settled_at,
        "replaces_from": _iso(replaces_from),
        "_replaces_from_dt": replaces_from,
        "replaces": replaces,
        "revision": str(revision) if revision is not None else None,
        "_revision_rank": revision_int if revision_int is not None else 0,
        "op": op,
        "coverage": coverage,
        "raw_index": index,
        "business_signature": _hash({
            "source": str(source), "group": raw.get("report_group") or raw.get("group"),
            "sighting_ids": sorted(sighting_ids), "domain": raw.get("numbering_domain") or raw.get("domain"),
            "start": start, "end": end, "scope": [scope_start, scope_end],
            "count": claimed_count, "op": op, "coverage": coverage,
            "replaces": sorted(replaces), "revision": revision,
        }),
    }
    return record, conflicts, referenced_ids


def _new_group(name: str) -> dict[str, Any]:
    return {
        "group": name,
        "domains": {},
        "components": [],
        "evidence": [],
        "reason_codes": set(),
        "reasons": set(),
        "conflict_codes": set(),
    }


def _union_interval_size(intervals: list[tuple[int, int]]) -> int:
    if not intervals:
        return 0
    ordered = sorted(intervals)
    total = 0
    current_start, current_end = ordered[0]
    for start, end in ordered[1:]:
        if start <= current_end + 1:
            current_end = max(current_end, end)
        else:
            total += current_end - current_start + 1
            current_start, current_end = start, end
    total += current_end - current_start + 1
    return total


def _compress_ranges(numbers: set[int]) -> list[dict[str, int]]:
    if not numbers:
        return []
    ordered = sorted(numbers)
    ranges = []
    start = previous = ordered[0]
    for number in ordered[1:]:
        if number == previous + 1:
            previous = number
            continue
        ranges.append({"start": start, "end": previous, "count": previous - start + 1})
        start = previous = number
    ranges.append({"start": start, "end": previous, "count": previous - start + 1})
    return ranges


def _event_signature(record: dict[str, Any]) -> str:
    return _hash({
        "package_id": record["package_id"],
        "source": record["source"],
        "group": record["report_group"],
        "sighting_ids": sorted(record["sighting_ids"]),
        "domain": record["domain"],
        "start": record["start"],
        "end": record["end"],
        "scope_start": record["scope_start"],
        "scope_end": record["scope_end"],
        "claimed_count": record["claimed_count"],
        "settled_at": record["settled_at"],
        "replaces_from": record["replaces_from"],
        "replaces": sorted(record["replaces"]),
        "revision": record["revision"],
        "op": record["op"],
        "coverage": record["coverage"],
    })


def reconcile_observations(
    source: Any,
    manifests: list[dict[str, Any]] | dict[str, Any],
    *,
    as_of: Any = None,
    valid_at: Any = None,
    include_numbers: bool = False,
) -> dict[str, Any]:
    """Reconcile a stix2 DataSource with caller collection manifests."""
    as_of_dt = _parse_timestamp(as_of)
    valid_at_dt = _parse_timestamp(valid_at)
    sightings = sightings_from_source(source)

    manifest_metadata: dict[str, Any] = {}
    if isinstance(manifests, dict):
        raw_manifests, manifest_metadata = manifest_entries(manifests)
    else:
        raw_manifests = list(manifests or [])

    conflicts: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    referenced_ids: set[str] = set()

    for index, raw in enumerate(raw_manifests):
        if not isinstance(raw, dict):
            conflicts.append(_conflict(
                "invalid_manifest_record",
                "清单记录不是 JSON 对象，已隔离该条记录。",
                raw_index=index,
            ))
            continue
        record, record_conflicts, refs = normalize_manifest(raw, index)
        referenced_ids.update(refs)
        conflicts.extend(record_conflicts)
        if record is not None:
            records.append(record)

    event_signatures: dict[str, str] = {}
    disputed_events: set[str] = set()
    duplicate_receipts: list[str] = []
    for record in records:
        manifest_id = record["manifest_id"]
        signature = _event_signature(record)
        if manifest_id in event_signatures:
            if signature != event_signatures[manifest_id]:
                disputed_events.add(manifest_id)
                conflicts.append(_conflict(
                    "manifest_id_conflict",
                    "同一 manifest_id 出现不同内容；已隔离该登记事件，不按输入顺序取舍。",
                    manifest_id=manifest_id,
                    package_id=record["package_id"],
                ))
            else:
                duplicate_receipts.append(manifest_id)
        else:
            event_signatures[manifest_id] = signature

    records = [record for record in records if record["manifest_id"] not in disputed_events]
    visible_records = [
        record for record in records
        if as_of_dt is None or record["_settled_dt"] <= as_of_dt
    ]

    records_by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in visible_records:
        records_by_package[record["package_id"]].append(record)

    selected: dict[str, dict[str, Any]] = {}
    package_conflicts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for package_id, package_records in records_by_package.items():
        def version_key(record: dict[str, Any]) -> tuple[datetime, int, str]:
            return (record["_settled_dt"], record["_revision_rank"], record["manifest_id"])

        top_key = max(version_key(record) for record in package_records)
        candidates = [
            record for record in package_records
            if version_key(record)[:2] == top_key[:2]
        ]
        signatures = {record["business_signature"] for record in candidates}
        group_name = candidates[0]["report_group"]
        if len(signatures) > 1:
            conflict = _conflict(
                "package_version_conflict",
                "同一结算时点/版本的包内容互相冲突；该包被隔离，其他编号域继续出数。",
                package_id=package_id,
                report_group=group_name,
                manifest_ids=sorted(record["manifest_id"] for record in candidates),
            )
            conflicts.append(conflict)
            package_conflicts[group_name].append(conflict)
            continue

        chosen = sorted(candidates, key=lambda item: item["manifest_id"])[0]
        selected[package_id] = chosen

    active_packages = {
        package_id: record for package_id, record in selected.items()
        if record["op"] == "active"
    }
    withdrawn_packages = sorted(
        package_id for package_id, record in selected.items()
        if record["op"] == "withdrawn"
    )

    superseded: dict[str, str] = {}
    for new_id, new_record in active_packages.items():
        if valid_at_dt is not None and new_record["_replaces_from_dt"]:
            if new_record["_replaces_from_dt"] > valid_at_dt:
                continue
        for old_id in new_record["replaces"]:
            if old_id == new_id:
                continue
            if old_id in active_packages:
                superseded[old_id] = new_id

    groups: dict[str, dict[str, Any]] = {}

    def group_entry(name: str) -> dict[str, Any]:
        if name not in groups:
            groups[name] = _new_group(name)
        return groups[name]

    for group_name, group_conflict_list in package_conflicts.items():
        group = group_entry(group_name)
        group["conflict_codes"].update(item["code"] for item in group_conflict_list)

    for package_id, record in sorted(active_packages.items()):
        if package_id in superseded:
            continue
        group = group_entry(record["report_group"])
        sighting_ids = record["sighting_ids"]
        linked_ids = [sighting_id for sighting_id in sighting_ids if sighting_id in sightings]
        missing_ids = [sighting_id for sighting_id in sighting_ids if sighting_id not in sightings]

        sighting_claim: int | None = None
        for sighting_id in linked_ids:
            count_value = _integer(sightings[sighting_id].get("count", 1))
            sighting_claim = (sighting_claim or 0) + (count_value if count_value is not None else 1)

        claim = record["claimed_count"]
        if claim is None:
            claim = sighting_claim

        evidence = {
            "kind": "manifest_package",
            "manifest_id": record["manifest_id"],
            "package_id": package_id,
            "source": record["source"],
            "sighting_ids": sighting_ids,
            "linked_sighting_ids": linked_ids,
            "missing_sighting_ids": missing_ids,
            "settled_at": record["settled_at"],
            "replaces_from": record["replaces_from"],
            "domain": record["domain"],
            "number_range": [record["start"], record["end"]] if record["start"] is not None else None,
            "claimed_count": claim,
        }
        group["evidence"].append(evidence)

        if missing_ids:
            group["reason_codes"].add("linked_sighting_missing")
            group["reasons"].add("清单引用的部分 v2.1 Sighting 未从数据源读回；编号区间仍可作为清单证据，但 count 交叉校验缺失。")

        interval_size = None
        if record["start"] is not None and record["end"] is not None:
            interval_size = record["end"] - record["start"] + 1

        if interval_size is not None and claim is not None and claim != interval_size:
            conflict = _conflict(
                "count_range_mismatch",
                "Sighting/manifest count 与连续编号区间长度不一致；已隔离该包，不擅自选择其中一方。",
                package_id=package_id,
                report_group=record["report_group"],
                manifest_id=record["manifest_id"],
                count=claim,
                interval_size=interval_size,
            )
            conflicts.append(conflict)
            group["conflict_codes"].add("count_range_mismatch")
            continue

        if record["domain"] and interval_size is not None:
            domain_name = record["domain"]
            domain = group["domains"].setdefault(domain_name, {
                "numbers": set(),
                "scope_intervals": [],
                "partial": False,
                "evidence_packages": [],
            })
            domain["numbers"].update(range(record["start"], record["end"] + 1))
            if record["scope_start"] is not None and record["scope_end"] is not None:
                domain["scope_intervals"].append((record["scope_start"], record["scope_end"]))
            if record["coverage"] == "partial":
                domain["partial"] = True
            domain["evidence_packages"].append(package_id)
        elif interval_size is not None:
            group["components"].append({
                "kind": "unverified_number_range",
                "lower": interval_size,
                "upper": interval_size,
                "package_id": package_id,
                "reason_codes": ["numbering_domain_not_confirmed"],
                "reasons": ["编号区间未被清单确认属于同一编号域，因此只能作为数量声称，不能与其他编号消重。"],
            })
        else:
            if claim is None:
                group["components"].append({
                    "kind": "unknown_count_claim",
                    "lower": 0,
                    "upper": None,
                    "package_id": package_id,
                    "reason_codes": ["count_unavailable"],
                    "reasons": ["既没有可核验编号区间，也没有可用 count；不能给出有限上界。"],
                })
            else:
                group["components"].append({
                    "kind": "count_claim",
                    "lower": claim,
                    "upper": claim,
                    "package_id": package_id,
                    "reason_codes": ["observation_numbers_missing"],
                    "reasons": ["只有 Sighting count 或清单计数，没有可逐条核实且归属编号域的观测编号。"],
                })

    for sighting_id, sighting in sorted(sightings.items()):
        if sighting_id in referenced_ids:
            continue
        group_name = str(sighting.get("sighting_of_ref") or "unassigned")
        group = group_entry(group_name)
        count_value = _integer(sighting.get("count", 1))
        claim = count_value if count_value is not None else 1
        group["evidence"].append({
            "kind": "unmanifested_sighting",
            "sighting_id": sighting_id,
            "source": sighting.get("created_by_ref"),
            "first_seen": sighting.get("first_seen"),
            "last_seen": sighting.get("last_seen"),
            "count": claim,
        })
        group["components"].append({
            "kind": "unmanifested_count_claim",
            "lower": claim,
            "upper": claim,
            "sighting_id": sighting_id,
            "reason_codes": ["manifest_missing", "stix_id_is_not_observation_identity"],
            "reasons": ["该 Sighting 没有采集清单；STIX ID、时间和 count 均不能证明底层观测相同。"],
        })

    return _build_report(
        groups=groups,
        conflicts=conflicts,
        sightings=sightings,
        raw_manifests=raw_manifests,
        as_of=as_of_dt,
        valid_at=valid_at_dt,
        include_numbers=include_numbers,
        manifest_metadata=manifest_metadata,
        selected=selected,
        active_packages=active_packages,
        withdrawn_packages=withdrawn_packages,
        superseded=superseded,
        duplicate_receipts=duplicate_receipts,
    )


def _build_report(
    *,
    groups: dict[str, dict[str, Any]],
    conflicts: list[dict[str, Any]],
    sightings: dict[str, dict[str, Any]],
    raw_manifests: list[dict[str, Any]],
    as_of: datetime | None,
    valid_at: datetime | None,
    include_numbers: bool,
    manifest_metadata: dict[str, Any],
    selected: dict[str, dict[str, Any]],
    active_packages: dict[str, dict[str, Any]],
    withdrawn_packages: list[str],
    superseded: dict[str, str],
    duplicate_receipts: list[str],
) -> dict[str, Any]:
    weekly_report: list[dict[str, Any]] = []
    public_groups: dict[str, Any] = {}

    for group_name in sorted(groups):
        group = groups[group_name]
        all_components: list[dict[str, Any]] = list(group["components"])
        domains_public: dict[str, Any] = {}

        for domain_name in sorted(group["domains"]):
            domain = group["domains"][domain_name]
            verified_count = len(domain["numbers"])
            scope_size = _union_interval_size(domain["scope_intervals"])
            if scope_size:
                upper = max(verified_count, scope_size)
            elif domain["partial"]:
                upper = None
            else:
                upper = verified_count

            component = {
                "kind": "numbered_domain",
                "domain": domain_name,
                "lower": verified_count,
                "upper": upper,
                "verified_count": verified_count,
                "verified_ranges": _compress_ranges(domain["numbers"]),
                "scope_intervals": [list(item) for item in domain["scope_intervals"]],
                "coverage": "partial" if upper != verified_count else "complete",
                "evidence_packages": sorted(domain["evidence_packages"]),
                "reason_codes": [] if upper == verified_count else ["collection_scope_incomplete"],
                "reasons": (
                    [] if upper == verified_count
                    else [f"该编号域已核实 {verified_count} 个编号；采集范围不全，只能给出可支持上下界。"]
                ),
            }
            if include_numbers:
                component["numbers"] = sorted(domain["numbers"])
            all_components.append(component)

        reason_codes = set(group["reason_codes"])
        reasons = set(group["reasons"])
        for component in all_components:
            reason_codes.update(component.get("reason_codes", []))
            reasons.update(component.get("reasons", []))

        if group["conflict_codes"]:
            status = "conflict"
            writable = "do_not_report_pending_manifest_resolution"
            exact_number = None
            lower = upper = None
            report_text = "清单存在冲突，该组暂不写数；冲突已单列，不得按输入顺序择一使用。"
        elif not all_components:
            status = "empty"
            writable = "no_supported_number"
            exact_number = None
            lower = upper = 0
            report_text = "没有在指定结算时点可见的有效材料。"
        else:
            lower = max(int(component.get("lower") or 0) for component in all_components)
            upper_values = [component.get("upper") for component in all_components]
            if any(value is None for value in upper_values):
                upper = None
            else:
                upper = sum(int(value) for value in upper_values)

            exact_component = (
                len(all_components) == 1
                and all_components[0].get("kind") == "numbered_domain"
                and lower == upper
            )
            claim_component = (
                len(all_components) == 1
                and str(all_components[0].get("kind", "")).endswith("claim")
                and lower == upper
            )

            if exact_component:
                status = "exact_verified"
                writable = "exact_number"
                exact_number = lower
                report_text = f"可写确数 {lower}：编号已在同一编号域内去重。"
            elif claim_component:
                status = "claim_only"
                writable = "supplier_claim_only_not_verified_exact"
                exact_number = None
                report_text = f"可引用供方声称 {lower}，但不能写成逐笔核实后的确数。"
            else:
                status = "bounded"
                writable = "range_only"
                exact_number = None
                if upper is None:
                    report_text = f"只能写“至少 {lower}”；材料未提供有限上界。"
                else:
                    report_text = f"只能写区间 {lower}–{upper}；跨编号域或无编号材料的重叠无法排除。"

        weekly_entry = {
            "group": group_name,
            "status": status,
            "weekly_writable": writable,
            "exact_number": exact_number,
            "lower": lower,
            "upper": upper,
            "report_text": report_text,
            "reason_codes": sorted(reason_codes),
            "reasons": sorted(reasons),
        }
        weekly_report.append(weekly_entry)
        public_groups[group_name] = {
            **weekly_entry,
            "components": all_components,
            "evidence": group["evidence"],
            "numbering_domains": domains_public,
            "conflict_codes": sorted(group["conflict_codes"]),
        }

    exact_groups = [item for item in weekly_report if item["status"] == "exact_verified"]
    bounded_groups = [item for item in weekly_report if item["status"] == "bounded"]
    claim_groups = [item for item in weekly_report if item["status"] == "claim_only"]
    conflict_groups = [item for item in weekly_report if item["status"] == "conflict"]

    return {
        "schema_version": SCHEMA_VERSION,
        "as_of_settled_at": _iso(as_of),
        "valid_at": _iso(valid_at),
        "identity_policy": (
            "Exact dedup key is (report_group, numbering_domain, observation_number). "
            "STIX id, timestamp, count, and equal numeric labels without a confirmed "
            "shared domain are not observation identity evidence."
        ),
        "manifest_metadata": manifest_metadata,
        "summary": {
            "sighting_count": len(sightings),
            "manifest_count": len(raw_manifests),
            "group_count": len(weekly_report),
            "exact_verified_groups": len(exact_groups),
            "bounded_groups": len(bounded_groups),
            "claim_only_groups": len(claim_groups),
            "conflict_groups": len(conflict_groups),
            "conflict_count": len(conflicts),
        },
        "weekly_report": weekly_report,
        "groups": public_groups,
        "conflicts": conflicts,
        "audit": {
            "selected_packages": [
                {
                    "package_id": package_id,
                    "manifest_id": record["manifest_id"],
                    "op": record["op"],
                    "report_group": record["report_group"],
                    "settled_at": record["settled_at"],
                    "replaces_from": record["replaces_from"],
                    "replaces": record["replaces"],
                    "numbering_domain": record["domain"],
                }
                for package_id, record in sorted(selected.items())
            ],
            "active_package_ids": sorted(active_packages),
            "withdrawn_package_ids": withdrawn_packages,
            "superseded_package_ids": superseded,
            "duplicate_receipts": sorted(set(duplicate_receipts)),
        },
    }


def render_markdown(report):
    lines = [
        "# 异常观测离线对账报告",
        "",
        "- 结算时点: " + str(report.get("as_of_settled_at") or "ALL"),
        "- 口径: 同编号域内按编号取并集；不同编号域、count、时间和 STIX ID 均不用于观测消重。",
        "",
        "| 组别 | 周报可采用写法 | 下界 | 上界 | 原因 |",
        "|---|---|---:|---:|---|",
    ]
    for item in report.get("weekly_report", []):
        upper = "未闭合" if item.get("upper") is None else item.get("upper")
        reasons = "；".join(item.get("reasons", [])) or item.get("status", "")
        reasons = reasons.replace("|", "/")
        lines.append(
            "| {group} | {writable} | {lower} | {upper} | {reasons} |".format(
                group=item.get("group"),
                writable=item.get("weekly_writable"),
                lower=item.get("lower"),
                upper=upper,
                reasons=reasons,
            )
        )
    lines.extend(["", "## 清单冲突", ""])
    conflicts = report.get("conflicts", [])
    if not conflicts:
        lines.append("无。")
    else:
        for conflict in conflicts:
            lines.append("- [{code}] {message} {details}".format(
                code=conflict.get("code"),
                message=conflict.get("message"),
                details=json.dumps(
                    {k: v for k, v in conflict.items() if k not in {"code", "message"}},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            ))
    return "\n".join(lines)


def reconcile_files(sighting_paths, manifest_path, **kwargs):
    source = load_sighting_source(sighting_paths)
    manifests = read_json_file(manifest_path)
    return reconcile_observations(source, manifests, **kwargs)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m stix2.reconciliation",
        description="Offline STIX 2.1 Sighting/manifest reconciliation.",
    )
    parser.add_argument("--sightings", nargs="+", required=True)
    parser.add_argument("--manifests", required=True)
    parser.add_argument("--as-of", dest="as_of")
    parser.add_argument("--valid-at", dest="valid_at")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("-o", "--output")
    parser.add_argument("--show-numbers", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        report = reconcile_files(
            args.sightings,
            args.manifests,
            as_of=args.as_of,
            valid_at=args.valid_at,
            include_numbers=args.show_numbers,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("reconciliation failed: " + str(exc), file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    else:
        rendered = render_markdown(report) + "\n"

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
