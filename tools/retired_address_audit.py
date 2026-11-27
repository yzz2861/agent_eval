#!/usr/bin/env python3
"""Read-only reconciliation of retired-device addresses.

The audit overlays three timestamped sources of truth:

* DHCPACK lease confirmations parsed from pcap files with dpkt;
* IP/MAC associations captured in ARP requests and replies;
* device handover sheets / the migration ticket / the preservation file.

Every conclusion names the records that support it and the records that are
absent, including whether a missing observation is covered by a capture or
falls inside a known collection gap.

Inputs are only opened for reading.  A report is written only when --output is
given, and an output path equal to any input path is rejected.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from tools.pcap_evidence import (
    ArpBinding,
    DhcpAck,
    EvidenceError,
    iso_z,
    mac_to_text,
    read_arp_bindings,
    read_dhcp_acks,
    sha256_file,
)


SCHEMA_VERSION = "dpkt-retired-address-audit/v1"
POLICY_VERSION = "identity-by-time/v1"

VERDICT_LABELS = {
    "old_device": "仍属旧设备",
    "new_device": "可归到新设备",
    "in_use_only": "只能确认地址在用",
    "unverified": "证据不足",
}

CONFIDENCE_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
}

KIND_LABELS = {
    "preservation": "保全记录",
    "decommission": "工单下线时间",
    "handover": "设备交接单",
    "dhcp_ack": "DHCPACK",
    "arp_binding": "ARP 关联",
}


class InputError(Exception):
    """A human-readable input validation error."""


def parse_time(value, field_name: str) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise InputError("invalid timestamp %r for %s" % (value, field_name))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_mac(value, field_name: str) -> Optional[str]:
    if value is None or value == "":
        return None
    try:
        return mac_to_text(value)
    except EvidenceError as exc:
        raise InputError("%s: %s" % (field_name, exc))


def normalize_site(value) -> str:
    return str(value or "").strip().lower()


def _clean(value) -> str:
    return str(value or "").strip()


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    name: str
    site: str
    mac: Optional[str]
    decommissioned_at: Optional[datetime]
    role: str
    record_id: str
    ticket_id: str


@dataclass(frozen=True)
class AddressClaim:
    address: str
    site: str
    legacy_device: str
    legacy_mac: Optional[str]
    record_id: str
    recorded_at: Optional[datetime]
    source_path: str
    index: int


@dataclass(frozen=True)
class HandoverRecord:
    record_id: str
    at: datetime
    address: str
    site: str
    from_device: str
    to_device: str
    from_mac: Optional[str]
    to_mac: Optional[str]
    ticket_id: str
    source_path: str
    index: int


@dataclass(frozen=True)
class CoverageWindow:
    source: str
    site: str
    start: Optional[datetime]
    end: Optional[datetime]
    status: str
    reason: str


@dataclass(frozen=True)
class Inventory:
    ticket_id: str
    title: str
    source_path: str
    old_devices: Tuple[DeviceRecord, ...]
    new_devices: Tuple[DeviceRecord, ...]


@dataclass(frozen=True)
class AuditEvent:
    at: datetime
    kind: str
    record_id: str
    mac: Optional[str] = None
    device_id: Optional[str] = None
    detail: Dict = field(default_factory=dict)
    source_path: Optional[str] = None
    lease_end: Optional[datetime] = None
    lease_infinite: bool = False
    lease_present: bool = False


def _read_csv(path: str) -> List[dict]:
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    except OSError as exc:
        raise InputError("cannot read %s: %s" % (path, exc))


def load_table(path: str, list_keys: Sequence[str] = ()) -> Tuple[List[dict], dict]:
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return _read_csv(path), {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError("cannot read %s: %s" % (path, exc))
    if suffix in (".jsonl", ".ndjson"):
        records = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                raise InputError("%s:%d: invalid JSON: %s" % (path, line_number, exc))
            if not isinstance(record, dict):
                raise InputError("%s:%d: expected a JSON object" % (path, line_number))
            records.append(record)
        return records, {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InputError("%s: invalid JSON: %s" % (path, exc))
    if isinstance(data, list):
        return data, {}
    if not isinstance(data, dict):
        raise InputError("%s: expected a JSON object or array" % path)
    for key in list_keys:
        if isinstance(data.get(key), list):
            return data[key], data
    raise InputError(
        "%s: expected one of the record arrays: %s" % (path, ", ".join(list_keys))
    )


def load_ticket(path: str) -> Inventory:
    records, meta = load_table(path, ("devices", "old_devices", "new_devices"))
    if isinstance(meta.get("devices"), list):
        records = list(meta.get("devices", [])) + list(meta.get("new_devices", []))
    elif isinstance(meta.get("old_devices"), list):
        records = list(meta.get("old_devices", [])) + list(meta.get("new_devices", []))
    devices = []
    for index, record in enumerate(records):
        role = _clean(record.get("role")).lower()
        if role not in ("old", "new"):
            role = "new" if "decommissioned_at" not in record and "decommissioned" not in record else "old"
        device_id = _clean(record.get("device_id") or record.get("id") or record.get("name"))
        name = _clean(record.get("name") or device_id)
        if not device_id:
            raise InputError("%s: device %d is missing device_id" % (path, index))
        site = normalize_site(record.get("site"))
        mac = normalize_mac(record.get("mac") or record.get("hardware_address"), "%s device %d mac" % (path, index))
        decommissioned_at = parse_time(
            record.get("decommissioned_at"),
            "%s device %d decommissioned_at" % (path, index),
        )
        record_id = "ticket:%s:device:%s" % (meta.get("ticket_id", Path(path).stem), device_id)
        devices.append(
            DeviceRecord(
                device_id=device_id,
                name=name,
                site=site,
                mac=mac,
                decommissioned_at=decommissioned_at,
                role=role,
                record_id=record_id,
                ticket_id=_clean(meta.get("ticket_id") or Path(path).stem),
            )
        )
    old_devices = tuple(device for device in devices if device.role == "old")
    new_devices = tuple(device for device in devices if device.role == "new")
    return Inventory(
        ticket_id=_clean(meta.get("ticket_id") or Path(path).stem),
        title=_clean(meta.get("title")),
        source_path=path,
        old_devices=old_devices,
        new_devices=new_devices,
    )


def load_preservation(path: str) -> Tuple[List[AddressClaim], Optional[datetime], str]:
    records, meta = load_table(path, ("addresses", "claims", "records"))
    default_time = parse_time(meta.get("recorded_at"), "%s recorded_at" % path)
    claims = []
    for index, record in enumerate(records):
        address = _clean(record.get("address") or record.get("ip"))
        if not address:
            raise InputError("%s: claim %d is missing address" % (path, index))
        site = normalize_site(record.get("site"))
        legacy_device = _clean(
            record.get("legacy_device")
            or record.get("old_device")
            or record.get("device_id")
            or record.get("device")
        )
        legacy_mac = normalize_mac(
            record.get("legacy_mac") or record.get("mac"),
            "%s claim %d mac" % (path, index),
        )
        recorded_at = parse_time(
            record.get("recorded_at") or record.get("at"),
            "%s claim %d recorded_at" % (path, index),
        ) or default_time
        record_id = _clean(record.get("record_id") or record.get("id"))
        if not record_id:
            record_id = "preservation:%s:%d" % (Path(path).name, index)
        claims.append(
            AddressClaim(
                address=address,
                site=site,
                legacy_device=legacy_device,
                legacy_mac=legacy_mac,
                record_id=record_id,
                recorded_at=recorded_at,
                source_path=path,
                index=index,
            )
        )
    return claims, default_time, _clean(meta.get("file_id") or Path(path).stem)


def load_handovers(paths: Sequence[str]) -> List[HandoverRecord]:
    handovers = []
    for path in paths:
        records, _meta = load_table(path, ("handovers", "handover", "records", "addresses"))
        for index, record in enumerate(records):
            address = _clean(record.get("address") or record.get("ip"))
            at = parse_time(
                record.get("at") or record.get("time") or record.get("timestamp"),
                "%s handover %d at" % (path, index),
            )
            if not address:
                raise InputError("%s: handover %d is missing address" % (path, index))
            if at is None:
                raise InputError("%s: handover %d is missing at" % (path, index))
            from_device = _clean(record.get("from_device") or record.get("old_device"))
            to_device = _clean(record.get("to_device") or record.get("new_device"))
            from_mac = normalize_mac(record.get("from_mac"), "%s handover %d from_mac" % (path, index))
            to_mac = normalize_mac(record.get("to_mac"), "%s handover %d to_mac" % (path, index))
            if not to_device and to_mac:
                to_device = "mac:%s" % to_mac
            if not to_device:
                raise InputError("%s: handover %d needs to_device or to_mac" % (path, index))
            record_id = _clean(record.get("record_id") or record.get("id"))
            if not record_id:
                record_id = "handover:%s:%d" % (Path(path).name, index)
            handovers.append(
                HandoverRecord(
                    record_id=record_id,
                    at=at,
                    address=address,
                    site=normalize_site(record.get("site")),
                    from_device=from_device,
                    to_device=to_device,
                    from_mac=from_mac,
                    to_mac=to_mac,
                    ticket_id=_clean(record.get("ticket_id")),
                    source_path=path,
                    index=index,
                )
            )
    return handovers


def load_coverage(path: Optional[str]) -> List[CoverageWindow]:
    if not path:
        return []
    records, _meta = load_table(path, ("capture", "windows", "coverage"))
    windows = []
    for index, record in enumerate(records):
        source = _clean(record.get("source")).lower()
        if source not in ("dhcp", "arp"):
            raise InputError("%s: window %d has unsupported source %r" % (path, index, source))
        site = normalize_site(record.get("site"))
        start = parse_time(record.get("start"), "%s window %d start" % (path, index))
        end = parse_time(record.get("end"), "%s window %d end" % (path, index))
        status = _clean(record.get("status") or "covered").lower()
        if status not in ("covered", "lost", "degraded"):
            raise InputError("%s: window %d has unsupported status %r" % (path, index, status))
        windows.append(
            CoverageWindow(
                source=source,
                site=site,
                start=start,
                end=end,
                status=status,
                reason=_clean(record.get("reason")),
            )
        )
    return windows


KIND_ORDER = {
    "preservation": 0,
    "decommission": 1,
    "handover": 2,
    "dhcp_ack": 3,
    "arp_binding": 4,
}

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _find_device(devices: Sequence[DeviceRecord], key: str, mac: Optional[str]) -> Optional[DeviceRecord]:
    wanted = _clean(key).lower()
    for device in devices:
        candidates = {device.device_id.lower(), device.name.lower()}
        if device.mac:
            candidates.add(device.mac.lower())
        if wanted and wanted in candidates:
            return device
    if mac:
        for device in devices:
            if device.mac and device.mac.lower() == mac.lower():
                return device
    return None


def _resolved_handover_mac(handover: HandoverRecord, new_devices: Sequence[DeviceRecord]) -> Optional[str]:
    if handover.to_mac:
        return handover.to_mac
    device = _find_device(new_devices, handover.to_device, None)
    if device and device.mac:
        return device.mac
    if handover.to_device.startswith("mac:"):
        return handover.to_device[4:]
    return None


def _resolved_handover_old_mac(handover: HandoverRecord, old_devices: Sequence[DeviceRecord]) -> Optional[str]:
    if handover.from_mac:
        return handover.from_mac
    device = _find_device(old_devices, handover.from_device, None)
    return device.mac if device else None


def _event_to_timeline(event: AuditEvent) -> dict:
    detail = dict(event.detail)
    item = {
        "at": iso_z(event.at),
        "kind": event.kind,
        "kind_label": KIND_LABELS.get(event.kind, event.kind),
        "record_id": event.record_id,
    }
    if event.mac:
        item["mac"] = event.mac
    if event.device_id:
        item["device_id"] = event.device_id
    if detail:
        item["detail"] = detail
    return item


def _support_entry(event: AuditEvent, why: str, role: str = "evidence") -> dict:
    entry = {
        "record_id": event.record_id,
        "kind": event.kind,
        "kind_label": KIND_LABELS.get(event.kind, event.kind),
        "at": iso_z(event.at),
        "role": role,
        "why": why,
    }
    if event.mac:
        entry["mac"] = event.mac
    if event.device_id:
        entry["device_id"] = event.device_id
    if event.detail:
        entry["detail"] = dict(event.detail)
    return entry


def _context_entry(event: AuditEvent, why: str) -> dict:
    entry = _support_entry(event, why, role="context")
    return entry


def _coverage_note(
    windows: Sequence[CoverageWindow],
    source: str,
    site: str,
    after: Optional[datetime],
) -> dict:
    relevant = [
        window
        for window in windows
        if window.source == source and (not window.site or not site or window.site == site)
    ]
    base = {
        "source": source,
        "site": site,
        "last_window_start": None,
        "last_window_end": None,
        "reason": "",
    }
    if not relevant:
        base.update(
            {
                "status": "unknown",
                "note": "未提供覆盖说明；只能按现有 pcap 中未出现该记录来判断",
            }
        )
        return base
    latest = max(relevant, key=lambda window: window.end or window.start or EPOCH)
    base["last_window_start"] = iso_z(latest.start) if latest.start else None
    base["last_window_end"] = iso_z(latest.end) if latest.end else None
    base["reason"] = latest.reason
    covering = []
    if after is not None:
        covering = [
            window
            for window in relevant
            if (window.start is None or window.start <= after)
            and (window.end is None or after <= window.end)
        ]
    if covering:
        window = max(covering, key=lambda item: item.start or EPOCH)
        base["status"] = window.status
        base["reason"] = window.reason
        if window.status == "covered":
            base["note"] = "采集窗口覆盖该时段，但没有观察到匹配记录"
        elif window.status == "degraded":
            base["note"] = "采集窗口只部分可用，匹配记录可能没有被看到"
        else:
            base["note"] = "采集窗口标记为丢失，缺席不能证明地址未被使用"
        return base
    if latest.end is not None and after is not None and latest.end < after:
        base["status"] = "ended"
        base["note"] = "最后一个采集窗口在该时点之前结束，之后没有观测"
    else:
        base["status"] = latest.status
        base["note"] = "没有覆盖该期望时点的采集窗口"
    return base


def _absent_entry(
    kind: str,
    role: str,
    impact: str,
    after: Optional[datetime],
    site: str,
    windows: Sequence[CoverageWindow],
    source: Optional[str] = None,
    note: str = "",
) -> dict:
    source_name = source or ("dhcp" if kind.startswith("dhcp") else "arp" if kind.startswith("arp") else "handover")
    if source_name in ("dhcp", "arp"):
        observation = _coverage_note(windows, source_name, site, after)
    else:
        observation = {
            "source": "handover",
            "site": site,
            "status": "not-applicable",
            "note": "交接单是文档记录，不由抓包覆盖",
        }
    requested_impact = impact
    observation_status = observation.get("status")
    if impact in ("supports_old_device", "supports_new_device") and observation_status != "covered":
        impact = "weakens_conclusion"
    entry = {
        "kind": kind,
        "role": role,
        "impact": impact,
        "impact_label": IMPACT_LABELS[impact],
        "impact_requested": requested_impact,
        "expected_after": iso_z(after) if after else None,
        "observation": observation,
    }
    if impact != requested_impact:
        entry["impact_note"] = "缺席落在丢失/未覆盖的采集窗口，不能作为反向证据"
    if note:
        entry["note"] = note
    return entry


IMPACT_LABELS = {
    "supports_old_device": "支持仍属旧设备",
    "supports_new_device": "支持可归到新设备",
    "supports_in_use_only": "支持仅确认地址在用",
    "weakens_conclusion": "削弱结论",
    "documentation_gap": "文档缺口",
}


def _build_claim_events(
    claim: AddressClaim,
    old_device: Optional[DeviceRecord],
    handovers: Sequence[HandoverRecord],
    dhcp_records: Sequence[DhcpAck],
    arp_records: Sequence[ArpBinding],
    as_of: datetime,
) -> List[AuditEvent]:
    events: List[AuditEvent] = []
    if claim.recorded_at and claim.recorded_at <= as_of:
        events.append(
            AuditEvent(
                at=claim.recorded_at,
                kind="preservation",
                record_id=claim.record_id,
                device_id=claim.legacy_device or None,
                detail={
                    "legacy_device": claim.legacy_device,
                    "legacy_mac": claim.legacy_mac,
                },
                source_path=claim.source_path,
            )
        )
    if old_device and old_device.decommissioned_at and old_device.decommissioned_at <= as_of:
        events.append(
            AuditEvent(
                at=old_device.decommissioned_at,
                kind="decommission",
                record_id=old_device.record_id,
                device_id=old_device.device_id,
                detail={"device_name": old_device.name, "ticket_id": old_device.ticket_id},
                source_path=old_device.record_id,
            )
        )
    for handover in handovers:
        if handover.at > as_of:
            continue
        events.append(
            AuditEvent(
                at=handover.at,
                kind="handover",
                record_id=handover.record_id,
                mac=handover.to_mac,
                device_id=handover.to_device,
                detail={
                    "from_device": handover.from_device,
                    "to_device": handover.to_device,
                    "from_mac": handover.from_mac,
                    "to_mac": handover.to_mac,
                    "ticket_id": handover.ticket_id,
                },
                source_path=handover.source_path,
            )
        )
    for ack in dhcp_records:
        if ack.address != claim.address or ack.captured_at > as_of:
            continue
        events.append(
            AuditEvent(
                at=ack.captured_at,
                kind="dhcp_ack",
                record_id=ack.record_id,
                mac=ack.client_mac,
                detail={
                    "lease_seconds": ack.lease_seconds,
                    "lease_infinite": ack.lease_infinite,
                    "lease_present": ack.lease_present,
                    "lease_end": iso_z(ack.lease_end) if ack.lease_end else None,
                    "server_id": ack.server_id,
                    "xid": ack.xid,
                },
                source_path=ack.source_path,
                lease_end=ack.lease_end,
                lease_infinite=ack.lease_infinite,
                lease_present=ack.lease_present,
            )
        )
    for binding in arp_records:
        if binding.ip != claim.address or binding.captured_at > as_of:
            continue
        events.append(
            AuditEvent(
                at=binding.captured_at,
                kind="arp_binding",
                record_id=binding.record_id,
                mac=binding.mac,
                detail={
                    "role": binding.role,
                    "operation": binding.operation,
                    "frame_src": binding.frame_src,
                    "frame_dst": binding.frame_dst,
                    "frame_src_matches": binding.frame_src_matches,
                },
                source_path=binding.source_path,
            )
        )
    events.sort(key=lambda event: (event.at, KIND_ORDER.get(event.kind, 9), event.record_id))
    return events


def _is_post_cutover(event: AuditEvent, base: Optional[datetime]) -> bool:
    return base is None or event.at >= base


def _lease_spans_cutover(event: AuditEvent, base: Optional[datetime], as_of: datetime) -> bool:
    if base is None or event.kind != "dhcp_ack" or event.at >= base:
        return False
    if event.lease_infinite:
        return True
    if not event.lease_present or event.lease_end is None:
        return False
    return event.lease_end > base and event.lease_end > as_of


def _event_is_binding(event: AuditEvent) -> bool:
    if event.kind == "arp_binding":
        return event.mac is not None
    if event.kind == "dhcp_ack":
        return event.mac is not None
    return False


def _analyze_claim(
    claim: AddressClaim,
    inventory: Inventory,
    handovers: Sequence[HandoverRecord],
    dhcp_records: Sequence[DhcpAck],
    arp_records: Sequence[ArpBinding],
    windows: Sequence[CoverageWindow],
    as_of: datetime,
    warnings: List[dict],
) -> dict:
    old_device = _find_device(inventory.old_devices, claim.legacy_device, claim.legacy_mac)
    if old_device is None and claim.legacy_device:
        warnings.append(
            {
                "code": "unknown_legacy_device",
                "address": claim.address,
                "message": "保全记录引用的旧设备 %s 不在工单中" % claim.legacy_device,
            }
        )
    if old_device and old_device.mac and claim.legacy_mac and old_device.mac != claim.legacy_mac:
        warnings.append(
            {
                "code": "legacy_mac_conflict",
                "address": claim.address,
                "message": "保全 MAC %s 与工单设备 MAC %s 不一致"
                % (claim.legacy_mac, old_device.mac),
            }
        )
    if old_device and not old_device.decommissioned_at:
        warnings.append(
            {
                "code": "missing_decommission_time",
                "address": claim.address,
                "message": "工单中旧设备 %s 没有下线时间" % old_device.name,
            }
        )

    matching_handovers: List[HandoverRecord] = []
    for handover in handovers:
        if handover.address != claim.address:
            continue
        if handover.at > as_of:
            continue
        if handover.site and claim.site and handover.site != claim.site:
            warnings.append(
                {
                    "code": "handover_site_mismatch",
                    "address": claim.address,
                    "message": "交接单 %s 的站点 %s 与保全记录 %s 不一致，已排除"
                    % (handover.record_id, handover.site, claim.site),
                }
            )
            continue
        matching_handovers.append(handover)

    current_handover = max(matching_handovers, key=lambda item: item.at) if matching_handovers else None
    if len(matching_handovers) > 1:
        warnings.append(
            {
                "code": "multiple_handovers",
                "address": claim.address,
                "message": "存在多张交接单，使用最新 %s，其余按历史上下文处理"
                % current_handover.record_id,
            }
        )
    new_macs = set()
    if current_handover is not None:
        resolved = _resolved_handover_mac(current_handover, inventory.new_devices)
        if resolved:
            new_macs.add(resolved)
        new_device = _find_device(inventory.new_devices, current_handover.to_device, None)
        if new_device and new_device.mac and resolved and new_device.mac != resolved:
            warnings.append(
                {
                    "code": "new_mac_conflict",
                    "address": claim.address,
                    "message": "交接单 MAC %s 与新设备清单 %s 的 MAC %s 不一致"
                    % (resolved, new_device.name, new_device.mac),
                }
            )

    old_macs = {mac for mac in (claim.legacy_mac, old_device.mac if old_device else None) if mac}
    if old_macs & new_macs:
        warnings.append(
            {
                "code": "old_new_mac_overlap",
                "address": claim.address,
                "message": "旧设备与新设备的 MAC 集合重叠，无法按 MAC 区分身份",
            }
        )

    events = _build_claim_events(
        claim, old_device, matching_handovers, dhcp_records, arp_records, as_of
    )
    latest_handover_at = max((handover.at for handover in matching_handovers), default=None)
    decommission_at = old_device.decommissioned_at if old_device else None
    if decommission_at and decommission_at > as_of:
        decommission_at = None
        warnings.append(
            {
                "code": "decommission_after_as_of",
                "address": claim.address,
                "message": "工单下线时间晚于核对时点，未参与判定",
            }
        )
    base_times = [time for time in (latest_handover_at, decommission_at) if time]
    base = max(base_times) if base_times else None

    old_candidates: List[AuditEvent] = []
    new_observations: List[AuditEvent] = []
    unknown_strong: List[AuditEvent] = []
    unknown_weak: List[AuditEvent] = []
    for event in events:
        if not _event_is_binding(event):
            continue
        if not (_is_post_cutover(event, base) or _lease_spans_cutover(event, base, as_of)):
            continue
        if event.mac in old_macs and event.mac not in new_macs:
            old_candidates.append(event)
        elif event.mac in new_macs and event.mac not in old_macs:
            new_observations.append(event)
        else:
            role = event.detail.get("role")
            if event.kind == "arp_binding" and role == "target":
                unknown_weak.append(event)
            else:
                unknown_strong.append(event)

    latest_old = max((event.at for event in old_candidates), default=None)
    latest_new = max((event.at for event in new_observations), default=None)
    latest_unknown = max((event.at for event in unknown_strong), default=None)
    latest_unknown_weak = max((event.at for event in unknown_weak), default=None)

    verdict = "unverified"
    conflicts: List[dict] = []
    caveats: List[str] = []
    if latest_unknown is not None and (
        latest_old is None and latest_new is None and latest_handover_at is None
        or latest_unknown > max(
            [time for time in (latest_old, latest_new, latest_handover_at) if time] or [EPOCH]
        )
    ):
        verdict = "in_use_only"
        if current_handover is not None:
            handover_event = next(
                (event for event in events if event.record_id == current_handover.record_id), None
            )
            if handover_event is not None:
                conflicts.append(
                    _support_entry(
                        handover_event,
                        "交接单声称已转给新设备，但之后最新的运行时关联使用了未知 MAC",
                        role="conflict",
                    )
                )
    elif latest_old is not None and (latest_new is None or latest_old > latest_new):
        verdict = "old_device"
    elif latest_new is not None or matching_handovers:
        verdict = "new_device"
    elif latest_unknown is not None or latest_unknown_weak is not None:
        verdict = "in_use_only"
    else:
        verdict = "unverified"

    if verdict == "old_device" and latest_new is not None and latest_old == latest_new:
        conflicts.append(
            {"kind": "timestamp_tie", "message": "新旧身份在同一秒出现，按保守策略判为旧设备"}
        )

    if verdict == "old_device" and decommission_at:
        for event in old_candidates:
            if event.at > decommission_at:
                conflicts.append(
                    {
                        "kind": "decommission_contradiction",
                        "record_id": event.record_id,
                        "message": "工单称 %s 已于 %s 下线，但 %s 仍观察到旧设备 MAC %s；地址结论为仍属旧设备"
                        % (
                            old_device.name if old_device else claim.legacy_device,
                            iso_z(decommission_at),
                            event.record_id,
                            event.mac,
                        ),
                    }
                )
                break

    if verdict == "new_device":
        latest_new_observation = latest_new
        first_new_after_cutover = min(
            (
                event.at
                for event in new_observations
                if latest_handover_at is None or event.at >= latest_handover_at
            ),
            default=latest_new_observation,
        )
        for event in old_candidates:
            if (
                first_new_after_cutover is not None
                and event.kind == "dhcp_ack"
                and event.lease_present
                and event.lease_end
                and event.lease_end > first_new_after_cutover
            ):
                conflicts.append(
                    {
                        "kind": "lease_overlap",
                        "record_id": event.record_id,
                        "message": "旧租约 %s 到 %s 仍未到期，但新设备在 %s 已获得同一地址；"
                        "按更晚的 DHCPACK 覆盖归属，需核查旧租约是否被提前终止"
                        % (
                            event.record_id,
                            iso_z(event.lease_end),
                            iso_z(first_new_after_cutover),
                        ),
                    }
                )

    support: List[dict] = []
    context: List[dict] = []
    if verdict == "old_device":
        for event in old_candidates:
            if event.kind == "dhcp_ack":
                if _lease_spans_cutover(event, base, as_of):
                    why = "DHCPACK 起始于交接前，但租期覆盖到 %s，旧设备租约跨过交接时点" % (
                        iso_z(event.lease_end) if event.lease_end else "无限期"
                    )
                else:
                    why = "DHCPACK 在交接后仍把 %s 租给旧设备 MAC %s" % (
                        claim.address,
                        event.mac,
                    )
            else:
                why = "ARP %s 关联在交接后仍把 %s 指向旧设备 MAC %s" % (
                    event.detail.get("role", "sender"),
                    claim.address,
                    event.mac,
                )
            support.append(_support_entry(event, why, role="binds_old_device"))
    elif verdict == "new_device":
        for handover in [current_handover] if current_handover else []:
            event = next(item for item in events if item.record_id == handover.record_id)
            support.append(
                _support_entry(
                    event,
                    "交接单把 %s 从 %s 转给 %s（%s）"
                    % (claim.address, handover.from_device or "未注明", handover.to_device, iso_z(handover.at)),
                    role="assigns_new_device",
                )
            )
        for event in new_observations:
            if event.kind == "dhcp_ack":
                why = "DHCPACK 把 %s 的租约确认给新设备 MAC %s" % (claim.address, event.mac)
            else:
                why = "ARP %s 关联把 %s 指向新设备 MAC %s" % (
                    event.detail.get("role", "sender"),
                    claim.address,
                    event.mac,
                )
            support.append(_support_entry(event, why, role="binds_new_device"))
    elif verdict == "in_use_only":
        for event in unknown_strong + unknown_weak:
            who = event.mac or "未知 MAC"
            why = "%s 显示 %s 正在使用，但 MAC %s 不属于旧设备或交接单中的新设备" % (
                "DHCPACK" if event.kind == "dhcp_ack" else "ARP %s" % event.detail.get("role", "sender"),
                claim.address,
                who,
            )
            support.append(_support_entry(event, why, role="address_in_use_identity_unknown"))

    if verdict != "old_device":
        for event in events:
            if event.kind in ("preservation", "decommission"):
                context.append(
                    _context_entry(
                        event,
                        "保全/工单基线：地址原属 %s" % (event.device_id or claim.legacy_device or "未知设备"),
                    )
                )
            elif event.mac in old_macs and event not in old_candidates:
                context.append(
                    _context_entry(event, "交接前的旧设备身份记录，已被后续新设备记录覆盖")
                )
            elif event in old_candidates:
                context.append(
                    _context_entry(event, "旧设备租约/关联跨过交接，但之后出现了更新的新设备运行时证据")
                )
            elif event.kind == "handover" and event.record_id != (
                current_handover.record_id if current_handover else None
            ):
                context.append(_context_entry(event, "历史交接单，已被最新交接单覆盖"))

    if verdict == "old_device":
        for event in events:
            if event.kind in ("preservation", "decommission"):
                context.append(
                    _context_entry(
                        event,
                        "保全/工单基线：地址原属 %s" % (event.device_id or claim.legacy_device or "未知设备"),
                    )
                )
            if event.kind == "handover":
                context.append(_context_entry(event, "交接单记录早于后出现的旧设备运行时证据"))

    for event in old_candidates:
        if event.kind == "dhcp_ack" and event.lease_present and event.lease_end and event.lease_end <= as_of:
            caveats.append(
                "%s 的租期在核对时点前已经结束（%s），只能证明交接后旧设备曾持有该地址"
                % (event.record_id, iso_z(event.lease_end))
            )
        if not event.lease_present and event.kind == "dhcp_ack":
            caveats.append("%s 没有 option 51 租期字段，租期长度未知" % event.record_id)
        if event.lease_infinite:
            caveats.append("%s 的租期为无限期" % event.record_id)
        if event.kind == "arp_binding" and event.detail.get("frame_src_matches") is False:
            caveats.append("%s 的以太网源 MAC 与 ARP 发送 MAC 不一致" % event.record_id)

    if verdict == "new_device" and matching_handovers and not new_observations:
        caveats.append("新设备归属只由交接单支持；没有 DHCPACK 或 ARP 运行时身份记录")
    if verdict == "in_use_only":
        unknown_macs = sorted({event.mac for event in unknown_strong + unknown_weak if event.mac})
        if unknown_macs:
            caveats.append("地址在用，但观察到 MAC（%s）不在旧/新设备清单内" % ", ".join(unknown_macs))
        else:
            caveats.append("地址在用，但没有可用的客户端 MAC 身份")
    if decommission_at and matching_handovers:
        for event in events:
            if event.mac in old_macs and decommission_at <= event.at < latest_handover_at:
                caveats.append(
                    "工单称旧设备已于 %s 下线，但 %s 仍观察到旧设备身份，直到交接前"
                    % (iso_z(decommission_at), event.record_id)
                )
                break

    after_for_absence = base or as_of
    absent: List[dict] = []
    new_dhcp = [event for event in new_observations if event.kind == "dhcp_ack"]
    new_arp = [event for event in new_observations if event.kind == "arp_binding"]
    old_dhcp = [event for event in old_candidates if event.kind == "dhcp_ack"]
    old_arp = [event for event in old_candidates if event.kind == "arp_binding"]
    unknown_dhcp = [event for event in unknown_strong if event.kind == "dhcp_ack"]
    unknown_arp = [
        event for event in unknown_strong + unknown_weak if event.kind == "arp_binding"
    ]

    if verdict == "new_device":
        if not matching_handovers:
            absent.append(
                _absent_entry(
                    "handover",
                    "new-device assignment document",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                    note="没有交接单，只能按清单 MAC 推断",
                )
            )
        if not new_dhcp:
            absent.append(
                _absent_entry(
                    "dhcp_ack",
                    "new-device lease confirmation",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                )
            )
        if not new_arp:
            absent.append(
                _absent_entry(
                    "arp_binding",
                    "new-device runtime association",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                )
            )
        if not old_dhcp:
            absent.append(
                _absent_entry(
                    "old_dhcp_ack",
                    "post-cutover legacy lease confirmation",
                    "supports_new_device",
                    after_for_absence,
                    claim.site,
                    windows,
                    source="dhcp",
                )
            )
        if not old_arp:
            absent.append(
                _absent_entry(
                    "old_arp_binding",
                    "post-cutover legacy runtime association",
                    "supports_new_device",
                    after_for_absence,
                    claim.site,
                    windows,
                    source="arp",
                )
            )
    elif verdict == "old_device":
        if not matching_handovers:
            absent.append(
                _absent_entry(
                    "handover",
                    "transfer document",
                    "documentation_gap",
                    after_for_absence,
                    claim.site,
                    windows,
                    note="没有交接单，旧设备绑定仍由运行时记录支持",
                )
            )
        if not new_dhcp:
            absent.append(
                _absent_entry(
                    "new_dhcp_ack",
                    "new-device lease confirmation",
                    "supports_old_device",
                    after_for_absence,
                    claim.site,
                    windows,
                    source="dhcp",
                )
            )
        if not new_arp:
            absent.append(
                _absent_entry(
                    "new_arp_binding",
                    "new-device runtime association",
                    "supports_old_device",
                    after_for_absence,
                    claim.site,
                    windows,
                    source="arp",
                )
            )
    elif verdict == "in_use_only":
        if not matching_handovers:
            absent.append(
                _absent_entry(
                    "handover",
                    "device assignment document",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                )
            )
        if not unknown_dhcp:
            absent.append(
                _absent_entry(
                    "dhcp_ack",
                    "lease/identity confirmation",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                )
            )
        if not unknown_arp:
            absent.append(
                _absent_entry(
                    "arp_binding",
                    "runtime association",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                )
            )
        if not any(event.mac in old_macs | new_macs for event in events):
            absent.append(
                _absent_entry(
                    "known_device_binding",
                    "identity-bearing DHCPACK or ARP for a known device",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                    source="dhcp",
                    note="DHCP 与 ARP 都没有把地址绑定到旧/新设备清单中的 MAC",
                )
            )
    else:
        absent.extend(
            [
                _absent_entry(
                    "handover",
                    "device assignment document",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                ),
                _absent_entry(
                    "dhcp_ack",
                    "lease/identity confirmation",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                ),
                _absent_entry(
                    "arp_binding",
                    "runtime association",
                    "weakens_conclusion",
                    after_for_absence,
                    claim.site,
                    windows,
                ),
            ]
        )

    if matching_handovers and not new_macs:
            absent.append(
                _absent_entry(
                    "handover_to_mac",
                    "new-device hardware identity",
                    "documentation_gap",
                latest_handover_at or after_for_absence,
                claim.site,
                windows,
                note="交接单没有 to_mac，新设备清单里也没有对应 MAC",
            )
        )

    if verdict == "old_device":
        old_types = {event.kind for event in old_candidates}
        if len(old_candidates) >= 2 and len(old_types) >= 2:
            confidence = "high"
        elif old_candidates:
            confidence = "medium"
        else:
            confidence = "low"
    elif verdict == "new_device":
        if matching_handovers and new_dhcp and new_arp:
            confidence = "high"
        elif matching_handovers and (new_dhcp or new_arp):
            confidence = "medium"
        elif matching_handovers:
            confidence = "low"
        else:
            confidence = "medium" if new_observations else "low"
    elif verdict == "in_use_only":
        if unknown_dhcp or len(unknown_strong) >= 2:
            confidence = "medium"
        else:
            confidence = "low"
    else:
        confidence = "low"

    decided_at = {
        "old_device": latest_old,
        "new_device": max([time for time in (latest_new, latest_handover_at) if time] or [as_of]),
        "in_use_only": latest_unknown or latest_unknown_weak or as_of,
        "unverified": as_of,
    }[verdict]

    for window in windows:
        if window.status in ("lost", "degraded") and window.site == claim.site:
            window_range = "（%s 至 %s）" % (iso_z(window.start), iso_z(window.end)) if window.start and window.end else ""
            caveats.append(
                "%s 采集窗口%s状态为 %s：%s"
                % (
                    window.source.upper(),
                    window_range,
                    window.status,
                    window.reason or "未说明原因",
                )
            )

    return {
        "address": claim.address,
        "site": claim.site,
        "legacy_device": claim.legacy_device,
        "preservation_record": claim.record_id,
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict],
        "confidence": confidence,
        "confidence_label": CONFIDENCE_LABELS[confidence],
        "decided_at": iso_z(decided_at),
        "basis": [entry["record_id"] for entry in support],
        "supporting_records": support,
        "absent_records": absent,
        "context_records": context,
        "conflicting_records": conflicts,
        "caveats": caveats,
        "timeline": [_event_to_timeline(event) for event in events],
        "_events": events,
        "_base": base,
        "_matching_handovers": matching_handovers,
        "_old_macs": sorted(old_macs),
        "_new_macs": sorted(new_macs),
    }


def _input_manifest(entries: Sequence[Tuple[str, str]]) -> List[dict]:
    manifest = []
    for role, path in entries:
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            raise InputError("cannot stat %s: %s" % (path, exc))
        manifest.append(
            {
                "role": role,
                "path": path,
                "bytes": size,
                "sha256": sha256_file(path),
            }
        )
    return manifest


def _determine_as_of(
    as_of_text: Optional[str],
    claims: Sequence[AddressClaim],
    inventory: Inventory,
    handovers: Sequence[HandoverRecord],
    dhcp_records: Sequence[DhcpAck],
    arp_records: Sequence[ArpBinding],
) -> Tuple[datetime, str]:
    if as_of_text:
        return parse_time(as_of_text, "--as-of"), "explicit"
    times = []
    for claim in claims:
        if claim.recorded_at:
            times.append(claim.recorded_at)
    for device in list(inventory.old_devices) + list(inventory.new_devices):
        if device.decommissioned_at:
            times.append(device.decommissioned_at)
    times.extend(handover.at for handover in handovers)
    times.extend(ack.captured_at for ack in dhcp_records)
    times.extend(binding.captured_at for binding in arp_records)
    if not times:
        return datetime.now(timezone.utc).replace(microsecond=0), "no-evidence"
    return max(times), "latest-evidence"


def build_report(
    ticket_path: str,
    preservation_path: str,
    handover_paths: Sequence[str],
    dhcp_paths: Sequence[str],
    arp_paths: Sequence[str],
    coverage_path: Optional[str] = None,
    as_of_text: Optional[str] = None,
) -> dict:
    inventory = load_ticket(ticket_path)
    claims, preservation_time, preservation_id = load_preservation(preservation_path)
    handovers = load_handovers(handover_paths)
    windows = load_coverage(coverage_path)
    dhcp_records = read_dhcp_acks(dhcp_paths)
    arp_records = read_arp_bindings(arp_paths)
    as_of, as_of_source = _determine_as_of(
        as_of_text, claims, inventory, handovers, dhcp_records, arp_records
    )

    manifest_entries = [("ticket", ticket_path), ("preservation", preservation_path)]
    manifest_entries.extend(("handover", path) for path in handover_paths)
    if coverage_path:
        manifest_entries.append(("coverage", coverage_path))
    manifest_entries.extend(("dhcp_pcap", path) for path in dhcp_paths)
    manifest_entries.extend(("arp_pcap", path) for path in arp_paths)
    manifest = _input_manifest(manifest_entries)

    warnings: List[dict] = []
    seen_claims = set()
    unique_claims = []
    for claim in claims:
        key = (claim.address, claim.site)
        if key in seen_claims:
            warnings.append(
                {
                    "code": "duplicate_preservation_claim",
                    "address": claim.address,
                    "message": "保全文件重复登记了 %s，只处理第一条记录 %s"
                    % (claim.address, claim.record_id),
                }
            )
            continue
        seen_claims.add(key)
        unique_claims.append(claim)

    results = [
        _analyze_claim(
            claim, inventory, handovers, dhcp_records, arp_records, windows, as_of, warnings
        )
        for claim in unique_claims
    ]
    for result in results:
        for key in list(result):
            if key.startswith("_"):
                del result[key]

    counts = {key: 0 for key in VERDICT_LABELS}
    for result in results:
        counts[result["verdict"]] += 1
    sites = {}
    for result in results:
        site = result["site"] or "(unspecified)"
        sites.setdefault(site, {key: 0 for key in VERDICT_LABELS})
        sites[site][result["verdict"]] += 1

    control_plane_gaps = []
    for window in windows:
        if window.status in ("lost", "degraded"):
            control_plane_gaps.append(
                {
                    "source": window.source,
                    "site": window.site,
                    "start": iso_z(window.start) if window.start else None,
                    "end": iso_z(window.end) if window.end else None,
                    "status": window.status,
                    "reason": window.reason,
                }
            )

    devices = []
    for device in list(inventory.old_devices) + list(inventory.new_devices):
        devices.append(
            {
                "device_id": device.device_id,
                "name": device.name,
                "site": device.site,
                "mac": device.mac,
                "role": device.role,
                "decommissioned_at": iso_z(device.decommissioned_at)
                if device.decommissioned_at
                else None,
            }
        )

    return {
        "schema": SCHEMA_VERSION,
        "tool": "tools.retired_address_audit",
        "policy_version": POLICY_VERSION,
        "ticket": {
            "ticket_id": inventory.ticket_id,
            "title": inventory.title,
            "source": inventory.source_path,
            "devices": devices,
        },
        "preservation": {
            "file_id": preservation_id,
            "source": preservation_path,
            "recorded_at": iso_z(preservation_time) if preservation_time else None,
            "addresses": [
                {
                    "address": claim.address,
                    "site": claim.site,
                    "legacy_device": claim.legacy_device,
                    "legacy_mac": claim.legacy_mac,
                    "record_id": claim.record_id,
                    "recorded_at": iso_z(claim.recorded_at) if claim.recorded_at else None,
                }
                for claim in claims
            ],
        },
        "handovers": [
            {
                "record_id": handover.record_id,
                "at": iso_z(handover.at),
                "site": handover.site,
                "address": handover.address,
                "from_device": handover.from_device,
                "to_device": handover.to_device,
                "from_mac": handover.from_mac or _resolved_handover_old_mac(handover, inventory.old_devices),
                "to_mac": _resolved_handover_mac(handover, inventory.new_devices),
                "ticket_id": handover.ticket_id,
            }
            for handover in handovers
        ],
        "captures": {
            "dhcp_ack_records": len(dhcp_records),
            "arp_binding_records": len(arp_records),
            "dhcp_pcaps": list(dhcp_paths),
            "arp_pcaps": list(arp_paths),
        },
        "coverage_windows": [
            {
                "source": window.source,
                "site": window.site,
                "start": iso_z(window.start) if window.start else None,
                "end": iso_z(window.end) if window.end else None,
                "status": window.status,
                "reason": window.reason,
            }
            for window in windows
        ],
        "control_plane_gaps": control_plane_gaps,
        "as_of": iso_z(as_of),
        "as_of_source": as_of_source,
        "inputs": manifest,
        "warnings": warnings,
        "method": {
            "cutover": "取该地址交接单时间与旧设备工单下线时间的较晚者",
            "old_device": "交接后仍出现旧 MAC 的 DHCPACK/ARP，或旧租约跨过交接时点且仍有效",
            "new_device": "交接单把地址转给新设备，且没有更晚的旧设备身份；新 DHCPACK/ARP 可加强结论",
            "in_use_only": "有 DHCPACK/ARP 证明地址在用，但 MAC 不属于旧设备或交接单中的新设备",
            "ordering": "同一身份以最新起始时间为准；更晚的新设备确认会覆盖跨交接的旧租约，"
            "更晚的未知 MAC 会把结论降为仅确认在用",
        },
        "summary": {
            "addresses": len(results),
            **counts,
            "by_site": sites,
            "old_device_addresses": [
                result["address"] for result in results if result["verdict"] == "old_device"
            ],
        },
        "addresses": results,
    }


def _md_cell(value) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _timeline_detail(item: dict) -> str:
    detail = item.get("detail") or {}
    kind = item["kind"]
    if kind == "dhcp_ack":
        if detail.get("lease_infinite"):
            lease = "无限期"
        elif detail.get("lease_seconds") is not None:
            lease = "%ss" % detail["lease_seconds"]
        elif detail.get("lease_present"):
            lease = "已确认"
        else:
            lease = "租期字段缺席"
        return "MAC %s；租期 %s；到期 %s" % (
            item.get("mac") or "未知",
            lease,
            detail.get("lease_end") or "-",
        )
    if kind == "arp_binding":
        return "%s/%s：%s" % (
            detail.get("role", "sender"),
            detail.get("operation", ""),
            item.get("mac") or "未知 MAC",
        )
    if kind == "handover":
        return "%s → %s" % (detail.get("from_device") or "?", detail.get("to_device") or "?")
    if kind in ("preservation", "decommission"):
        return item.get("device_id") or detail.get("legacy_device") or ""
    return ""


def report_to_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# 退役地址只读核对",
        "",
        "工单：`%s` %s" % (report["ticket"]["ticket_id"], report["ticket"].get("title") or ""),
        "",
        "核对时点：`%s`（%s）" % (report["as_of"], report["as_of_source"]),
        "",
        "结论分布：仍属旧设备 **%d**；可归到新设备 **%d**；只能确认地址在用 **%d**；证据不足 **%d**。"
        % (
            summary["old_device"],
            summary["new_device"],
            summary["in_use_only"],
            summary["unverified"],
        ),
        "",
        "## 地址结论",
        "",
        "| 地址 | 站点 | 原设备 | 结论 | 置信度 | 支持记录 | 缺席记录 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for result in report["addresses"]:
        support = ", ".join("`%s`" % entry["record_id"] for entry in result["supporting_records"])
        absent = ", ".join("`%s`" % entry["kind"] for entry in result["absent_records"])
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                result["address"],
                _md_cell(result["site"]),
                _md_cell(result["legacy_device"]),
                result["verdict_label"],
                result["confidence_label"],
                support or "—",
                absent or "—",
            )
        )
    lines.extend(["", "## 采集缺口", ""])
    if report["control_plane_gaps"]:
        lines.append("| 来源 | 站点 | 窗口 | 状态 | 原因 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for gap in report["control_plane_gaps"]:
            lines.append(
                "| %s | %s | %s ~ %s | %s | %s |"
                % (
                    gap["source"].upper(),
                    _md_cell(gap["site"]),
                    gap["start"] or "?",
                    gap["end"] or "?",
                    gap["status"],
                    _md_cell(gap["reason"] or "未说明"),
                )
            )
    else:
        lines.append("未声明控制面采集缺口。")

    for result in report["addresses"]:
        lines.extend(["", "## %s — %s" % (result["address"], result["verdict_label"]), ""])
        lines.append(
            "站点 `%s`；原设备 `%s`；判定时点 `%s`；置信度 %s。"
            % (
                result["site"] or "(unspecified)",
                result["legacy_device"] or "(missing)",
                result["decided_at"],
                result["confidence_label"],
            )
        )
        lines.extend(["", "**支持记录**", ""])
        if result["supporting_records"]:
            for entry in result["supporting_records"]:
                lines.append(
                    "- `%s`（%s，%s）：%s"
                    % (entry["record_id"], entry["kind"], entry["at"], entry["why"])
                )
        else:
            lines.append("- 无")
        lines.extend(["", "**缺席记录**", ""])
        if result["absent_records"]:
            for entry in result["absent_records"]:
                observation = entry["observation"]
                lines.append(
                    "- `%s`（%s）：%s；采集状态 `%s`，%s"
                    % (
                        entry["kind"],
                        entry["impact_label"],
                        entry["role"],
                        observation.get("status"),
                        observation.get("note") or "",
                    )
                )
        else:
            lines.append("- 无")
        if result["conflicting_records"]:
            lines.extend(["", "**冲突记录**", ""])
            for entry in result["conflicting_records"]:
                lines.append(
                    "- `%s`：%s"
                    % (entry.get("record_id", entry.get("kind", "")), entry.get("why", entry.get("message", "")))
                )
        if result["caveats"]:
            lines.extend(["", "**注意**", ""])
            for caveat in result["caveats"]:
                lines.append("- %s" % caveat)
        lines.extend(["", "**时间线**", ""])
        lines.append("| 时间 | 类型 | 记录 | 身份/租期 |")
        lines.append("| --- | --- | --- | --- |")
        for item in result["timeline"]:
            lines.append(
                "| %s | %s | `%s` | %s |"
                % (
                    item["at"],
                    item.get("kind_label", item["kind"]),
                    item["record_id"],
                    _md_cell(_timeline_detail(item)),
                )
            )

    lines.extend(["", "## 输入清单", ""])
    lines.append("| 角色 | 路径 | SHA-256 |")
    lines.append("| --- | --- | --- |")
    for item in report["inputs"]:
        lines.append(
            "| %s | `%s` | `%s…` |" % (item["role"], item["path"], item["sha256"][:16])
        )
    if report["warnings"]:
        lines.extend(["", "## 输入警告", ""])
        for warning in report["warnings"]:
            lines.append("- `%s` %s：%s" % (warning.get("code", ""), warning.get("address", ""), warning.get("message", "")))
    lines.append("")
    return "\n".join(lines)


def _output_conflicts(output_path: str, inputs: Sequence[str]) -> bool:
    output = os.path.realpath(output_path)
    for path in inputs:
        if not path:
            continue
        if output == os.path.realpath(path):
            return True
        try:
            if os.path.samefile(output_path, path):
                return True
        except OSError:
            pass
    return False


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only reconciliation of addresses preserved from retired devices"
    )
    parser.add_argument("--ticket", required=True, help="migration ticket (JSON/JSONL/CSV)")
    parser.add_argument("--preservation", required=True, help="address preservation file")
    parser.add_argument("--handover", action="append", default=[], help="device handover sheet; repeatable")
    parser.add_argument("--dhcp-pcap", action="append", default=[], help="pcap with DHCPACK records; repeatable")
    parser.add_argument("--arp-pcap", action="append", default=[], help="pcap with ARP records; repeatable")
    parser.add_argument("--coverage", help="JSON/JSONL/CSV capture coverage and gaps")
    parser.add_argument("--as-of", help="evaluate only records at or before this ISO-8601 time")
    parser.add_argument("--output", help="write report here; inputs are never overwritten")
    parser.add_argument("--format", choices=("json", "markdown"), help="report format (inferred from --output)")
    parser.add_argument(
        "--fail-on-old",
        action="store_true",
        help="exit with status 2 when any address is still bound to an old device",
    )
    args = parser.parse_args(argv)

    inputs = [args.ticket, args.preservation, args.coverage] + list(args.handover) + list(
        args.dhcp_pcap
    ) + list(args.arp_pcap)
    if args.output and _output_conflicts(args.output, inputs):
        parser.error("--output must not be the same file as any input")

    try:
        report = build_report(
            ticket_path=args.ticket,
            preservation_path=args.preservation,
            handover_paths=args.handover,
            dhcp_paths=args.dhcp_pcap,
            arp_paths=args.arp_pcap,
            coverage_path=args.coverage,
            as_of_text=args.as_of,
        )
    except (InputError, EvidenceError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    report_format = args.format
    if report_format is None:
        report_format = "markdown" if args.output and args.output.lower().endswith((".md", ".markdown")) else "json"
    if report_format == "json":
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
    else:
        rendered = report_to_markdown(report)

    if args.output:
        try:
            Path(args.output).write_text(
                rendered + ("" if rendered.endswith("\n") else "\n"), encoding="utf-8"
            )
        except OSError as exc:
            print("error: cannot write %s: %s" % (args.output, exc), file=sys.stderr)
            return 1
    else:
        print(rendered)

    if args.fail_on_old and report["summary"]["old_device"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
