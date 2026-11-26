"""Offline direction attribution for mirrored Ethernet captures.

The module never sends packets or performs scans.  It reads pcap/pcapng files
with dpkt and combines link-layer evidence with a trusted mirror-port ledger
and capture scope.  MAC addresses are retained as evidence, but are never by
themselves treated as proof of inbound/outbound direction.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import dpkt
from dpkt import ethernet as dpkt_ethernet
from dpkt import pcap as dpkt_pcap


ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_IP6 = 0x86DD
ETH_TYPE_MPLS = 0x8847
ETH_TYPE_MPLS_MCAST = 0x8848
ETH_TYPE_8021Q = 0x8100
ETH_TYPE_8021AD = 0x88A8
QINQ_TPIDS = {0x9100, 0x9200, 0x9300}
VLAN_TPIDS = {ETH_TYPE_8021Q, ETH_TYPE_8021AD, *QINQ_TPIDS}

DLT_EN10MB = dpkt_pcap.DLT_EN10MB
DLT_LINUX_SLL = getattr(dpkt_pcap, "DLT_LINUX_SLL", 113)
DLT_LINUX_SLL2 = getattr(dpkt_pcap, "DLT_LINUX_SLL2", 276)

LINKTYPE_NAMES = {
    0: "NULL/LOOP",
    1: "EN10MB/Ethernet",
    113: "LINUX_SLL",
    276: "LINUX_SLL2",
    101: "RAW",
    12: "RAW/OPENBSD",
    108: "LOOP",
}

ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q",
    0x86DD: "IPv6",
    0x8847: "MPLS",
    0x8848: "MPLS multicast",
    0x88A8: "802.1ad QinQ",
    0x9100: "QinQ",
    0x9200: "QinQ",
    0x9300: "QinQ",
}


_INBOUND_WORDS = {
    "inbound", "in", "ingress", "rx", "receive", "received", "input",
    "入站", "入", "进站", "流入", "接收",
}
_OUTBOUND_WORDS = {
    "outbound", "out", "egress", "tx", "transmit", "transmitted", "output",
    "出站", "出", "出发", "流出", "发送",
}
_BOTH_WORDS = {
    "both", "bidirectional", "bi-directional", "all", "rxtx", "rx_tx",
    "full", "双向", "入站出站", "进出站",
}


def _norm_token(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    text = text.replace("-", "_").replace(" ", "_")
    text = re.sub(r"[\s/\\.:：]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


def normalize_mac(value: Any) -> Optional[str]:
    """Return a canonical lowercase colon MAC, or None when unavailable."""
    if value is None:
        return None
    if isinstance(value, bytes):
        if len(value) != 6:
            return None
        return ":".join(f"{octet:02x}" for octet in value)
    text = str(value).strip().lower()
    if not text:
        return None
    cleaned = re.sub(r"[^0-9a-f]", "", text)
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    if len(text) == 17 and text.count(":") == 5:
        return text
    return None


def mac_to_str(value: Any) -> Optional[str]:
    return normalize_mac(value)


def parse_vlan_ids(value: Any) -> List[int]:
    """Parse ints, VLAN names, comma lists and inclusive ranges."""
    if value is None or value == "":
        return []
    if isinstance(value, Mapping):
        for key in ("id", "vlan", "vlan_id", "vid"):
            if key in value:
                return parse_vlan_ids(value[key])
        return []
    if isinstance(value, (list, tuple, set)):
        result: List[int] = []
        for item in value:
            result.extend(parse_vlan_ids(item))
        return sorted(set(result))
    if isinstance(value, int):
        return [value] if 0 <= value <= 4095 else []

    text = str(value).strip()
    text = re.sub(r"(?i)vlan\s*", "", text)
    result = []
    for part in re.split(r"[,;、/\s]+", text):
        part = part.strip()
        if not part:
            continue
        range_match = re.fullmatch(r"(\d{1,4})\s*-\s*(\d{1,4})", part)
        if range_match:
            start, end = map(int, range_match.groups())
            result.extend(range(min(start, end), max(start, end) + 1))
            continue
        try:
            vid = int(part, 0)
        except ValueError:
            continue
        if 0 <= vid <= 4095:
            result.append(vid)
    return sorted(set(result))


def normalize_direction(value: Any) -> List[str]:
    """Normalize common Chinese/English and rx/tx direction labels."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        result: List[str] = []
        for item in value:
            result.extend(normalize_direction(item))
        return sorted(set(result))

    raw = str(value).strip()
    compact = raw.replace("/", "_").replace("、", "_").replace(",", "_")
    parts = [part for part in compact.split("_") if part]
    if len(parts) > 1:
        result: List[str] = []
        for part in parts:
            result.extend(normalize_direction(part))
        return sorted(set(result))

    token = _norm_token(raw)
    if token in _BOTH_WORDS or token.replace("_", "") in _BOTH_WORDS:
        return ["inbound", "outbound"]
    if token in _INBOUND_WORDS or token.replace("_", "") in _INBOUND_WORDS:
        return ["inbound"]
    if token in _OUTBOUND_WORDS or token.replace("_", "") in _OUTBOUND_WORDS:
        return ["outbound"]
    return [token] if token else []


def directions_compatible(claimed: Any, candidates: Sequence[str]) -> bool:
    claimed_dirs = normalize_direction(claimed)
    candidate_dirs = set(normalize_direction(candidates))
    return any(direction in candidate_dirs for direction in claimed_dirs)


def _first_key(data: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    lower_map = {str(k).strip().lower(): k for k in data}
    for key in keys:
        actual = lower_map.get(key.lower())
        if actual is not None and data[actual] not in (None, ""):
            return data[actual]
    return None


def _as_mapping_list(data: Any, list_keys: Sequence[str]) -> List[Mapping[str, Any]]:
    if data is None:
        return []
    if isinstance(data, MirrorLedger):
        return [record.raw for record in data.records]
    if isinstance(data, Mapping):
        for key in list_keys:
            value = _first_key(data, [key])
            if isinstance(value, list):
                return value
        for value in data.values():
            if isinstance(value, list) and all(isinstance(item, Mapping) for item in value):
                return value
        return [data]
    if isinstance(data, list):
        return data
    raise TypeError(f"Expected mapping/list ledger data, got {type(data).__name__}")


def load_structured_file(path: Union[str, Path]) -> Any:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    suffix = path.suffix.lower()
    if suffix == ".csv" or suffix == ".tsv":
        delimiter = "\t" if suffix == ".tsv" else ","
        with path.open(newline="", encoding="utf-8-sig") as handle:
            return list(csv.DictReader(handle, delimiter=delimiter))
    if suffix in {".toml", ".tml"}:
        try:
            import tomllib
        except ImportError:  # pragma: no cover
            import tomli as tomllib  # type: ignore
        return tomllib.loads(text)
    return json.loads(text)


POINT_FIELDS = (
    "capture_point", "capture_point_id", "point", "probe", "probe_id",
    "sensor", "sensor_id", "collector", "collector_id", "source", "source_id",
    "capture_source", "capture_interface", "interface", "iface",
    "interface_name", "mirror_port", "mirror_interface", "span_port",
    "monitor_port", "destination_port", "dest_port", "port_id", "id", "name",
    "采集点", "采集节点", "探针", "探头", "采集口", "采集接口", "镜像口",
    "镜像端口", "监控口", "目的端口", "端口编号", "编号", "名称",
)

MONITORED_PORT_FIELDS = (
    "monitored_port", "source_port", "observed_port", "ingress_port",
    "monitored_interface", "source_interface", "被镜像端口", "源端口",
    "监控端口", "业务端口",
)

VLAN_FIELDS = (
    "vlans", "vlan_ids", "allowed_vlans", "expected_vlans", "vlan",
    "vlan_id", "outer_vlan", "outer_vlan_id", "outer_vlans", "vid",
    "vlan_list", "outer_tag", "outer_tags", "vlan_tags",
    "vlan", "外层vlan", "外层标签", "外层虚拟局域网",
)

DIRECTION_FIELDS = (
    "directions", "direction", "mirror_direction", "span_direction",
    "observed_direction", "traffic_direction", "方向", "镜像方向",
    "流量方向",
)


@dataclass
class MirrorPortRecord:
    raw: Mapping[str, Any]
    record_id: Optional[str] = None
    keys: List[str] = field(default_factory=list)
    vlans: List[int] = field(default_factory=list)
    directions: List[str] = field(default_factory=list)
    monitored_ports: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        data = dict(self.raw)
        self.record_id = str(_first_key(data, ("id", "record_id", "ledger_id", "编号")) or "") or None
        key_values: List[Any] = []
        for field_name in POINT_FIELDS:
            value = _first_key(data, [field_name])
            if value not in (None, ""):
                key_values.append(value)
        self.keys = sorted({_norm_token(value) for value in key_values if _norm_token(value)})

        vlan_values: List[Any] = []
        for field_name in VLAN_FIELDS:
            value = _first_key(data, [field_name])
            if value not in (None, ""):
                vlan_values.append(value)
        self.vlans = parse_vlan_ids(vlan_values)

        direction_values: List[Any] = []
        for field_name in DIRECTION_FIELDS:
            value = _first_key(data, [field_name])
            if value not in (None, ""):
                direction_values.append(value)
        self.directions = normalize_direction(direction_values)

        monitored = []
        for field_name in MONITORED_PORT_FIELDS:
            value = _first_key(data, [field_name])
            if value not in (None, ""):
                monitored.append(str(value))
        self.monitored_ports = monitored

    def matches(self, query_keys: Iterable[str]) -> bool:
        wanted = {_norm_token(key) for key in query_keys if _norm_token(key)}
        return bool(wanted.intersection(self.keys))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "lookup_keys": self.keys,
            "vlans": self.vlans,
            "directions": self.directions,
            "monitored_ports": self.monitored_ports,
            "raw": dict(self.raw),
        }


class MirrorLedger:
    """Trusted mirror-port ledger indexed by collector/interface/port names."""

    def __init__(self, data: Any = None) -> None:
        if data is None:
            data = []
        if isinstance(data, (str, Path)):
            data = load_structured_file(data)
        records = _as_mapping_list(data, ("mirror_ports", "ports", "records", "items", "data"))
        self.records = [MirrorPortRecord(record) for record in records if isinstance(record, Mapping)]
        self.index: Dict[str, List[MirrorPortRecord]] = {}
        for record in self.records:
            for key in record.keys:
                self.index.setdefault(key, []).append(record)

    def lookup(self, **query: Any) -> List[MirrorPortRecord]:
        keys: List[str] = []
        for value in query.values():
            if value is None:
                continue
            if isinstance(value, (list, tuple, set)):
                keys.extend(str(item) for item in value if item)
            else:
                text = str(value)
                keys.append(text)
                path = Path(text)
                keys.extend([path.name, path.stem])
        normalized = {_norm_token(key) for key in keys if _norm_token(key)}
        found: Dict[int, MirrorPortRecord] = {}
        for key in normalized:
            for record in self.index.get(key, []):
                found[id(record)] = record
            # Also allow substring-free filename stems such as capture-a.pcap.
            for indexed_key, records in self.index.items():
                if key and (key == indexed_key or key.endswith("_" + indexed_key) or indexed_key.endswith("_" + key)):
                    for record in records:
                        found[id(record)] = record
        return list(found.values())


def coerce_ledger(data: Any) -> MirrorLedger:
    if isinstance(data, MirrorLedger):
        return data
    return MirrorLedger(data)


def coerce_scope(scope: Any) -> Dict[str, Any]:
    if scope is None:
        return {}
    if isinstance(scope, (str, Path)):
        scope = load_structured_file(scope)
    if isinstance(scope, Mapping):
        return dict(scope)
    raise TypeError("scope must be a mapping, path, or None")


def scope_points(scope: Mapping[str, Any]) -> List[str]:
    values = []
    for key in (
        "capture_points", "points", "mirror_ports", "collectors", "probes",
        "allowed_points", "allowed_mirror_ports", "采集点", "镜像口",
    ):
        value = _first_key(scope, [key])
        if value:
            values.extend(value if isinstance(value, (list, tuple, set)) else [value])
    return sorted({_norm_token(value) for value in values if _norm_token(value)})


def scope_vlans(scope: Mapping[str, Any], capture_point: Optional[str] = None) -> List[int]:
    vlans = parse_vlan_ids([
        scope.get(key) for key in ("vlans", "allowed_vlans", "vlan_ids", "scope_vlans")
        if key in scope
    ])
    point_map = scope.get("point_vlans") or scope.get("vlans_by_point") or {}
    if isinstance(point_map, Mapping) and capture_point:
        wanted = _norm_token(capture_point)
        for key, value in point_map.items():
            if _norm_token(key) == wanted:
                vlans.extend(parse_vlan_ids(value))
    return sorted(set(vlans))


def parse_scope_time(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def parse_outer_tags(raw: bytes) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Optional[int]]:
    vlans: List[Dict[str, Any]] = []
    mpls: List[Dict[str, Any]] = []
    if len(raw) < 14:
        if len(raw) >= 13:
            tpid = int.from_bytes(raw[12:14], "big") if len(raw) >= 14 else None
            if tpid in VLAN_TPIDS:
                vlans.append({"tpid": f"0x{tpid:04x}", "truncated": True})
        return vlans, mpls, None

    offset = 12
    ethertype = int.from_bytes(raw[12:14], "big")
    final_ethertype = ethertype

    while ethertype in VLAN_TPIDS:
        if len(raw) < offset + 4:
            vlans.append({
                "tpid": f"0x{ethertype:04x}",
                "tpid_name": ETHERTYPE_NAMES.get(ethertype, "VLAN"),
                "truncated": True,
                "raw_hex": raw[offset:].hex(),
            })
            final_ethertype = None
            return vlans, mpls, final_ethertype

        tci = int.from_bytes(raw[offset + 2:offset + 4], "big")
        tag: Dict[str, Any] = {
            "tpid": f"0x{ethertype:04x}",
            "tpid_name": ETHERTYPE_NAMES.get(ethertype, "VLAN"),
            "pcp": (tci >> 13) & 0x07,
            "dei": (tci >> 12) & 0x01,
            "cfi": (tci >> 12) & 0x01,
            "vlan_id": tci & 0x0FFF,
            "tci": tci,
            "raw_hex": raw[offset:offset + 4].hex(),
            "truncated": False,
        }
        next_offset = offset + 4
        if len(raw) >= next_offset + 2:
            ethertype = int.from_bytes(raw[next_offset:next_offset + 2], "big")
            tag["next_ethertype"] = f"0x{ethertype:04x}"
            tag["next_ethertype_name"] = ETHERTYPE_NAMES.get(ethertype)
        else:
            tag["next_ethertype"] = None
            tag["truncated"] = True
            vlans.append(tag)
            final_ethertype = None
            return vlans, mpls, final_ethertype

        vlans.append(tag)
        final_ethertype = ethertype
        offset = next_offset
        if ethertype not in VLAN_TPIDS:
            break

    cursor = offset + 2
    if final_ethertype in {ETH_TYPE_MPLS, ETH_TYPE_MPLS_MCAST}:
        while cursor + 4 <= len(raw) and len(mpls) < 24:
            label_bytes = raw[cursor:cursor + 4]
            word = struct.unpack("!I", label_bytes)[0]
            mpls.append({
                "label": word >> 12,
                "traffic_class": (word >> 9) & 0x07,
                "bottom_of_stack": bool((word >> 8) & 0x01),
                "ttl": word & 0xFF,
                "raw_hex": label_bytes.hex(),
            })
            cursor += 4
            if (word >> 8) & 0x01:
                break

    return vlans, mpls, final_ethertype


def parse_frame(
    raw: Any,
    *,
    linktype: int = DLT_EN10MB,
    frame_number: Optional[int] = None,
    timestamp: Optional[float] = None,
    source: Optional[str] = None,
    source_id: Optional[str] = None,
    capture_point: Optional[str] = None,
    interface_id: Optional[Any] = None,
    interface_name: Optional[str] = None,
    caplen: Optional[int] = None,
    orig_len: Optional[int] = None,
    record_format: Optional[str] = None,
    warnings: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Parse one captured frame and preserve link-layer evidence."""
    raw = bytes(raw or b"")
    included_len = len(raw)
    caplen = included_len if caplen is None else int(caplen)
    orig_len = caplen if orig_len is None else int(orig_len)

    evidence: Dict[str, Any] = {
        "frame_number": frame_number,
        "timestamp": timestamp,
        "source": source,
        "source_id": source_id or (Path(str(source)).name if source else None),
        "capture_point": capture_point,
        "interface_id": interface_id,
        "interface_name": interface_name,
        "record_format": record_format,
        "linktype": linktype,
        "linktype_name": LINKTYPE_NAMES.get(linktype, f"DLT_{linktype}"),
        "included_len": included_len,
        "captured_len": caplen,
        "caplen": caplen,
        "original_len": orig_len,
        "orig_len": orig_len,
        "wire_truncated": caplen < orig_len,
        "read_truncated": included_len < caplen,
        "frame_sha256": hashlib.sha256(raw).hexdigest(),
        "link_header_hex": raw[:64].hex(),
        "raw_hex": raw.hex(),
        "raw": raw,
        "src_mac": None,
        "dst_mac": None,
        "ethertype": None,
        "ethertype_name": None,
        "vlan_tags": [],
        "vlan_ids": [],
        "outer_vlan": None,
        "mpls_labels": [],
        "dpkt_parsed": False,
        "dpkt_error": None,
        "parse_errors": [],
        "warnings": [],
    }
    if warnings:
        evidence["warnings"].extend(str(item) for item in warnings)

    if source_id is None and source:
        evidence["source_id"] = Path(str(source)).name
    stem = evidence["source_id"] or capture_point or "capture"
    canonical_id = f"{stem}#{frame_number}" if frame_number is not None else f"{stem}#frame"
    evidence["evidence_id"] = canonical_id
    aliases = {canonical_id}
    if evidence.get("source_id"):
        source_path = Path(str(evidence["source_id"]))
        if source_path.suffix:
            aliases.add(f"{source_path.stem}#{frame_number if frame_number is not None else 'frame'}")
    if capture_point and frame_number is not None:
        aliases.add(f"{capture_point}#{frame_number}")
    evidence["evidence_aliases"] = sorted(aliases)

    if linktype == DLT_EN10MB:
        evidence["link_layer"] = "Ethernet"
        if len(raw) >= 6:
            evidence["dst_mac"] = normalize_mac(raw[0:6])
        if len(raw) >= 12:
            evidence["src_mac"] = normalize_mac(raw[6:12])
        if len(raw) >= 14:
            ethertype = int.from_bytes(raw[12:14], "big")
            evidence["ethertype"] = f"0x{ethertype:04x}"
            evidence["ethertype_value"] = ethertype
            evidence["ethertype_name"] = ETHERTYPE_NAMES.get(ethertype)
        else:
            evidence["parse_errors"].append("short Ethernet header")

        vlan_tags, mpls_labels, final_ethertype = parse_outer_tags(raw)
        evidence["vlan_tags"] = vlan_tags
        evidence["mpls_labels"] = mpls_labels
        evidence["vlan_ids"] = [tag["vlan_id"] for tag in vlan_tags if "vlan_id" in tag]
        evidence["outer_vlan"] = evidence["vlan_ids"][0] if evidence["vlan_ids"] else None
        if final_ethertype is not None and len(raw) >= 14:
            evidence["inner_ethertype"] = f"0x{final_ethertype:04x}"
            evidence["inner_ethertype_name"] = ETHERTYPE_NAMES.get(final_ethertype)

        try:
            dpkt_ethernet.Ethernet(raw)
            evidence["dpkt_parsed"] = True
        except Exception as exc:  # offline untrusted frames must not abort audit
            evidence["dpkt_error"] = f"{type(exc).__name__}: {exc}"
            evidence["parse_errors"].append(evidence["dpkt_error"])

        evidence["link_header_complete"] = len(raw) >= 14
        evidence["header_truncated"] = (
            len(raw) < 14
            or any(tag.get("truncated") for tag in vlan_tags)
            or "NeedData" in (evidence["dpkt_error"] or "")
        )
    else:
        evidence["link_layer"] = evidence["linktype_name"]
        evidence["link_header_complete"] = False
        evidence["header_truncated"] = True
        evidence["warnings"].append("No Ethernet MAC decoder for linktype; ledger/capture metadata still usable")

    evidence["truncated"] = bool(
        evidence["wire_truncated"]
        or evidence["read_truncated"]
        or evidence["header_truncated"]
    )
    evidence["is_truncated"] = evidence["truncated"]
    evidence["mac_evidence_complete"] = bool(evidence["src_mac"] and evidence["dst_mac"])
    return evidence


# Friendly alias used by some task descriptions.
build_frame_evidence = parse_frame
parse_packet = parse_frame


def _pcapng_interface_name(interface: Any) -> Optional[str]:
    for option in getattr(interface, "opts", []) or []:
        if getattr(option, "code", None) == 2:  # if_name
            data = getattr(option, "data", b"") or b""
            if isinstance(data, str):
                return data.rstrip("\0")
            return bytes(data).rstrip(b"\0").decode("utf-8", "replace")
    return None


def normalize_source(source: Any, default_point: Optional[str] = None) -> Dict[str, Any]:
    if isinstance(source, (str, Path)):
        path = Path(source)
        return {
            "path": path,
            "source": str(path),
            "source_id": path.name,
            "capture_point": default_point or path.stem,
        }
    if isinstance(source, Mapping):
        item = dict(source)
        path = item.get("path") or item.get("file") or item.get("filename")
        if path is not None:
            path = Path(path)
            item.setdefault("source", str(path))
            item.setdefault("source_id", path.name)
            item.setdefault("capture_point", item.get("point") or path.stem)
        else:
            item.setdefault("source_id", item.get("source_id") or item.get("id") or "fileobj")
            item.setdefault("capture_point", item.get("point") or default_point)
        if default_point and not item.get("capture_point"):
            item["capture_point"] = default_point
        return item
    raise TypeError(f"Unsupported capture source: {type(source).__name__}")


def normalize_sources(captures: Any, capture_point: Optional[str] = None) -> List[Dict[str, Any]]:
    if captures is None:
        return []
    if isinstance(captures, Mapping) and not ("path" in captures or "fileobj" in captures or "file" in captures):
        return [
            normalize_source({"capture_point": point, "path": path}, capture_point)
            for point, path in captures.items()
        ]
    if isinstance(captures, (str, Path, Mapping)):
        return [normalize_source(captures, capture_point)]
    if isinstance(captures, (list, tuple)):
        return [normalize_source(item, capture_point) for item in captures]
    raise TypeError("captures must be a path, mapping, source dict, or sequence")


def iter_frames(source: Any, capture_point: Optional[str] = None) -> Iterable[Dict[str, Any]]:
    """Yield frame evidence from a pcap/pcapng source using dpkt."""
    src = normalize_source(source, capture_point)
    own_handle = False
    handle = src.get("fileobj") or src.get("handle")
    if handle is None:
        if not src.get("path"):
            raise ValueError("capture source has neither path nor fileobj")
        handle = Path(src["path"]).open("rb")
        own_handle = True

    try:
        reader = dpkt_pcap.UniversalReader(handle)
        linktype = reader.datalink() if callable(getattr(reader, "datalink", None)) else 1

        if isinstance(reader, dpkt_pcap.Reader):
            packet_header = reader._Reader__ph
            divisor = float(reader._divisor)
            frame_number = 0
            while True:
                header_buf = handle.read(packet_header.__hdr_len__)
                if not header_buf:
                    break
                if len(header_buf) < packet_header.__hdr_len__:
                    yield parse_frame(
                        b"", frame_number=frame_number + 1, source=src.get("source"),
                        source_id=src.get("source_id"), capture_point=src.get("capture_point"),
                        linktype=linktype, warnings=["truncated pcap packet header"],
                    )
                    break
                header = packet_header(header_buf)
                raw = handle.read(header.caplen)
                frame_number += 1
                timestamp = float(header.tv_sec) + float(header.tv_usec) / divisor
                evidence = parse_frame(
                    raw,
                    linktype=linktype,
                    frame_number=frame_number,
                    timestamp=timestamp,
                    source=src.get("source"),
                    source_id=src.get("source_id"),
                    capture_point=src.get("capture_point"),
                    caplen=header.caplen,
                    orig_len=header.len,
                    record_format="pcap",
                )
                yield evidence
            return

        # dpkt.pcapng.Reader: retain EPB interface and length metadata.
        import struct as _struct

        little_endian = bool(reader._Reader__le)
        divisor = float(reader._divisor)
        time_offset = float(getattr(reader, "_tsoffset", 0) or 0)
        interfaces = [reader.idb]
        frame_number = 0
        endian = "<" if little_endian else ">"
        while True:
            block_header = handle.read(8)
            if len(block_header) < 8:
                break
            block_type, block_len = _struct.unpack(endian + "II", block_header)
            if block_len < 12:
                break
            block_buf = block_header + handle.read(block_len - 8)

            if block_type == dpkt_pcapng_IDB_TYPE:
                from dpkt.pcapng import InterfaceDescriptionBlock, InterfaceDescriptionBlockLE
                idb_cls = InterfaceDescriptionBlockLE if little_endian else InterfaceDescriptionBlock
                interfaces.append(idb_cls(block_buf))
                continue

            if block_type == 0x00000006:  # Enhanced Packet Block
                from dpkt.pcapng import EnhancedPacketBlock, EnhancedPacketBlockLE
                epb_cls = EnhancedPacketBlockLE if little_endian else EnhancedPacketBlock
                block = epb_cls(block_buf)
                interface_id = int(block.iface_id)
                interface = interfaces[interface_id] if interface_id < len(interfaces) else reader.idb
                interface_name = _pcapng_interface_name(interface)
                interface_map = src.get("interface_map") or {}
                point = (
                    interface_map.get(str(interface_id))
                    or interface_map.get(interface_name or "")
                    or src.get("capture_point")
                    or interface_name
                    or f"pcapng-if{interface_id}"
                )
                timestamp = time_offset + (((block.ts_high << 32) | block.ts_low) / divisor)
                frame_number += 1
                yield parse_frame(
                    block.pkt_data,
                    linktype=getattr(interface, "linktype", linktype),
                    frame_number=frame_number,
                    timestamp=timestamp,
                    source=src.get("source"),
                    source_id=src.get("source_id"),
                    capture_point=point,
                    interface_id=interface_id,
                    interface_name=interface_name,
                    caplen=block.caplen,
                    orig_len=block.pkt_len,
                    record_format="pcapng",
                )
    finally:
        if own_handle:
            handle.close()


dpkt_pcapng_IDB_TYPE = 0x00000001


def read_capture(source: Any, capture_point: Optional[str] = None) -> List[Dict[str, Any]]:
    return list(iter_frames(source, capture_point))


def audit_frame(
    frame: Mapping[str, Any],
    ledger: Any = None,
    scope: Any = None,
) -> Dict[str, Any]:
    """Attach trusted ledger directions and scope checks to one frame."""
    result = dict(frame)
    ledger = coerce_ledger(ledger)
    scope = coerce_scope(scope)

    capture_point = result.get("capture_point")
    source = result.get("source")
    source_id = result.get("source_id")
    interface_name = result.get("interface_name")
    interface_id = result.get("interface_id")

    records = ledger.lookup(
        capture_point=capture_point,
        point=capture_point,
        source=source,
        source_id=source_id,
        interface=interface_name,
        interface_name=interface_name,
        interface_id=interface_id,
        mirror_port=capture_point,
    )
    result["ledger_records"] = [record.to_dict() for record in records]
    result["ledger_record_ids"] = [record.record_id for record in records if record.record_id]
    result["ledger_matched"] = bool(records)

    issues: List[Dict[str, Any]] = list(result.get("issues", []))
    conflicts: List[Dict[str, Any]] = list(result.get("conflicts", []))

    allowed_points = scope_points(scope)
    point_key = _norm_token(capture_point)
    if allowed_points and point_key and point_key not in allowed_points:
        issue = {
            "code": "capture_point_out_of_scope",
            "message": f"capture point {capture_point!r} is outside the trusted capture scope",
        }
        issues.append(issue)
        conflicts.append(issue)
    elif allowed_points and not point_key:
        issues.append({
            "code": "unknown_capture_point",
            "message": "frame has no capture point and cannot be proven to be in scope",
        })

    start = parse_scope_time(scope.get("start_time") or scope.get("start"))
    end = parse_scope_time(scope.get("end_time") or scope.get("end"))
    timestamp = result.get("timestamp")
    if timestamp is not None and start is not None and float(timestamp) < start:
        issues.append({"code": "before_capture_window", "message": "timestamp precedes capture scope"})
    if timestamp is not None and end is not None and float(timestamp) > end:
        issues.append({"code": "after_capture_window", "message": "timestamp follows capture scope"})

    actual_vlans = list(result.get("vlan_ids") or [])
    ledger_vlans = sorted({vlan for record in records for vlan in record.vlans})
    allowed_vlans = scope_vlans(scope, capture_point)
    expected_vlans = sorted(set(ledger_vlans) | set(allowed_vlans))
    result["ledger_vlans"] = ledger_vlans
    result["scope_vlans"] = allowed_vlans
    result["expected_vlans"] = expected_vlans

    vlan_matching_records = [
        record for record in records
        if not record.vlans or set(record.vlans).intersection(actual_vlans)
    ]
    if expected_vlans:
        if not actual_vlans:
            issue = {
                "code": "missing_outer_vlan",
                "message": f"trusted records expect VLAN(s) {expected_vlans}, but no outer VLAN tag is present",
                "expected_vlans": expected_vlans,
            }
            issues.append(issue)
            conflicts.append(issue)
        elif not set(expected_vlans).intersection(actual_vlans):
            issue = {
                "code": "vlan_mismatch",
                "message": f"outer VLAN {actual_vlans} is not in trusted VLAN set {expected_vlans}",
                "actual_vlans": actual_vlans,
                "expected_vlans": expected_vlans,
            }
            issues.append(issue)
            conflicts.append(issue)

    direction_sources: List[Dict[str, Any]] = []
    candidate_directions: List[str] = []
    for record in (vlan_matching_records or records):
        for direction in record.directions:
            candidate_directions.append(direction)
            direction_sources.append({
                "direction": direction,
                "record_id": record.record_id,
                "vlans": record.vlans,
                "monitored_ports": record.monitored_ports,
                "lookup_keys": record.keys,
            })
    result["direction_sources"] = direction_sources
    result["possible_directions"] = sorted(set(candidate_directions))
    result["directions"] = result["possible_directions"]
    result["multiple_directions_possible"] = len(result["possible_directions"]) > 1
    result["mac_is_direction_evidence"] = False
    result["mac_policy"] = "MAC association is not sufficient; use capture point and trusted ledger"

    if not records:
        result["attribution_status"] = "no_ledger_match"
    elif not result["possible_directions"]:
        result["attribution_status"] = "ledger_direction_unknown"
    elif result["multiple_directions_possible"]:
        result["attribution_status"] = "multiple_possible"
    else:
        result["attribution_status"] = "attributed"

    result["issues"] = issues
    result["conflicts"] = conflicts
    result["has_scope_or_vlan_conflict"] = bool(conflicts)
    return result


attribute_direction = audit_frame
attribute_frame = audit_frame


def _claim_value(claim: Mapping[str, Any], keys: Sequence[str]) -> Any:
    return _first_key(claim, keys)


def _evidence_ref_matches(ref: Any, frame: Mapping[str, Any]) -> bool:
    text_ref = str(ref)
    aliases = {str(frame.get("evidence_id")), *map(str, frame.get("evidence_aliases") or [])}
    if text_ref in aliases:
        return True

    ref_path, separator, ref_suffix = text_ref.partition("#")
    source_id = str(frame.get("source_id") or "")
    source_stem = Path(source_id).stem if source_id else ""
    if separator and ref_suffix == str(frame.get("frame_number")):
        ref_name = Path(ref_path).name
        if ref_name in {source_id, source_stem, str(frame.get("capture_point") or "")}:
            return True
    if not separator and text_ref == str(frame.get("frame_number")):
        return True
    if Path(text_ref).name == source_id:
        return True
    return False


def evaluate_claim(
    claim: Mapping[str, Any],
    frames: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Check one report direction assertion against attributed frame evidence."""
    claim_id = _claim_value(claim, ("claim_id", "id", "assertion_id", "label_id", "编号", "主张id"))
    claimed_direction = _claim_value(claim, (
        "claimed_direction", "direction", "report_direction", "label",
        "verdict", "主张方向", "方向",
    ))
    claim_mac = normalize_mac(_claim_value(claim, (
        "mac", "mac_address", "address", "hwaddr", "src_mac", "dst_mac", "mac地址",
    )))
    evidence_id = _claim_value(claim, ("evidence_id", "frame_id", "result_id", "evidence", "frame_result_id"))
    frame_ref = _claim_value(claim, ("frame_ref", "frame", "packet", "packet_id", "帧"))
    frame_number = _claim_value(claim, ("frame_number", "frame_index", "index", "number", "seq", "序号", "帧编号"))
    source = _claim_value(claim, ("source", "source_id", "file", "pcap", "capture_file"))
    capture_point = _claim_value(claim, ("capture_point", "point", "probe", "collector", "采集点"))

    if evidence_id is None and isinstance(frame_ref, str) and "#" in frame_ref:
        evidence_id = frame_ref

    candidates = list(frames)
    matching: List[Dict[str, Any]] = []

    if evidence_id is not None:
        matching = [frame for frame in candidates if _evidence_ref_matches(evidence_id, frame)]
    elif frame_ref is not None:
        matching = [frame for frame in candidates if _evidence_ref_matches(frame_ref, frame)]
    elif frame_number is not None:
        try:
            number = int(frame_number)
        except (TypeError, ValueError):
            number = None
        matching = [frame for frame in candidates if frame.get("frame_number") == number]
    elif claim_mac:
        matching = [
            frame for frame in candidates
            if claim_mac in {normalize_mac(frame.get("src_mac")), normalize_mac(frame.get("dst_mac"))}
        ]

    if source:
        source_key = _norm_token(source)
        source_filtered = [
            frame for frame in matching
            if source_key in {
                _norm_token(frame.get("source")),
                _norm_token(frame.get("source_id")),
                _norm_token(Path(str(frame.get("source") or "")).name),
            }
        ]
        if source_filtered:
            matching = source_filtered
    if capture_point:
        point_key = _norm_token(capture_point)
        point_filtered = [
            frame for frame in matching
            if _norm_token(frame.get("capture_point")) == point_key
        ]
        if point_filtered:
            matching = point_filtered

    findings: List[Dict[str, Any]] = []
    conflicting_ids: List[str] = []
    supported_ids: List[str] = []
    unverifiable_ids: List[str] = []
    mac_conflict_ids: List[str] = []

    for frame in matching:
        possible = list(frame.get("possible_directions") or [])
        relation = "unverifiable"
        direct_conflict = False
        mac_relation = "not_checked"

        if claim_mac:
            src_mac = normalize_mac(frame.get("src_mac"))
            dst_mac = normalize_mac(frame.get("dst_mac"))
            known_macs = {mac for mac in (src_mac, dst_mac) if mac}
            mac_evidence_complete = bool(frame.get("mac_evidence_complete")) or bool(src_mac and dst_mac)
            if not known_macs:
                mac_relation = "unverifiable_truncated_header"
            elif claim_mac in known_macs:
                role = []
                if claim_mac == src_mac:
                    role.append("src")
                if claim_mac == dst_mac:
                    role.append("dst")
                mac_relation = "matches_" + "_and_".join(role)
            elif not mac_evidence_complete:
                mac_relation = "unverifiable_truncated_header"
            else:
                mac_relation = "conflict"
                mac_conflict_ids.append(frame.get("evidence_id"))

        if normalize_direction(claimed_direction) and possible:
            if directions_compatible(claimed_direction, possible):
                relation = "supported"
                supported_ids.append(frame.get("evidence_id"))
            else:
                relation = "direction_conflict"
                direct_conflict = bool(frame.get("ledger_matched"))
                conflicting_ids.append(frame.get("evidence_id"))
        else:
            unverifiable_ids.append(frame.get("evidence_id"))

        findings.append({
            "evidence_id": frame.get("evidence_id"),
            "frame_number": frame.get("frame_number"),
            "capture_point": frame.get("capture_point"),
            "source_id": frame.get("source_id"),
            "claimed_direction": claimed_direction,
            "possible_directions": possible,
            "relation": relation,
            "directly_conflicts_with_ledger": direct_conflict,
            "mac_relation": mac_relation,
            "outer_vlan": frame.get("outer_vlan"),
            "vlan_ids": frame.get("vlan_ids") or [],
            "truncated": bool(frame.get("truncated")),
            "ledger_record_ids": frame.get("ledger_record_ids") or [],
            "issues": frame.get("issues") or [],
        })

    if not matching:
        status = "no_matching_frame"
        direct = False
        reasons = ["claim selectors did not match any parsed frame"]
    elif conflicting_ids:
        status = "conflict"
        direct = True
        reasons = [
            f"claimed {claimed_direction!r} is absent from trusted ledger directions for "
            + ", ".join(str(fid) for fid in conflicting_ids)
        ]
    elif unverifiable_ids and not supported_ids:
        status = "unverifiable"
        direct = False
        reasons = ["ledger direction or link evidence is insufficient", str(unverifiable_ids)]
    elif any(frame.get("multiple_directions_possible") for frame in matching):
        status = "supported_with_multiple_directions"
        direct = False
        reasons = ["claim is one allowed direction, but the trusted mirror record allows more than one direction"]
    else:
        status = "supported"
        direct = False
        reasons = ["claimed direction is present in trusted mirror ledger directions"]

    if mac_conflict_ids:
        reasons.append(f"claimed MAC does not match link header in {mac_conflict_ids}")

    return {
        "claim_id": claim_id,
        "id": claim_id,
        "claimed_direction": claimed_direction,
        "direction": claimed_direction,
        "mac": claim_mac,
        "basis": _claim_value(claim, ("basis", "reason", "rule", "label_basis", "依据")) or "mac_address",
        "status": status,
        "verdict": status,
        "directly_conflicts_with_ledger": direct,
        "is_conflict": status == "conflict",
        "conflict": status == "conflict",
        "supported": status.startswith("supported"),
        "ambiguous": status == "supported_with_multiple_directions",
        "unverifiable": status == "unverifiable",
        "matching_evidence_ids": [frame.get("evidence_id") for frame in matching],
        "conflicting_evidence_ids": conflicting_ids,
        "supported_evidence_ids": supported_ids,
        "unverifiable_evidence_ids": unverifiable_ids,
        "mac_conflict_evidence_ids": mac_conflict_ids,
        "frame_findings": findings,
        "reasons": reasons,
        "raw_claim": dict(claim),
    }


check_claim = evaluate_claim


def evaluate_claims(
    claims: Optional[Sequence[Mapping[str, Any]]],
    frames: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    return [evaluate_claim(claim, frames) for claim in (claims or [])]


check_direction_claims = evaluate_claims


def build_mac_observations(frames: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    observations: Dict[str, Dict[str, Any]] = {}
    for frame in frames:
        for role in ("src_mac", "dst_mac"):
            mac = normalize_mac(frame.get(role))
            if not mac:
                continue
            item = observations.setdefault(mac, {
                "mac": mac,
                "roles": set(),
                "evidence_ids": [],
                "capture_points": set(),
                "possible_directions": set(),
                "vlans": set(),
            })
            item["roles"].add(role.replace("_mac", ""))
            item["evidence_ids"].append(frame.get("evidence_id"))
            if frame.get("capture_point"):
                item["capture_points"].add(frame["capture_point"])
            item["possible_directions"].update(frame.get("possible_directions") or [])
            item["vlans"].update(frame.get("vlan_ids") or [])

    result = {}
    for mac, item in observations.items():
        result[mac] = {
            "mac": mac,
            "roles": sorted(item["roles"]),
            "evidence_ids": item["evidence_ids"],
            "capture_points": sorted(item["capture_points"]),
            "possible_directions": sorted(item["possible_directions"]),
            "vlans": sorted(item["vlans"]),
            "seen_at_multiple_points": len(item["capture_points"]) > 1,
            "has_multiple_possible_directions": len(item["possible_directions"]) > 1,
        }
    return result


def build_conclusion(report: Mapping[str, Any]) -> str:
    claim_results = report.get("claims") or []
    conflicts = [claim for claim in claim_results if claim.get("directly_conflicts_with_ledger")]
    lines = []
    if conflicts:
        ids = ", ".join(str(claim.get("claim_id")) for claim in conflicts)
        lines.append(f"与可信镜像端口台账直接冲突的方向主张: {ids}。")
        for claim in conflicts:
            evidence = ", ".join(claim.get("conflicting_evidence_ids") or [])
            lines.append(
                f"- {claim.get('claim_id')}: 主张 {claim.get('claimed_direction')}；"
                f"冲突证据 {evidence}。"
            )
    else:
        lines.append("没有方向主张与可信镜像端口台账直接冲突。")

    multi_point = [
        mac for mac, item in (report.get("mac_observations") or {}).items()
        if item.get("seen_at_multiple_points")
    ]
    if multi_point:
        lines.append(
            "同一 MAC 出现在不同采集点: " + ", ".join(multi_point)
            + "；必须按采集点/台账分别归属，不能全局贴同一方向。"
        )
    truncated = report.get("summary", {}).get("truncated_evidence_ids") or []
    if truncated:
        lines.append("截断帧已保留原始链路字节和长度差异，MAC 缺失时只能作证据不足处理: " + ", ".join(truncated) + "。")
    lines.append("外层 VLAN/QinQ 标签已单独保留；VLAN 不一致属于台账或捕获范围冲突。")
    return "\n".join(lines)


def audit_captures(
    captures: Any = None,
    mirror_table: Any = None,
    scope: Any = None,
    claims: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    capture_point: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse captures, attribute directions, and optionally audit claims."""
    sources = normalize_sources(captures, capture_point)
    ledger = coerce_ledger(mirror_table)
    scope_data = coerce_scope(scope)

    frames: List[Dict[str, Any]] = []
    for source in sources:
        frames.extend(iter_frames(source))

    attributed = [audit_frame(frame, ledger, scope_data) for frame in frames]
    claim_results = evaluate_claims(claims, attributed)
    mac_observations = build_mac_observations(attributed)

    conflict_claim_ids = [
        claim.get("claim_id") for claim in claim_results
        if claim.get("directly_conflicts_with_ledger")
    ]
    summary = {
        "frame_count": len(attributed),
        "claim_count": len(claim_results),
        "conflict_count": len(conflict_claim_ids),
        "conflicting_claim_ids": conflict_claim_ids,
        "truncated_evidence_ids": [frame["evidence_id"] for frame in attributed if frame.get("truncated")],
        "capture_points": sorted({str(frame.get("capture_point")) for frame in attributed if frame.get("capture_point")}),
        "outer_vlans": sorted({frame.get("outer_vlan") for frame in attributed if frame.get("outer_vlan") is not None}),
        "vlan_ids": sorted({vlan for frame in attributed for vlan in frame.get("vlan_ids", [])}),
        "multiple_direction_evidence_ids": [
            frame["evidence_id"] for frame in attributed if frame.get("multiple_directions_possible")
        ],
    }
    report: Dict[str, Any] = {
        "summary": summary,
        "frames": attributed,
        "results": attributed,
        "direction_attributions": attributed,
        "claims": claim_results,
        "conflicting_claims": [claim for claim in claim_results if claim.get("directly_conflicts_with_ledger")],
        "mac_observations": mac_observations,
        "ledger": ledger,
        "scope": scope_data,
    }
    report["conflicts"] = report["conflicting_claims"]
    report["conclusion"] = build_conclusion(report)
    return report


def run_audit(
    captures: Any = None,
    mirror_table: Any = None,
    scope: Any = None,
    claims: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    pcap: Any = None,
    pcap_file: Any = None,
    pcap_path: Any = None,
    capture_file: Any = None,
    capture_files: Any = None,
    pcaps: Any = None,
    packets: Any = None,
    mirror_ports: Any = None,
    mirror_port_table: Any = None,
    ledger: Any = None,
    capture_scope: Any = None,
    scope_config: Any = None,
    direction_claims: Optional[Sequence[Mapping[str, Any]]] = None,
    report_claims: Optional[Sequence[Mapping[str, Any]]] = None,
    capture_point: Optional[str] = None,
    **_: Any,
) -> Dict[str, Any]:
    """Keyword-tolerant wrapper for callers using task-domain names."""
    capture_input = (
        captures if captures is not None
        else pcap if pcap is not None
        else pcap_file if pcap_file is not None
        else pcap_path if pcap_path is not None
        else capture_file if capture_file is not None
        else capture_files if capture_files is not None
        else pcaps if pcaps is not None
        else packets
    )
    ledger_input = (
        mirror_table if mirror_table is not None
        else mirror_ports if mirror_ports is not None
        else mirror_port_table if mirror_port_table is not None
        else ledger
    )
    scope_input = scope if scope is not None else capture_scope if capture_scope is not None else scope_config
    claim_input = claims if claims is not None else direction_claims if direction_claims is not None else report_claims
    return audit_captures(
        capture_input,
        ledger_input,
        scope_input,
        claim_input,
        capture_point=capture_point,
    )


class DirectionAuditor:
    """Stateful facade combining a trusted ledger and capture scope."""

    def __init__(self, mirror_ports: Any = None, capture_scope: Any = None, scope: Any = None):
        self.ledger = coerce_ledger(mirror_ports)
        self.scope = coerce_scope(capture_scope if capture_scope is not None else scope)

    def parse_pcap(self, source: Any, capture_point: Optional[str] = None) -> List[Dict[str, Any]]:
        return read_capture(source, capture_point)

    def audit_frame(self, frame: Mapping[str, Any]) -> Dict[str, Any]:
        return audit_frame(frame, self.ledger, self.scope)

    def audit_capture(self, source: Any, capture_point: Optional[str] = None) -> List[Dict[str, Any]]:
        return [self.audit_frame(frame) for frame in read_capture(source, capture_point)]

    def evaluate_claims(self, claims: Sequence[Mapping[str, Any]], frames: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        attributed = frames if frames and any("possible_directions" in frame for frame in frames) else [self.audit_frame(frame) for frame in frames]
        return evaluate_claims(claims, attributed)

    def audit(
        self,
        captures: Any,
        claims: Optional[Sequence[Mapping[str, Any]]] = None,
        capture_point: Optional[str] = None,
    ) -> Dict[str, Any]:
        return audit_captures(captures, self.ledger, self.scope, claims, capture_point=capture_point)


audit_capture = audit_captures
audit_directions = audit_captures
verify_directions = audit_captures
audit_pcap = audit_captures
audit_packets = audit_captures
check_directions = audit_captures
audit = audit_captures
attribute_packet = audit_frame
analyze_frame = audit_frame
verify_claim = evaluate_claim
check_direction_claim = evaluate_claim
check_claim_direction = evaluate_claim
load_ledger = coerce_ledger
load_mirror_table = coerce_ledger
solve = run_audit
audit_direction_attribution = run_audit


def json_safe(value: Any) -> Any:
    if isinstance(value, MirrorLedger):
        return {"records": [record.to_dict() for record in value.records]}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items() if key != "raw"}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    return value


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = ["# 方向归属核对报告", "", report.get("conclusion", ""), "", "## 帧证据", ""]
    lines.append("| 证据 | 采集点 | 源MAC | 目的MAC | 外层VLAN | 可能方向 | 截断 |")
    lines.append("|---|---|---|---|---:|---|---|")
    for frame in report.get("frames", []):
        lines.append(
            "| {evidence_id} | {capture_point} | {src_mac} | {dst_mac} | {outer_vlan} | {directions} | {truncated} |".format(
                evidence_id=frame.get("evidence_id"),
                capture_point=frame.get("capture_point"),
                src_mac=frame.get("src_mac"),
                dst_mac=frame.get("dst_mac"),
                outer_vlan=frame.get("outer_vlan") if frame.get("outer_vlan") is not None else "—",
                directions=", ".join(frame.get("possible_directions") or []),
                truncated="yes" if frame.get("truncated") else "no",
            )
        )
    lines.extend(["", "## 主张核对", ""])
    lines.append("| 主张 | 方向 | 状态 | 直接冲突 | 冲突证据 |")
    lines.append("|---|---|---|---|---|")
    for claim in report.get("claims", []):
        lines.append(
            f"| {claim.get('claim_id')} | {claim.get('claimed_direction')} | "
            f"{claim.get('status')} | {'yes' if claim.get('directly_conflicts_with_ledger') else 'no'} | "
            f"{', '.join(claim.get('conflicting_evidence_ids') or [])} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Offline dpkt-based direction attribution audit")
    parser.add_argument("--source", "-s", action="append", default=[], help="capture_point=file.pcap; repeatable")
    parser.add_argument("--pcap", action="append", default=[], help="pcap/pcapng path; point defaults to filename stem")
    parser.add_argument("--mirror-table", "-m", required=True, help="trusted mirror port table (JSON/CSV/TOML)")
    parser.add_argument("--scope", help="capture scope file (JSON/TOML)")
    parser.add_argument("--claims", help="direction claims file (JSON)")
    parser.add_argument("--output", "-o", help="JSON output path; default stdout")
    parser.add_argument("--markdown", help="optional Markdown report path")
    parser.add_argument("--strict-conflicts", action="store_true", help="exit 2 when claims directly conflict")
    args = parser.parse_args(argv)

    captures: List[Dict[str, Any]] = []
    for item in args.source:
        if "=" not in item:
            parser.error("--source requires capture_point=path")
        point, path = item.split("=", 1)
        captures.append({"capture_point": point, "path": path})
    for path in args.pcap:
        captures.append(path)

    claims = load_structured_file(args.claims) if args.claims else None
    if isinstance(claims, Mapping):
        claims = claims.get("claims") or claims.get("items") or []
    report = audit_captures(captures, args.mirror_table, args.scope, claims)
    safe_report = json_safe(report)
    rendered = json.dumps(safe_report, ensure_ascii=False, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if args.markdown:
        Path(args.markdown).write_text(render_markdown(report), encoding="utf-8")
    if args.strict_conflicts and report["summary"]["conflict_count"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
