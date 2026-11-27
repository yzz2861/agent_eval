"""Extract DHCP lease and ARP binding evidence from packet captures.

Only packet data is read.  Nothing in this module writes to a capture or to a
fixture; the audit is deliberately one-way.
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence

import dpkt
from dpkt import arp as dpkt_arp
from dpkt import dhcp as dpkt_dhcp
from dpkt import ethernet as dpkt_ethernet
from dpkt import ip as dpkt_ip
from dpkt import udp as dpkt_udp


INFINITE_LEASE = 0xFFFFFFFF
DHCP_MAGIC = b"\x63\x82\x53\x63"


class EvidenceError(Exception):
    """Raised when a capture or a record cannot be interpreted safely."""


@dataclass(frozen=True)
class DhcpAck:
    record_id: str
    captured_at: datetime
    address: str
    client_mac: Optional[str]
    lease_seconds: Optional[int]
    lease_end: Optional[datetime]
    lease_present: bool
    lease_infinite: bool
    server_id: Optional[str]
    source_path: str
    packet_index: int
    xid: int

    @property
    def kind(self) -> str:
        return "dhcp_ack"


@dataclass(frozen=True)
class ArpBinding:
    record_id: str
    captured_at: datetime
    ip: str
    mac: str
    role: str  # "sender" or "target"
    operation: str  # "request", "reply" or "other"
    frame_src: str
    frame_dst: str
    source_path: str
    packet_index: int
    frame_src_matches: bool

    @property
    def kind(self) -> str:
        return "arp_binding"


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_size(path: str) -> int:
    return os.path.getsize(path)


def iso_z(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def capture_time(timestamp: float) -> datetime:
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc)


def mac_to_text(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) != 6 or not any(raw):
            return None
        return ":".join("%02x" % octet for octet in raw)
    text = str(value).strip().lower().replace("-", ":")
    if not text or text in ("00:00:00:00:00:00", "0:0:0:0:0:0"):
        return None
    parts = text.split(":")
    if len(parts) != 6:
        raise EvidenceError("invalid MAC address %r" % value)
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        raise EvidenceError("invalid MAC address %r" % value)
    if any(octet < 0 or octet > 255 for octet in octets):
        raise EvidenceError("invalid MAC address %r" % value)
    if not any(octets):
        return None
    return ":".join("%02x" % octet for octet in octets)


def ip_from_int(value: int) -> Optional[str]:
    if not value:
        return None
    return str(dpkt_ip.inet_to_str(struct.pack("!I", value)))


def ip_from_bytes(value) -> Optional[str]:
    if not value:
        return None
    raw = bytes(value)
    if len(raw) != 4 or not any(raw):
        return None
    return str(dpkt_ip.inet_to_str(raw))


def _unique_record_id(kind: str, path: str, packet_index: int, role: str = "") -> str:
    base = os.path.basename(path)
    suffix = ":%s" % role if role else ""
    return "%s:%s:%d%s" % (kind, base, packet_index, suffix)


def _iter_ethernet(path: str, linktype_aware: bool = False):
    try:
        with open(path, "rb") as handle:
            reader = dpkt.pcap.Reader(handle)
            for index, (timestamp, buf) in enumerate(reader):
                try:
                    yield index, capture_time(timestamp), dpkt_ethernet.Ethernet(buf)
                except (dpkt.UnpackError, ValueError, struct.error):
                    continue
    except (OSError, ValueError) as exc:
        raise EvidenceError("cannot read pcap %s: %s" % (path, exc))


def read_dhcp_acks(paths: Sequence[str]) -> List[DhcpAck]:
    """Return DHCPACK records, using the pcap timestamp as the lease start.

    A DHCPACK is the confirmation the task asks about.  OFFER/REQUEST records
    are intentionally ignored because they do not confirm a binding.
    """
    records: List[DhcpAck] = []
    seen_ids = set()
    for path in paths:
        for packet_index, timestamp, ethernet in _iter_ethernet(path):
            ip = ethernet.data
            if not isinstance(ip, dpkt_ip.IP) or ip.p != dpkt_ip.IP_PROTO_UDP:
                continue
            udp = ip.data
            if not isinstance(udp, dpkt_udp.UDP):
                continue
            payload = udp.data
            if not isinstance(payload, (bytes, bytearray)) or len(payload) < 240:
                continue
            if bytes(payload[236:240]) != DHCP_MAGIC:
                continue
            try:
                message = dpkt_dhcp.DHCP(bytes(payload))
            except (dpkt.UnpackError, ValueError, struct.error):
                continue
            if message.op != dpkt_dhcp.DHCP_OP_REPLY:
                continue
            options = {}
            for option_type, option_data in message.opts:
                options.setdefault(option_type, option_data)
            if options.get(dpkt_dhcp.DHCP_OPT_MSGTYPE) != b"\x05":
                continue
            address = ip_from_int(message.yiaddr or message.ciaddr)
            if not address:
                continue
            client_mac = mac_to_text(message.chaddr)
            if client_mac is None and dpkt_dhcp.DHCP_OPT_CLIENT_ID in options:
                client_id = options[dpkt_dhcp.DHCP_OPT_CLIENT_ID]
                if len(client_id) >= 7 and client_id[0:1] == b"\x01":
                    client_mac = mac_to_text(client_id[1:7])
            lease_present = dpkt_dhcp.DHCP_OPT_LEASE_SEC in options
            lease_seconds: Optional[int] = None
            lease_infinite = False
            lease_end: Optional[datetime] = None
            if lease_present:
                raw_lease = options[dpkt_dhcp.DHCP_OPT_LEASE_SEC]
                if len(raw_lease) != 4:
                    raise EvidenceError(
                        "DHCPACK %s has a malformed lease option" % path
                    )
                lease_value = struct.unpack("!I", raw_lease)[0]
                if lease_value == INFINITE_LEASE:
                    lease_infinite = True
                else:
                    lease_seconds = lease_value
                    lease_end = timestamp + timedelta(seconds=lease_value)
            server_id = ip_from_bytes(options.get(dpkt_dhcp.DHCP_OPT_SERVER_ID))
            record_id = _unique_record_id("dhcp", path, packet_index)
            if record_id in seen_ids:
                record_id = "%s#%d" % (record_id, len(seen_ids))
            seen_ids.add(record_id)
            records.append(
                DhcpAck(
                    record_id=record_id,
                    captured_at=timestamp,
                    address=address,
                    client_mac=client_mac,
                    lease_seconds=lease_seconds,
                    lease_end=lease_end,
                    lease_present=lease_present,
                    lease_infinite=lease_infinite,
                    server_id=server_id,
                    source_path=path,
                    packet_index=packet_index,
                    xid=message.xid,
                )
            )
    return records


def _arp_operation_name(value: int) -> str:
    if value == dpkt_arp.ARP_OP_REQUEST:
        return "request"
    if value == dpkt_arp.ARP_OP_REPLY:
        return "reply"
    return "other"


def read_arp_bindings(paths: Sequence[str]) -> List[ArpBinding]:
    """Return sender and reply-target ARP bindings.

    An ARP request's sender pair is a binding.  Its target pair is not: the
    request is asking about that address, not asserting who owns it.  A reply
    contributes both the sender pair and the target pair.
    """
    records: List[ArpBinding] = []
    seen_ids = set()
    for path in paths:
        for packet_index, timestamp, ethernet in _iter_ethernet(path):
            message = ethernet.data
            if not isinstance(message, dpkt_arp.ARP):
                continue
            if message.pro != dpkt_arp.ARP_PRO_IP:
                continue
            operation = _arp_operation_name(message.op)
            frame_src = mac_to_text(ethernet.src) or ""
            frame_dst = mac_to_text(ethernet.dst) or ""
            sender_mac = mac_to_text(message.sha)
            sender_ip = ip_from_bytes(message.spa)
            if sender_mac and sender_ip:
                record_id = _unique_record_id("arp", path, packet_index, "sender")
                if record_id in seen_ids:
                    record_id = "%s#%d" % (record_id, len(seen_ids))
                seen_ids.add(record_id)
                records.append(
                    ArpBinding(
                        record_id=record_id,
                        captured_at=timestamp,
                        ip=sender_ip,
                        mac=sender_mac,
                        role="sender",
                        operation=operation,
                        frame_src=frame_src,
                        frame_dst=frame_dst,
                        source_path=path,
                        packet_index=packet_index,
                        frame_src_matches=(frame_src == sender_mac),
                    )
                )
            if message.op == dpkt_arp.ARP_OP_REPLY:
                target_mac = mac_to_text(message.tha)
                target_ip = ip_from_bytes(message.tpa)
                if target_mac and target_ip:
                    record_id = _unique_record_id("arp", path, packet_index, "target")
                    if record_id in seen_ids:
                        record_id = "%s#%d" % (record_id, len(seen_ids))
                    seen_ids.add(record_id)
                    records.append(
                        ArpBinding(
                            record_id=record_id,
                            captured_at=timestamp,
                            ip=target_ip,
                            mac=target_mac,
                            role="target",
                            operation=operation,
                            frame_src=frame_src,
                            frame_dst=frame_dst,
                            source_path=path,
                            packet_index=packet_index,
                            frame_src_matches=(frame_src == mac_to_text(message.sha)),
                        )
                    )
    return records


def collect_capture_manifest(paths: Iterable[str]) -> List[dict]:
    manifest = []
    for path in paths:
        manifest.append(
            {
                "path": path,
                "bytes": file_size(path),
                "sha256": sha256_file(path),
            }
        )
    return manifest
