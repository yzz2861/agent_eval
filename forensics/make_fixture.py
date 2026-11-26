"""Build the offline evidence fixture for the forensic review.

Creates, under forensics/evidence/:

- capture.pcapng        -- the archive under review (two sections).
- capture_config.json   -- the independent capture configuration
  (operator-side record of what was configured per interface).
- manifest.json         -- the evidence manifest (取证清单) whose claim
  is being audited.

The scenario: the manifest claims that both interfaces of session A
fully retained the same traffic class (TCP/23 telnet).  The archive
itself contradicts this: interface 1 of section 0 carries an
if_filter option, and its interface statistics show packets rejected
by the capture filter.
"""

import json
import os
import struct

import pcapng.blocks as blocks
from pcapng import FileWriter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "evidence")

TELNET_FILTER = "tcp port 23 and host 192.0.2.5"
TELNET_ONLY_FILTER = "tcp port 23"


def eth_ipv4_tcp(src_ip, dst_ip, sport, dport, payload=b""):
    """Minimal Ethernet/IPv4/TCP frame (checksums zeroed; offline use)."""
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    tcp = struct.pack("!HHIIHHHH", sport, dport, 0, 0, 0x5000, 8192, 0, 0)
    ip_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, 0, 64, 6, 0, src, dst
    )
    return eth + ip + tcp + payload


def eth_ipv4_udp(src_ip, dst_ip, sport, dport, payload=b""):
    """Minimal Ethernet/IPv4/UDP frame."""
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    ip_len = 20 + len(udp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, ip_len, 2, 0, 64, 17, 0, src, dst
    )
    return eth + ip + udp + payload


def build_archive(path):
    with open(path, "wb") as stream:
        # ---------------- Section 0: capture session A ----------------
        shb_a = blocks.SectionHeader(
            options={
                "shb_hardware": "probe-01",
                "shb_os": "Linux 5.15",
                "shb_userappl": "dumpcap 3.6",
            }
        )
        shb_a.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            snaplen=65535,
            options={
                "if_name": "eth0",
                "if_description": "session A / eth0 (no capture filter)",
            },
        )
        shb_a.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            snaplen=65535,
            options={
                "if_name": "eth1",
                "if_description": "session A / eth1 (filtered)",
                "if_filter": [(0, TELNET_FILTER.encode("ascii"))],
            },
        )
        writer = FileWriter(stream, shb_a)

        ts = 1764208800_000_000  # 2026-11-26 10:00:00 UTC, microseconds

        def epb(section, interface_id, frame, offset_us):
            pkt = section.new_member(
                blocks.EnhancedPacket,
                interface_id=interface_id,
                timestamp_high=(ts + offset_us) >> 32,
                timestamp_low=(ts + offset_us) & 0xFFFFFFFF,
            )
            pkt.packet_data = frame
            writer.write_block(pkt)

        # eth0 (interface 0, unfiltered): mixed classes are all retained
        epb(shb_a, 0, eth_ipv4_tcp("10.0.0.8", "192.0.2.5", 51001, 23), 0)
        epb(shb_a, 0, eth_ipv4_tcp("10.0.0.9", "192.0.2.7", 51002, 23), 1000)
        epb(shb_a, 0, eth_ipv4_udp("10.0.0.8", "192.0.2.53", 53300, 53), 2000)
        epb(shb_a, 0, eth_ipv4_tcp("10.0.0.8", "192.0.2.80", 51003, 80), 3000)

        # eth1 (interface 1, filtered): only filter-matching packets stored
        epb(shb_a, 1, eth_ipv4_tcp("10.0.0.8", "192.0.2.5", 51011, 23), 500)
        epb(shb_a, 1, eth_ipv4_tcp("192.0.2.5", "10.0.0.8", 23, 51011), 1500)

        writer.write_block(
            shb_a.new_member(
                blocks.InterfaceStatistics,
                interface_id=0,
                timestamp_high=(ts + 300_000_000) >> 32,
                timestamp_low=(ts + 300_000_000) & 0xFFFFFFFF,
                options={"isb_ifrecv": 4, "isb_usrdeliv": 4},
            )
        )
        writer.write_block(
            shb_a.new_member(
                blocks.InterfaceStatistics,
                interface_id=1,
                timestamp_high=(ts + 300_000_000) >> 32,
                timestamp_low=(ts + 300_000_000) & 0xFFFFFFFF,
                options={
                    "isb_ifrecv": 9,
                    "isb_filteraccept": 2,
                    "isb_usrdeliv": 2,
                },
            )
        )

        # ---------------- Section 1: capture session B ----------------
        # Interface IDs restart at 0: this "interface 0" is NOT the same
        # interface as section 0 interface 0, even though the OS name
        # is also "eth0".
        shb_b = blocks.SectionHeader(
            options={
                "shb_hardware": "probe-01",
                "shb_os": "Linux 5.15",
                "shb_userappl": "dumpcap 3.6",
            }
        )
        shb_b.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            snaplen=65535,
            options={
                "if_name": "eth0",
                "if_description": "session B / eth0 (filtered, new instance)",
                "if_filter": [(0, TELNET_ONLY_FILTER.encode("ascii"))],
            },
        )
        writer.write_block(shb_b)

        ts_b = 1764212400_000_000  # 2026-11-26 11:00:00 UTC
        pkt = shb_b.new_member(
            blocks.EnhancedPacket,
            interface_id=0,
            timestamp_high=ts_b >> 32,
            timestamp_low=ts_b & 0xFFFFFFFF,
        )
        pkt.packet_data = eth_ipv4_tcp("10.0.0.8", "192.0.2.9", 52001, 23)
        writer.write_block(pkt)
        writer.write_block(
            shb_b.new_member(
                blocks.InterfaceStatistics,
                interface_id=0,
                timestamp_high=(ts_b + 300_000_000) >> 32,
                timestamp_low=(ts_b + 300_000_000) & 0xFFFFFFFF,
                options={
                    "isb_ifrecv": 5,
                    "isb_filteraccept": 1,
                    "isb_usrdeliv": 1,
                },
            )
        )


def build_config(path):
    config = {
        "tool": "dumpcap 3.6",
        "host": "probe-01",
        "sessions": [
            {
                "section_index": 0,
                "started_utc": "2026-11-26T10:00:00Z",
                "stopped_utc": "2026-11-26T10:05:00Z",
                "interfaces": [
                    {"name": "eth0", "capture_filter": None},
                    {"name": "eth1", "capture_filter": TELNET_FILTER},
                ],
            },
            {
                "section_index": 1,
                "started_utc": "2026-11-26T11:00:00Z",
                "stopped_utc": "2026-11-26T11:05:00Z",
                "interfaces": [
                    {"name": "eth0", "capture_filter": TELNET_ONLY_FILTER},
                ],
            },
        ],
    }
    with open(path, "w") as stream:
        json.dump(config, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def build_manifest(path):
    manifest = {
        "claim_id": "EV-2026-1126-07",
        "claim": (
            "Session A 的两个接口 (eth0, eth1) 均完整留存了 "
            "TCP/23 (telnet) 类流量"
        ),
        "archive": "capture.pcapng",
    }
    with open(path, "w") as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    build_archive(os.path.join(OUT_DIR, "capture.pcapng"))
    build_config(os.path.join(OUT_DIR, "capture_config.json"))
    build_manifest(os.path.join(OUT_DIR, "manifest.json"))
    print("fixture written to", OUT_DIR)


if __name__ == "__main__":
    main()
