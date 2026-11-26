#!/usr/bin/env python3
"""Generate the three-frame offline direction-attribution verification case.

Run from the repository root:

    .venv/bin/python examples/direction_audit_demo.py

The script only writes local pcap/JSON/Markdown artifacts. It neither sends
packets nor scans a network.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dpkt  # noqa: E402
import direction_audit as da  # noqa: E402

SHARED_MAC = "02:11:22:33:44:55"
PEER_MAC = "02:aa:bb:cc:dd:ee"


def mac_bytes(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", "").replace("-", ""))


def ethernet_frame(vlan: int, payload: bytes, dst_mac: str = PEER_MAC) -> bytes:
    return (
        mac_bytes(dst_mac)
        + mac_bytes(SHARED_MAC)
        + struct.pack("!HHH", 0x8100, vlan & 0x0FFF, 0x0800)
        + payload
    )


def write_pcap(path: Path, frame: bytes, timestamp: float) -> None:
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle, snaplen=65535, linktype=dpkt.pcap.DLT_EN10MB)
        writer.writepkt(frame, timestamp)


def write_truncated_pcap(path: Path, prefix: bytes, original_length: int) -> None:
    global_header = struct.pack(
        "<IHHiIII",
        dpkt.pcap.TCPDUMP_MAGIC,
        2,
        4,
        0,
        0,
        65535,
        dpkt.pcap.DLT_EN10MB,
    )
    record_header = struct.pack("<IIII", 1764100003, 0, len(prefix), original_length)
    path.write_bytes(global_header + record_header + prefix)


def main() -> int:
    output = ROOT / "direction_audit_demo"
    output.mkdir(exist_ok=True)

    frame_a = ethernet_frame(100, b"normal-frame-at-probe-a")
    frame_b = ethernet_frame(200, b"normal-frame-at-probe-b", "02:cc:dd:ee:ff:00")
    frame_truncated = ethernet_frame(100, b"truncated-header-frame")

    pcap_a = output / "probe_a.pcap"
    pcap_b = output / "probe_b.pcap"
    pcap_truncated = output / "truncated_header.pcap"
    write_pcap(pcap_a, frame_a, 1764100001)
    write_pcap(pcap_b, frame_b, 1764100002)
    write_truncated_pcap(pcap_truncated, frame_truncated[:13], len(frame_truncated))

    ledger = [
        {
            "id": "MP-A",
            "capture_point": "probe_a",
            "switch": "dc1-leaf-7",
            "mirror_port": "Eth1/1",
            "monitored_port": "Gi1/0/1",
            "vlans": [100],
            "directions": ["outbound"],
        },
        {
            "id": "MP-B",
            "capture_point": "probe_b",
            "switch": "dc2-leaf-3",
            "mirror_port": "Eth1/2",
            "monitored_port": "Gi1/0/9",
            "vlans": [200],
            "directions": ["inbound"],
        },
    ]
    scope = {
        "name": "incident-DS055-authorized-span-scope",
        "capture_points": ["probe_a", "probe_b"],
        "point_vlans": {"probe_a": [100], "probe_b": [200]},
    }
    claims = [
        {
            "claim_id": "R-A",
            "mac": SHARED_MAC,
            "capture_point": "probe_a",
            "direction": "outbound",
            "basis": "report-mac-rule",
        },
        {
            "claim_id": "R-B",
            "mac": SHARED_MAC,
            "capture_point": "probe_b",
            "direction": "outbound",
            "basis": "report-mac-rule",
        },
        {
            "claim_id": "R-TRUNC",
            "evidence_id": "truncated_header#1",
            "mac": SHARED_MAC,
            "direction": "outbound",
            "basis": "report-mac-rule",
        },
    ]

    (output / "mirror_ports.json").write_text(
        json.dumps({"mirror_ports": ledger}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "capture_scope.json").write_text(
        json.dumps(scope, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output / "direction_claims.json").write_text(
        json.dumps({"claims": claims}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = da.audit_captures(
        [
            {"path": pcap_a, "capture_point": "probe_a"},
            {"path": pcap_b, "capture_point": "probe_b"},
            {
                "path": pcap_truncated,
                "capture_point": "probe_a",
                "source_id": "truncated_header",
            },
        ],
        ledger,
        scope,
        claims,
    )
    (output / "audit_report.json").write_text(
        json.dumps(da.json_safe(report), ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    (output / "audit_report.md").write_text(da.render_markdown(report), encoding="utf-8")

    assert report["summary"]["frame_count"] == 3
    assert report["summary"]["conflicting_claim_ids"] == ["R-B"]
    assert report["frames"][2]["truncated"] is True
    print(report["conclusion"])
    print(f"\nArtifacts written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
