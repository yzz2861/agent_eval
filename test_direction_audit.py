import struct
import sys

import dpkt
import direction_audit as da


SHARED_MAC = "02:11:22:33:44:55"
PEER_MAC = "02:aa:bb:cc:dd:ee"


def mac_bytes(value):
    return bytes.fromhex(value.replace(":", "").replace("-", ""))


def ethernet_frame(src=SHARED_MAC, dst=PEER_MAC, vlan=100, ethertype=0x0800, payload=b"offline-audit"):
    frame = mac_bytes(dst) + mac_bytes(src)
    if vlan is None:
        frame += struct.pack("!H", ethertype)
    else:
        frame += struct.pack("!HHH", 0x8100, int(vlan) & 0x0FFF, ethertype)
    return frame + payload


def write_pcap(path, frames):
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle, snaplen=65535, linktype=dpkt.pcap.DLT_EN10MB)
        for index, frame in enumerate(frames, 1):
            writer.writepkt(frame, 1764100000 + index)


def write_truncated_pcap(path, prefix, original_length, timestamp=1764100003):
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
    record_header = struct.pack("<IIII", timestamp, 0, len(prefix), original_length)
    path.write_bytes(global_header + record_header + prefix)


def ledger():
    return [
        {
            "id": "MP-A",
            "capture_point": "probe_a",
            "mirror_port": "Eth1/1",
            "monitored_port": "Gi1/0/1",
            "vlans": [100],
            "directions": ["outbound"],
        },
        {
            "id": "MP-B",
            "capture_point": "probe_b",
            "mirror_port": "Eth1/2",
            "monitored_port": "Gi1/0/2",
            "vlans": [200],
            "directions": ["inbound"],
        },
    ]


def claims():
    return [
        {
            "claim_id": "R-A",
            "mac": SHARED_MAC,
            "capture_point": "probe_a",
            "direction": "outbound",
            "basis": "mac-only-report-rule",
        },
        {
            "claim_id": "R-B",
            "mac": SHARED_MAC,
            "capture_point": "probe_b",
            "direction": "outbound",
            "basis": "mac-only-report-rule",
        },
        {
            "claim_id": "R-TRUNC",
            "evidence_id": "truncated#1",
            "mac": SHARED_MAC,
            "direction": "outbound",
            "basis": "mac-only-report-rule",
        },
    ]


def build_report(tmp_path):
    frame_a = ethernet_frame(vlan=100, payload=b"normal-frame-a")
    frame_b = ethernet_frame(dst="02:cc:dd:ee:ff:00", vlan=200, payload=b"normal-frame-b")
    full_truncated = ethernet_frame(vlan=100, payload=b"truncated-payload")

    pcap_a = tmp_path / "probe_a.pcap"
    pcap_b = tmp_path / "probe_b.pcap"
    pcap_trunc = tmp_path / "truncated.pcap"
    write_pcap(pcap_a, [frame_a])
    write_pcap(pcap_b, [frame_b])
    write_truncated_pcap(pcap_trunc, full_truncated[:13], len(full_truncated))

    scope = {
        "capture_points": ["probe_a", "probe_b"],
        "point_vlans": {"probe_a": [100], "probe_b": [200]},
    }
    captures = [
        str(pcap_a),
        str(pcap_b),
        {
            "path": str(pcap_trunc),
            "capture_point": "probe_a",
            "source_id": "truncated",
        },
    ]
    return da.audit_captures(captures, ledger(), scope, claims())


def test_two_same_mac_frames_keep_point_vlan_and_direction(tmp_path):
    report = build_report(tmp_path)
    frames = report["frames"]
    assert report["summary"]["frame_count"] == 3

    frame_a = next(frame for frame in frames if frame["capture_point"] == "probe_a" and not frame["truncated"])
    frame_b = next(frame for frame in frames if frame["capture_point"] == "probe_b")

    assert frame_a["src_mac"] == SHARED_MAC
    assert frame_b["src_mac"] == SHARED_MAC
    assert frame_a["outer_vlan"] == 100
    assert frame_b["outer_vlan"] == 200
    assert frame_a["possible_directions"] == ["outbound"]
    assert frame_b["possible_directions"] == ["inbound"]
    assert frame_a["frame_sha256"] and len(frame_a["frame_sha256"]) == 64
    assert frame_a["link_header_complete"] is True

    mac_view = report["mac_observations"][SHARED_MAC]
    assert mac_view["seen_at_multiple_points"] is True
    assert set(mac_view["capture_points"]) == {"probe_a", "probe_b"}
    assert set(mac_view["possible_directions"]) == {"inbound", "outbound"}
    assert set(mac_view["vlans"]) == {100, 200}


def test_truncated_header_is_evidence_not_crash_and_remains_traceable(tmp_path):
    report = build_report(tmp_path)
    truncated = next(frame for frame in report["frames"] if frame["evidence_id"] == "truncated#1")

    assert truncated["truncated"] is True
    assert truncated["wire_truncated"] is True
    assert truncated["header_truncated"] is True
    assert truncated["original_len"] > truncated["captured_len"]
    assert truncated["captured_len"] == 13
    assert truncated["src_mac"] == SHARED_MAC
    assert truncated["dst_mac"] == PEER_MAC
    assert truncated["ethertype"] is None
    assert truncated["raw_hex"] == ethernet_frame()[:13].hex() or len(truncated["raw_hex"]) == 26
    assert truncated["frame_sha256"]
    assert truncated["possible_directions"] == ["outbound"]

    claim = next(claim for claim in report["claims"] if claim["claim_id"] == "R-TRUNC")
    finding = claim["frame_findings"][0]
    assert finding["relation"] == "supported"
    assert finding["mac_relation"] == "matches_src"
    assert claim["directly_conflicts_with_ledger"] is False


def test_only_mac_outbound_claim_at_second_point_conflicts_with_ledger(tmp_path):
    report = build_report(tmp_path)
    assert report["summary"]["conflicting_claim_ids"] == ["R-B"]

    by_id = {claim["claim_id"]: claim for claim in report["claims"]}
    assert by_id["R-A"]["directly_conflicts_with_ledger"] is False
    assert by_id["R-A"]["status"] == "supported"
    assert by_id["R-B"]["directly_conflicts_with_ledger"] is True
    assert by_id["R-B"]["status"] == "conflict"
    assert by_id["R-B"]["conflicting_evidence_ids"]
    assert "R-B" in report["conclusion"]
    assert "probe_b" in report["conclusion"]


def test_qinq_outer_tags_are_all_retained():
    frame = mac_bytes(PEER_MAC) + mac_bytes(SHARED_MAC)
    frame += struct.pack("!HHH", 0x88A8, 100, 0x8100)
    frame += struct.pack("!HH", 200, 0x0800)
    frame += b"qinq-payload"

    evidence = da.parse_frame(frame)
    assert evidence["vlan_ids"] == [100, 200]
    assert evidence["outer_vlan"] == 100
    assert [tag["tpid_name"] for tag in evidence["vlan_tags"]] == ["802.1ad QinQ", "802.1Q"]


def test_both_mirror_directions_remain_multiple_candidates():
    frame = da.parse_frame(ethernet_frame(vlan=101), capture_point="span-both")
    table = [{"capture_point": "span-both", "vlan": 101, "direction": "both"}]
    attributed = da.audit_frame(frame, table)
    assert attributed["possible_directions"] == ["inbound", "outbound"]
    assert attributed["multiple_directions_possible"] is True

    claim = da.evaluate_claim(
        {"claim_id": "C-MULTI", "frame_id": "span-both#frame", "direction": "inbound"},
        [attributed],
    )
    assert claim["status"] == "supported_with_multiple_directions"
    assert claim["ambiguous"] is True
    assert claim["directly_conflicts_with_ledger"] is False


def test_vlan_from_other_ledger_is_flagged():
    frame = da.parse_frame(ethernet_frame(vlan=999), capture_point="probe_a")
    attributed = da.audit_frame(frame, ledger(), {"capture_points": ["probe_a"]})
    codes = {issue["code"] for issue in attributed["issues"]}
    assert "vlan_mismatch" in codes
    assert attributed["expected_vlans"] == [100]


def test_missing_mac_in_short_prefix_is_unverifiable_not_invented():
    prefix = ethernet_frame()[:8]
    evidence = da.parse_frame(prefix, orig_len=80, caplen=8)
    assert evidence["truncated"] is True
    assert evidence["src_mac"] is None
    assert evidence["dst_mac"] == PEER_MAC
    claim = da.evaluate_claim(
        {"claim_id": "C-SHORT", "frame_id": "capture#frame", "mac": SHARED_MAC, "direction": "outbound"},
        [da.audit_frame(evidence, ledger())],
    )
    assert claim["frame_findings"][0]["mac_relation"] == "unverifiable_truncated_header"


if __name__ == "__main__":
    sys.exit(__import__("pytest").main([__file__, "-v", "-o", "addopts="]))
