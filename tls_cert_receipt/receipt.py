"""TLS certificate observation receipt, built on dpkt.

Reads a local pcap, reassembles each TCP flow, parses TLS handshake
records, and reports exactly where (which frames, which time range) a
server certificate was observed. The observation is then checked against
the maintenance-provided old/new certificate digests and the assumed
maintenance window.

Usage:
  python receipt.py analyze <pcap> --maintenance maintenance.json [-o receipt.json]
  python receipt.py review <receipt.json> [<receipt.json> ...]
"""
import argparse
import hashlib
import json
import socket
import sys
from datetime import datetime, timezone

import dpkt

TLS_HANDSHAKE = 22
HS_CERTIFICATE = 11
HS_NAMES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
            14: "ServerHelloDone", 20: "Finished"}


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat()


class Direction:
    def __init__(self):
        self.chunks = []  # (seq, data, frame_no, ts)

    def add(self, seq, data, frame_no, ts):
        self.chunks.append((seq, data, frame_no, ts))

    def assemble(self):
        """Return (stream_bytes, segments) where segments map stream
        offsets back to (frame_no, ts). Assumes in-order synthetic
        traffic; trims retransmitted overlap."""
        stream = bytearray()
        segments = []  # (start, end, frame_no, ts)
        next_seq = None
        for seq, data, frame_no, ts in sorted(self.chunks, key=lambda c: c[0]):
            if not data:
                continue
            if next_seq is None:
                next_seq = seq
            if seq < next_seq:  # overlap / retransmit: keep the new tail
                skip = next_seq - seq
                if skip >= len(data):
                    continue
                data = data[skip:]
                seq = next_seq
            if seq > next_seq:  # gap: capture lost bytes, pad to stay aligned
                gap = seq - next_seq
                stream.extend(b"\x00" * gap)
                segments.append((len(stream) - gap, len(stream), None, None))
                next_seq = seq
            start = len(stream)
            stream.extend(data)
            segments.append((start, len(stream), frame_no, ts))
            next_seq = seq + len(data)
        return bytes(stream), segments


def frames_for_range(segments, start, end):
    frames, first_ts = [], None
    for seg_start, seg_end, frame_no, ts in segments:
        if frame_no is None:
            continue
        if seg_start < end and start < seg_end:
            frames.append(frame_no)
            if first_ts is None or ts < first_ts:
                first_ts = ts
    return sorted(set(frames)), first_ts


def parse_tls(stream, segments):
    """Parse TLS records; return (records, handshake_messages, incomplete)."""
    records = []
    pos = 0
    incomplete = None
    while pos + 5 <= len(stream):
        content_type = stream[pos]
        version = stream[pos + 1:pos + 3]
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        if content_type not in (20, 21, 22, 23) or version[0] != 3:
            break  # not TLS anymore (or stream padding)
        rec_end = pos + 5 + length
        if rec_end > len(stream):
            frames, ts = frames_for_range(segments, pos, len(stream))
            incomplete = {
                "content_type": content_type,
                "declared_length": length,
                "captured_length": len(stream) - pos - 5,
                "frames": frames,
                "ts": ts,
            }
            break
        frames, ts = frames_for_range(segments, pos, rec_end)
        records.append({
            "content_type": content_type,
            "version": version.hex(),
            "payload": stream[pos + 5:rec_end],
            "frames": frames,
            "ts": ts,
            "stream_range": (pos, rec_end),
        })
        pos = rec_end

    messages = []
    hs_stream = bytearray()
    hs_map = []  # (hs_start, hs_end, record)
    for rec in records:
        if rec["content_type"] != TLS_HANDSHAKE:
            continue
        start = len(hs_stream)
        hs_stream.extend(rec["payload"])
        hs_map.append((start, len(hs_stream), rec))

    pos = 0
    while pos + 4 <= len(hs_stream):
        msg_type = hs_stream[pos]
        msg_len = int.from_bytes(hs_stream[pos + 1:pos + 4], "big")
        msg_end = pos + 4 + msg_len
        if msg_end > len(hs_stream):
            break
        frames, ts = [], None
        for hs_start, hs_end, rec in hs_map:
            if hs_start < msg_end and pos < hs_end:
                frames.extend(rec["frames"])
                if ts is None or (rec["ts"] is not None and rec["ts"] < ts):
                    ts = rec["ts"]
        messages.append({
            "type": msg_type,
            "name": HS_NAMES.get(msg_type, "type_%d" % msg_type),
            "body": bytes(hs_stream[pos + 4:msg_end]),
            "frames": sorted(set(frames)),
            "ts": ts,
        })
        pos = msg_end
    return records, messages, incomplete


def parse_certificate(body):
    """TLS 1.2 Certificate message: 3-byte list len, then 3-byte len + DER."""
    certs = []
    if len(body) < 3:
        return certs
    total = int.from_bytes(body[0:3], "big")
    pos = 3
    end = min(3 + total, len(body))
    while pos + 3 <= end:
        clen = int.from_bytes(body[pos:pos + 3], "big")
        der = body[pos + 3:pos + 3 + clen]
        if len(der) < clen:
            break
        certs.append(der)
        pos += 3 + clen
    return certs


def flow_key(ip, tcp):
    a = (socket.inet_ntoa(ip.src), tcp.sport)
    b = (socket.inet_ntoa(ip.dst), tcp.dport)
    return (a, b) if a <= b else (b, a)


def analyze(pcap_path, maintenance):
    frames = []
    with open(pcap_path, "rb") as fh:
        for i, (ts, buf) in enumerate(dpkt.pcap.Reader(fh), start=1):
            frames.append((i, ts, buf))

    flows = {}
    for frame_no, ts, buf in frames:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        key = flow_key(ip, tcp)
        flow = flows.setdefault(key, {
            "endpoints": key,
            "syn_frame": None, "fin_frames": [], "rst_frame": None,
            "first_ts": ts, "last_ts": ts,
            "dirs": {},  # (src,sport,dst,dport) -> Direction
        })
        flow["first_ts"] = min(flow["first_ts"], ts)
        flow["last_ts"] = max(flow["last_ts"], ts)
        if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
            if flow["syn_frame"] is None:
                flow["syn_frame"] = frame_no
        if tcp.flags & dpkt.tcp.TH_FIN:
            flow["fin_frames"].append(frame_no)
        if tcp.flags & dpkt.tcp.TH_RST:
            flow["rst_frame"] = frame_no
        src = (socket.inet_ntoa(ip.src), tcp.sport)
        dst = (socket.inet_ntoa(ip.dst), tcp.dport)
        dkey = (src, dst)
        flow["dirs"].setdefault(dkey, Direction()).add(tcp.seq, tcp.data, frame_no, ts)

    win_start = datetime.fromisoformat(maintenance["window"]["start"]).timestamp()
    win_end = datetime.fromisoformat(maintenance["window"]["end"]).timestamp()
    digests = {name: info["sha256"].lower()
               for name, info in maintenance["certificates"].items()}

    connections = []
    for conn_id, (key, flow) in enumerate(sorted(flows.items()), start=1):
        (a, b) = flow["endpoints"]
        conn = {
            "id": conn_id,
            "endpoints": ["%s:%d" % a, "%s:%d" % b],
            "boundary": {
                "syn_frame": flow["syn_frame"],
                "fin_frames": flow["fin_frames"],
                "rst_frame": flow["rst_frame"],
                "first_ts": iso(flow["first_ts"]),
                "last_ts": iso(flow["last_ts"]),
            },
            "handshake": [],
            "certificate": None,
            "incomplete_record": None,
        }
        # Server is whichever endpoint sits on the TLS service port (443);
        # fall back to the direction that carries parseable TLS records.
        server_dir = None
        for (src, dst), direction in flow["dirs"].items():
            if src[1] == 443:
                server_dir = direction
        candidates = [server_dir] if server_dir else list(flow["dirs"].values())
        for direction in [d for d in candidates if d]:
            stream, segments = direction.assemble()
            records, messages, incomplete = parse_tls(stream, segments)
            if not records and incomplete is None:
                continue
            for msg in messages:
                conn["handshake"].append({
                    "message": msg["name"],
                    "frames": msg["frames"],
                    "ts": iso(msg["ts"]) if msg["ts"] else None,
                })
                if msg["type"] == HS_CERTIFICATE and conn["certificate"] is None:
                    certs = parse_certificate(msg["body"])
                    if certs:
                        leaf = certs[0]
                        conn["certificate"] = {
                            "observed": True,
                            "sha256": hashlib.sha256(leaf).hexdigest(),
                            "der_length": len(leaf),
                            "chain_length": len(certs),
                            "frames": msg["frames"],
                            "observed_ts": iso(msg["ts"]) if msg["ts"] else None,
                            "observed_epoch": msg["ts"],
                        }
            if incomplete:
                conn["incomplete_record"] = {
                    "declared_length": incomplete["declared_length"],
                    "captured_length": incomplete["captured_length"],
                    "frames": incomplete["frames"],
                }
            break

        conn["verdict"], conn["reason"] = classify(conn, digests, win_start, win_end)
        if conn["certificate"]:
            conn["certificate"].pop("observed_epoch", None)
        connections.append(conn)

    receipt = {
        "capture": {
            "file": pcap_path,
            "frame_count": len(frames),
            "time_range": [iso(frames[0][1]), iso(frames[-1][1])] if frames else None,
        },
        "maintenance": maintenance,
        "connections": connections,
    }
    return receipt


def classify(conn, digests, win_start, win_end):
    cert = conn["certificate"]
    if not cert or not cert.get("observed"):
        note = ""
        if conn["incomplete_record"]:
            note = ("capture ended mid-handshake: TLS record declares %d bytes "
                    "but only %d were captured (frames %s)" % (
                        conn["incomplete_record"]["declared_length"],
                        conn["incomplete_record"]["captured_length"],
                        conn["incomplete_record"]["frames"]))
        return ("INCONCLUSIVE_NO_CERT",
                "no server certificate observed; " + (note or "certificate "
                "message absent from capture") + "; the pcap can neither prove "
                "nor refute that the old certificate is still in use")
    fp = cert["sha256"].lower()
    match = next((name for name, digest in digests.items() if digest == fp), None)
    ts = datetime.fromisoformat(cert["observed_ts"]).timestamp()
    where = "after" if ts >= win_end else ("inside" if ts >= win_start else "before")
    if match == "new":
        if ts >= win_end:
            return ("OK_NEW_CERT_AFTER_WINDOW",
                    "observed certificate matches the maintenance-provided NEW "
                    "digest, presented after the maintenance window; rotation "
                    "confirmed on this connection")
        return ("NEW_CERT_BEFORE_WINDOW_END",
                "new certificate observed before the maintenance window closed")
    if match == "old":
        if ts >= win_end:
            return ("ALERT_OLD_CERT_AFTER_WINDOW",
                    "observed certificate matches the maintenance-provided OLD "
                    "digest, presented after the maintenance window; consistent "
                    "with the claim that the server still uses the old certificate")
        return ("OLD_CERT_BEFORE_WINDOW_END",
                "old certificate observed, but before the maintenance window "
                "closed; expected during rotation")
    return ("UNKNOWN_CERT",
            "certificate fingerprint matches neither maintenance-provided digest")


def review(receipts):
    lines = []
    for receipt in receipts:
        cap = receipt["capture"]
        lines.append("capture %s: %d frames, %s .. %s" % (
            cap["file"], cap["frame_count"], *cap["time_range"]))
        win = receipt["maintenance"]["window"]
        lines.append("maintenance window: %s .. %s" % (win["start"], win["end"]))
        for conn in receipt["connections"]:
            b = conn["boundary"]
            lines.append("  connection %d %s <-> %s" % (
                conn["id"], conn["endpoints"][0], conn["endpoints"][1]))
            lines.append("    boundary: SYN frame %s, FIN frames %s, %s .. %s" % (
                b["syn_frame"], b["fin_frames"], b["first_ts"], b["last_ts"]))
            for msg in conn["handshake"]:
                lines.append("    handshake %-16s frames %s ts %s" % (
                    msg["message"], msg["frames"], msg["ts"]))
            cert = conn["certificate"]
            if cert and cert.get("observed"):
                lines.append("    certificate sha256=%s der_len=%d frames %s ts %s" % (
                    cert["sha256"], cert["der_length"], cert["frames"],
                    cert["observed_ts"]))
            elif conn["incomplete_record"]:
                rec = conn["incomplete_record"]
                lines.append("    certificate NOT observed; truncated record "
                             "(%d/%d bytes) in frames %s" % (
                                 rec["captured_length"], rec["declared_length"],
                                 rec["frames"]))
            lines.append("    VERDICT %s -- %s" % (conn["verdict"], conn["reason"]))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("analyze")
    pa.add_argument("pcap")
    pa.add_argument("--maintenance", required=True)
    pa.add_argument("-o", "--out")
    pr = sub.add_parser("review")
    pr.add_argument("receipts", nargs="+")
    args = parser.parse_args(argv)

    if args.cmd == "analyze":
        with open(args.maintenance) as fh:
            maintenance = json.load(fh)
        receipt = analyze(args.pcap, maintenance)
        text = json.dumps(receipt, indent=2)
        if args.out:
            with open(args.out, "w") as fh:
                fh.write(text + "\n")
        print(text)
    else:
        receipts = []
        for path in args.receipts:
            with open(path) as fh:
                receipts.append(json.load(fh))
        print(review(receipts))


if __name__ == "__main__":
    main()

