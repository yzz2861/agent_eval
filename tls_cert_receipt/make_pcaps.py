"""Generate synthetic TLS test pcaps for the certificate-observation receipt.

Three scenarios, all after the assumed maintenance window:

  A_missed_cert.pcap  capture stops halfway through the handshake; the
                      Certificate record is only partially saved, so the
                      sensor never sees the certificate.
  B_old_cert.pcap     full handshake presenting the OLD certificate.
  C_new_cert.pcap     full handshake presenting the NEW certificate.

Also writes maintenance.json (assumed maintenance window + old/new DER
digests provided by maintenance) and manifest.json (expected evidence
frames per scenario, used by the tests).
"""
import hashlib
import json
import os
import socket
import struct
import subprocess
from datetime import datetime, timedelta, timezone

import dpkt

HERE = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(HERE, "certs")
PCAP_DIR = os.path.join(HERE, "pcaps")

TZ = timezone(timedelta(hours=8))
WINDOW_START = datetime(2026, 11, 28, 10, 0, 0, tzinfo=TZ)
WINDOW_END = datetime(2026, 11, 28, 12, 0, 0, tzinfo=TZ)

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
SERVER_PORT = 443

TLS12 = b"\x03\x03"


def make_cert(name, cn):
    key = os.path.join(CERT_DIR, name + "_key.pem")
    pem = os.path.join(CERT_DIR, name + ".pem")
    der = os.path.join(CERT_DIR, name + ".der")
    if not os.path.exists(der):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", pem, "-days", "365",
             "-subj", "/CN=" + cn],
            check=True, capture_output=True)
        subprocess.run(["openssl", "x509", "-in", pem, "-outform", "DER",
                        "-out", der], check=True, capture_output=True)
    with open(der, "rb") as fh:
        return fh.read()


def hs(msg_type, body):
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def record(content_type, payload):
    return bytes([content_type]) + TLS12 + len(payload).to_bytes(2, "big") + payload


def client_hello():
    body = TLS12 + b"\xaa" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x00\x33" + b"\x01\x00"
    return record(22, hs(1, body))


def server_hello():
    body = TLS12 + b"\xbb" * 32 + b"\x00" + b"\x00\x33" + b"\x00"
    return record(22, hs(2, body))


def certificate_msg(cert_der):
    entry = len(cert_der).to_bytes(3, "big") + cert_der
    body = len(entry).to_bytes(3, "big") + entry
    return record(22, hs(11, body))


def server_hello_done():
    return record(22, hs(14, b""))


class Flow:
    """Tiny scripted TCP endpoint pair; yields (frame_bytes, ts) in order."""

    def __init__(self, sport, start_ts):
        self.sport = sport
        self.ts = start_ts
        self.cseq = 1000
        self.sseq = 5000
        self.frames = []

    def _tick(self, dt=0.001):
        self.ts += dt
        return self.ts

    def _packet(self, src, dst, sport, dport, seq, ack, flags, payload=b""):
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack,
                           flags=flags, win=64240, data=payload)
        ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                        p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = 20 + len(bytes(tcp))
        eth = dpkt.ethernet.Ethernet(src=b"\x02\x00\x00\x00\x00\x01",
                                     dst=b"\x02\x00\x00\x00\x00\x02",
                                     data=ip)
        self.frames.append((bytes(eth), self._tick()))

    def c2s(self, flags, payload=b""):
        self._packet(CLIENT_IP, SERVER_IP, self.sport, SERVER_PORT,
                     self.cseq, self.sseq, flags, payload)
        self.cseq += len(payload) + (1 if flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN) else 0)

    def s2c(self, flags, payload=b""):
        self._packet(SERVER_IP, CLIENT_IP, SERVER_PORT, self.sport,
                     self.sseq, self.cseq, flags, payload)
        self.sseq += len(payload) + (1 if flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN) else 0)

    def open(self):
        self.c2s(dpkt.tcp.TH_SYN)
        self.s2c(dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        self.c2s(dpkt.tcp.TH_ACK)

    def close(self):
        self.c2s(dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
        self.s2c(dpkt.tcp.TH_ACK)
        self.s2c(dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
        self.c2s(dpkt.tcp.TH_ACK)


def write_pcap(name, frames):
    path = os.path.join(PCAP_DIR, name)
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for buf, ts in frames:
            writer.writepkt(buf, ts=ts)
    return path


def build_all():
    old_der = make_cert("old", "old.example.internal")
    new_der = make_cert("new", "new.example.internal")

    maintenance = {
        "window": {
            "start": WINDOW_START.isoformat(),
            "end": WINDOW_END.isoformat(),
        },
        "certificates": {
            "old": {"sha256": hashlib.sha256(old_der).hexdigest(),
                    "label": "old.example.internal"},
            "new": {"sha256": hashlib.sha256(new_der).hexdigest(),
                    "label": "new.example.internal"},
        },
    }
    with open(os.path.join(HERE, "maintenance.json"), "w") as fh:
        json.dump(maintenance, fh, indent=2)

    manifest = {}
    base = datetime(2026, 11, 28, 12, 30, 0, tzinfo=TZ).timestamp()

    # Scenario A: capture stops mid-handshake, Certificate record truncated.
    flow = Flow(51000, base)
    flow.open()                                   # frames 1-3
    flow.c2s(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, client_hello())   # 4
    flow.s2c(dpkt.tcp.TH_ACK)                     # 5
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, server_hello())   # 6
    full_cert = certificate_msg(old_der)
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, full_cert[:120])  # 7 truncated
    write_pcap("A_missed_cert.pcap", flow.frames)
    manifest["A_missed_cert.pcap"] = {
        "expect_verdict": "INCONCLUSIVE_NO_CERT",
        "cert_frames": [],
        "partial_record_frames": [7],
    }

    # Scenario B: full handshake with the OLD certificate.
    flow = Flow(52000, base + 300)
    flow.open()                                   # 1-3
    flow.c2s(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, client_hello())   # 4
    flow.s2c(dpkt.tcp.TH_ACK)                     # 5
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, server_hello())   # 6
    cert = certificate_msg(old_der)
    half = len(cert) // 2
    flow.s2c(dpkt.tcp.TH_ACK, cert[:half])        # 7
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, cert[half:])      # 8
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, server_hello_done())  # 9
    flow.close()                                  # 10-13
    write_pcap("B_old_cert.pcap", flow.frames)
    manifest["B_old_cert.pcap"] = {
        "expect_verdict": "ALERT_OLD_CERT_AFTER_WINDOW",
        "cert_frames": [7, 8],
    }

    # Scenario C: full handshake with the NEW certificate.
    flow = Flow(53000, base + 600)
    flow.open()                                   # 1-3
    flow.c2s(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, client_hello())   # 4
    flow.s2c(dpkt.tcp.TH_ACK)                     # 5
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, server_hello())   # 6
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, certificate_msg(new_der))  # 7
    flow.s2c(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, server_hello_done())       # 8
    flow.close()                                  # 9-12
    write_pcap("C_new_cert.pcap", flow.frames)
    manifest["C_new_cert.pcap"] = {
        "expect_verdict": "OK_NEW_CERT_AFTER_WINDOW",
        "cert_frames": [7],
    }

    with open(os.path.join(HERE, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


if __name__ == "__main__":
    for name, meta in build_all().items():
        print(name, "->", meta["expect_verdict"])

