"""End-to-end checks: three synthetic captures, three verdicts, each
traceable back to concrete frame numbers."""
import json
import os
import subprocess
import sys

import dpkt
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from tls_cert_receipt import make_pcaps, receipt  # noqa: E402

PCAPS = os.path.join(HERE, "pcaps")


@pytest.fixture(scope="module")
def generated():
    return make_pcaps.build_all()


@pytest.fixture(scope="module")
def maintenance():
    with open(os.path.join(HERE, "maintenance.json")) as fh:
        return json.load(fh)


def analyze(name):
    with open(os.path.join(HERE, "maintenance.json")) as fh:
        maint = json.load(fh)
    return receipt.analyze(os.path.join(PCAPS, name), maint)


def pcap_frames(name):
    path = os.path.join(PCAPS, name)
    with open(path, "rb") as fh:
        return list(dpkt.pcap.Reader(fh))


def test_verdicts(generated):
    assert analyze("A_missed_cert.pcap")["connections"][0]["verdict"] == \
        "INCONCLUSIVE_NO_CERT"
    assert analyze("B_old_cert.pcap")["connections"][0]["verdict"] == \
        "ALERT_OLD_CERT_AFTER_WINDOW"
    assert analyze("C_new_cert.pcap")["connections"][0]["verdict"] == \
        "OK_NEW_CERT_AFTER_WINDOW"


def test_missed_cert_points_at_truncated_record(generated):
    conn = analyze("A_missed_cert.pcap")["connections"][0]
    assert conn["certificate"] is None
    inc = conn["incomplete_record"]
    assert inc["frames"] == generated["A_missed_cert.pcap"]["partial_record_frames"]
    assert inc["captured_length"] < inc["declared_length"]
    # boundary: connection opened but never closed inside the capture
    assert conn["boundary"]["syn_frame"] == 1
    assert conn["boundary"]["fin_frames"] == []


def test_old_cert_frames_and_digest(generated, maintenance):
    conn = analyze("B_old_cert.pcap")["connections"][0]
    cert = conn["certificate"]
    assert cert["observed"] is True
    assert cert["frames"] == generated["B_old_cert.pcap"]["cert_frames"]
    assert cert["sha256"] == maintenance["certificates"]["old"]["sha256"]
    assert conn["boundary"]["syn_frame"] == 1
    assert conn["boundary"]["fin_frames"]


def test_new_cert_frames_and_digest(generated, maintenance):
    conn = analyze("C_new_cert.pcap")["connections"][0]
    cert = conn["certificate"]
    assert cert["observed"] is True
    assert cert["frames"] == generated["C_new_cert.pcap"]["cert_frames"]
    assert cert["sha256"] == maintenance["certificates"]["new"]["sha256"]


def test_cert_frames_actually_carry_cert_bytes(generated, maintenance):
    """Independent re-check: the DER digest must be recoverable from exactly
    the frames the receipt cites."""
    import hashlib
    for name, key in (("B_old_cert.pcap", "old"), ("C_new_cert.pcap", "new")):
        conn = analyze(name)["connections"][0]
        frames = pcap_frames(name)
        payload = b""
        for frame_no in conn["certificate"]["frames"]:
            _, buf = frames[frame_no - 1]
            payload += dpkt.ethernet.Ethernet(buf).data.data.data
        target = maintenance["certificates"][key]["sha256"]
        assert hashlib.sha256(target and b"").hexdigest()  # sanity
        assert target.encode()[:8]  # non-empty digest configured
        # the cited frames contain the full TLS Certificate record
        assert payload[0] == 22 and payload[5] == 11
        cert_len = int.from_bytes(payload[12:15], "big")
        der = payload[15:15 + cert_len]
        assert hashlib.sha256(der).hexdigest() == target


def test_capture_time_range_after_window(generated, maintenance):
    from datetime import datetime
    win_end = datetime.fromisoformat(maintenance["window"]["end"])
    for name in generated:
        cap = analyze(name)["capture"]
        start, end = (datetime.fromisoformat(t) for t in cap["time_range"])
        assert start >= win_end  # all observations post-date the window
        assert cap["frame_count"] == len(pcap_frames(name))


def test_review_maps_each_verdict_to_frames(generated, tmp_path):
    paths = []
    for name in generated:
        out = tmp_path / (name + ".receipt.json")
        subprocess.run(
            [sys.executable, os.path.join(HERE, "receipt.py"), "analyze",
             os.path.join(PCAPS, name),
             "--maintenance", os.path.join(HERE, "maintenance.json"),
             "-o", str(out)],
            check=True, capture_output=True,
            env={**os.environ, "PYTHONPATH": ROOT})
        paths.append(str(out))
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "receipt.py"), "review"] + paths,
        check=True, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": ROOT}).stdout
    assert "INCONCLUSIVE_NO_CERT" in out and "frames [7]" in out
    assert "ALERT_OLD_CERT_AFTER_WINDOW" in out and "frames [7, 8]" in out
    assert "OK_NEW_CERT_AFTER_WINDOW" in out and "frames [7]" in out
    assert "SYN frame 1" in out

