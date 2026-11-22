"""Entry point: build synthetic capture, audit every frame, emit report."""
from __future__ import annotations

import json
import os

import dpkt.pcap

from .cases import build_cases, collector_declarations
from .offloadcheck import audit_frame
from .report import render


def main(out_dir="checksum_audit/out"):
    os.makedirs(out_dir, exist_ok=True)
    cases = build_cases()
    collectors = collector_declarations()

    audits = []
    for idx, case in enumerate(cases, start=1):
        audit = audit_frame(
            frame_id=idx,
            sample=case.sample,
            wire_len=case.wire_len,
            decl=case.collector,
        )
        audit.name = case.name
        audit.note = case.note
        audits.append(audit)

    pcap_path = os.path.join(out_dir, "synthetic.pcap")
    json_path = os.path.join(out_dir, "verdicts.json")
    report_path = os.path.join(out_dir, "report.md")

    with open(pcap_path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for seq, case in enumerate(cases):
            writer.writepkt(case.sample, ts=1_700_000_000 + seq)

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump([a.to_dict() for a in audits], fh, ensure_ascii=False, indent=2)

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(render(collectors, audits, pcap_path))

    return {"pcap": pcap_path, "json": json_path, "report": report_path}


if __name__ == "__main__":
    for name, path in main().items():
        print("%s: %s" % (name, path))
