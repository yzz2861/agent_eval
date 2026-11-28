#!/usr/bin/env python
"""Print the per-record BinXML evidence used to render an EVTX record."""

import json

import Evtx.Evtx as evtx
import Evtx.Views as e_views


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Print the evidence behind an EVTX record's rendered XML.")
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX file")
    parser.add_argument("record", type=int, help="Record number")
    parser.add_argument("--pretty", action="store_true", help="Indent the JSON output")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:
        record = log.get_record(args.record)
        if record is None:
            print("error: record not found")
            return -1
        report = e_views.evtx_record_evidence_view(record)
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    main()
