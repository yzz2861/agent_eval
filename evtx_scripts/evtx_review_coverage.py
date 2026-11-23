#!/usr/bin/env python3
"""Summarize review coverage across one or more EVTX evidence files."""

import argparse
import json
import sys

from Evtx.ReviewCoverage import ReviewCoverageLedger


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build a review-coverage ledger from EVTX records and review receipts."
    )
    parser.add_argument(
        "evtx",
        nargs="+",
        help="Path to one or more EVTX evidence files.",
    )
    parser.add_argument(
        "-r",
        "--receipts",
        action="append",
        default=[],
        help="Receipt JSON file (repeatable); accepts a list or an object with a 'receipts' key.",
    )
    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        help="Optional evidence id for the corresponding EVTX path (repeatable, in order).",
    )
    parser.add_argument(
        "--segment-seconds",
        type=float,
        default=None,
        help="Bucket records into fixed-size time segments for coverage reporting.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write JSON to this file instead of stdout.",
    )
    parser.add_argument(
        "--no-records",
        action="store_true",
        help="Omit per-record rows from the JSON output.",
    )
    args = parser.parse_args(argv)

    ledger = ReviewCoverageLedger(segment_seconds=args.segment_seconds)
    for index, path in enumerate(args.evtx):
        evidence_id = args.scope[index] if index < len(args.scope) else path
        ledger.add_evidence(path, evidence_id=evidence_id)
    for receipt_path in args.receipts:
        ledger.add_receipts(receipt_path)

    text = ledger.to_json(include_records=not args.no_records)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
