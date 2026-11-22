"""Command line entry point for the offline receipt comparator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from offline_receipt_compare.comparator import ReceiptComparator
from offline_receipt_compare.models import EvidenceStore, ReceiptSet
from offline_receipt_compare.verifier import MetadataBundle


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the offline comparator CLI."""
    parser = argparse.ArgumentParser(
        description=(
            "Compare old and candidate TUF metadata to decide which "
            "historical acceptance receipts can still be re-verified."
        )
    )
    parser.add_argument(
        "--old-metadata",
        required=True,
        type=Path,
        help="directory of the historical, trusted TUF metadata",
    )
    parser.add_argument(
        "--candidate-metadata",
        required=True,
        type=Path,
        help="directory of the candidate TUF metadata after rule removal",
    )
    parser.add_argument(
        "--receipts",
        required=True,
        type=Path,
        help="directory containing receipt JSON files",
    )
    parser.add_argument(
        "--evidence",
        required=True,
        type=Path,
        help="root directory of retained acceptance evidence",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="optional path to write the JSON report",
    )
    return parser


def main() -> int:
    """Run one comparison and print (and optionally save) the report."""
    args = build_parser().parse_args()
    receipts = ReceiptSet.load(args.receipts).receipts
    comparator = ReceiptComparator(
        old_bundle=MetadataBundle(args.old_metadata),
        candidate_bundle=MetadataBundle(args.candidate_metadata),
        receipts=receipts,
        evidence=EvidenceStore(args.evidence),
    )
    report = comparator.run()
    payload = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
