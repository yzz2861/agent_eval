"""Command line entry point for the offline mask consistency check."""

from __future__ import annotations

import argparse
import json
import sys

from mask_audit.checker import (
    MASK_CATEGORY_DATABASE,
    MaskRange,
    SessionSchema,
    check_consistency,
)


def _load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _build_schema(payload):
    return SessionSchema(
        database_zones=payload.get("database_zones", {}),
        placeholder_zones=payload.get("placeholder_zones", {}),
    )


def _build_permits(payload):
    permits = []
    for item in payload.get("mask_ranges", []):
        permits.append(
            MaskRange(
                start=item["start"],
                end=item["end"],
                category=item.get("category", MASK_CATEGORY_DATABASE),
                placeholder=item.get("placeholder"),
                zone=item.get("zone"),
            ),
        )
    return permits


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m mask_audit",
        description=(
            "Offline consistency check between an original SQL document "
            "and its desensitized review copy."
        ),
    )
    parser.add_argument("original", help="Path to the original SQL file.")
    parser.add_argument("review", help="Path to the masked review SQL file.")
    parser.add_argument(
        "--permits",
        required=True,
        help="JSON file listing the permitted mask ranges.",
    )
    parser.add_argument(
        "--schema",
        help="Optional JSON file with database-to-zone session schema.",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    with open(args.original, encoding="utf-8") as handle:
        original_sql = handle.read()
    with open(args.review, encoding="utf-8") as handle:
        review_sql = handle.read()
    permits = _build_permits(_load_json(args.permits))
    schema = (
        _build_schema(_load_json(args.schema))
        if args.schema is not None else SessionSchema()
    )
    report = check_consistency(original_sql, review_sql, permits, schema)
    json.dump(report.as_dict(), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 1 if report.has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
