#!/usr/bin/env python
"""Browse an EVTX file through a signed, role-bound scope."""

from __future__ import absolute_import

import sys
import json
import argparse

from Evtx.ScopedView import ScopedArchive, ScopedViewError


def _build_parser():
    parser = argparse.ArgumentParser(description="Browse EVTX records through a signed record/field/aggregate scope.")
    parser.add_argument("evtx", help="Path to the Windows EVTX file")
    parser.add_argument("--start", type=int, help="First visible record number (inclusive)")
    parser.add_argument("--end", type=int, help="Last visible record number (inclusive)")
    parser.add_argument("--start-time", help="First visible ISO-8601 timestamp (inclusive)")
    parser.add_argument("--end-time", help="Last visible ISO-8601 timestamp (inclusive)")
    parser.add_argument(
        "--role",
        default="investigator",
        help="View role (operator/investigator or a custom role; default: investigator)",
    )
    parser.add_argument("--label", help="Human-readable scope label")
    parser.add_argument("--field", dest="fields", action="append", help="Allowed field path/glob")
    parser.add_argument("--exclude-field", dest="exclude_fields", action="append", help="Hidden field path/glob")
    parser.add_argument("--redact-field", dest="redact_fields", action="append", help="Redacted field path/glob")
    parser.add_argument("--aggregate", dest="aggregates", action="append", help="Allowed aggregate name")
    parser.add_argument("--exclude-aggregate", dest="exclude_aggregates", action="append", help="Hidden aggregate name")
    parser.add_argument("--min-group-size", type=int, default=1, help="Suppress smaller groups")
    parser.add_argument("--limit", type=int, help="Page size")
    parser.add_argument("--cursor", help="Opaque cursor from a previous page")
    parser.add_argument("--count-by", help="Return a visible-only grouping for this field")
    parser.add_argument("--summary", action="store_true", help="Return the visible summary")
    parser.add_argument("--snapshot", action="store_true", help="Include a signed output receipt")
    parser.add_argument("--no-records", action="store_true", help="Omit record details from output")
    parser.add_argument("--output", help="Write JSON to this path instead of stdout")
    return parser


def _scope_kwargs(args):
    kwargs = {
        "record_start": args.start,
        "record_end": args.end,
        "start_time": args.start_time,
        "end_time": args.end_time,
        "role": args.role,
        "label": args.label,
        "fields": args.fields,
        "exclude_fields": args.exclude_fields,
        "redact_fields": args.redact_fields,
        "aggregates": args.aggregates,
        "exclude_aggregates": args.exclude_aggregates,
        "min_group_size": args.min_group_size,
    }
    return {key: value for key, value in kwargs.items() if value is not None}


def _emit(data, path):
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n")
    else:
        print(text)


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        with ScopedArchive(args.evtx) as archive:
            scope = archive.scope(**_scope_kwargs(args))
            view = archive.browse(scope)
            if args.count_by:
                data = {
                    "scope_id": view.scope.scope_id,
                    "role": view.role,
                    "count": int(view.count),
                    "count_by": view.count_by(args.count_by),
                    "provenance": view.provenance(),
                }
            elif args.summary:
                data = {
                    "scope_id": view.scope.scope_id,
                    "role": view.role,
                    "summary": view.summary(),
                    "provenance": view.provenance(),
                }
            else:
                page = view.records(cursor=args.cursor, limit=args.limit)
                data = page.to_dict(include_records=not args.no_records)
                data["provenance"] = view.provenance()
                if args.snapshot:
                    data["snapshot"] = page.snapshot.to_dict()
        _emit(data, args.output)
        return 0
    except (ScopedViewError, ValueError, OSError) as error:
        print("error: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
