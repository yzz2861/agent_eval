#!/usr/bin/env python
"""
Compare the policy values in two registry hives using per-value evidence.

This sample intentionally does not compare only the raw hex bytes. The raw
bytes can be identical while the type marker changes (for example RegDWord to
RegBigEndian), which is an evidence representation change rather than a new
policy value.
"""

from __future__ import print_function

import argparse
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from Registry import Registry


def _iter_values(key):
    for value in key.values():
        path = key.path()
        yield "{0}\\{1}".format(path, value.name()), value

    for subkey in key.subkeys():
        for item in _iter_values(subkey):
            yield item


def _collect(hive_path):
    registry = Registry.Registry(hive_path)
    return dict(_iter_values(registry.root()))


def _headline(status):
    if status == Registry.EVIDENCE_REPRESENTATION_CHANGED:
        return "evidence representation change"
    if status == Registry.EVIDENCE_VALUE_CHANGED:
        return "true policy value change"
    return "unchanged"


def compare_hives(before_path, after_path):
    before = _collect(before_path)
    after = _collect(after_path)

    rows = []
    for name in sorted(set(before) | set(after)):
        if name not in before:
            rows.append({
                "name": name,
                "status": "added",
                "headline": "value added",
                "report": "value exists only in the after snapshot",
            })
            continue
        if name not in after:
            rows.append({
                "name": name,
                "status": "removed",
                "headline": "value removed",
                "report": "value exists only in the before snapshot",
            })
            continue

        comparison = before[name].compare(after[name])
        left = comparison["left"]
        right = comparison["right"]
        rows.append({
            "name": name,
            "status": comparison["status"],
            "headline": _headline(comparison["status"]),
            "report": comparison["report"],
            "before": {
                "type": left["type_name"],
                "type_marker": left["value_type"],
                "raw_hex": left["raw_hex"],
                "decoded": left["decoded"],
                "complete": left["complete"],
            },
            "after": {
                "type": right["type_name"],
                "type_marker": right["value_type"],
                "raw_hex": right["raw_hex"],
                "decoded": right["decoded"],
                "complete": right["complete"],
            },
        })

    return rows


def _print_rows(rows, before_path, after_path):
    print("before: {0}".format(before_path))
    print("after:  {0}".format(after_path))
    print("")
    for row in rows:
        print("[{0}] {1}".format(row["status"], row["name"]))
        print("  {0}".format(row["headline"]))
        if "before" in row:
            print(
                "  before: raw={0} type=0x{1:x} {2} decoded={3!r} "
                "complete={4}".format(
                    row["before"]["raw_hex"],
                    row["before"]["type_marker"],
                    row["before"]["type"],
                    row["before"]["decoded"],
                    row["before"]["complete"],
                )
            )
            print(
                "  after:  raw={0} type=0x{1:x} {2} decoded={3!r} "
                "complete={4}".format(
                    row["after"]["raw_hex"],
                    row["after"]["type_marker"],
                    row["after"]["type"],
                    row["after"]["decoded"],
                    row["after"]["complete"],
                )
            )
        print("  why: {0}".format(row["report"]))

    representation = sum(
        1 for row in rows
        if row["status"] == Registry.EVIDENCE_REPRESENTATION_CHANGED
    )
    values = sum(
        1 for row in rows
        if row["status"] == Registry.EVIDENCE_VALUE_CHANGED
    )
    print("")
    print(
        "summary: {0} evidence representation change(s), "
        "{1} true policy value change(s)".format(representation, values)
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare policy registry values using per-value evidence."
    )
    parser.add_argument("before", help="baseline hive snapshot")
    parser.add_argument("after", help="later hive snapshot")
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    args = parser.parse_args(argv)

    rows = compare_hives(args.before, args.after)
    if args.json:
        print(json.dumps({
            "before": args.before,
            "after": args.after,
            "values": rows,
        }, indent=2, sort_keys=True, default=repr))
    else:
        _print_rows(rows, args.before, args.after)
    return 0


if __name__ == "__main__":
    sys.exit(main())
