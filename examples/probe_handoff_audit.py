#!/usr/bin/env python
"""
Offline audit of probe capture conditions from a (possibly concatenated)
pcapng file.

Two probes may label their capture interface with the same human remark
while actually capturing on different link layers.  This tool keeps each
section's interface identity separate, reports the link type declared in
each Interface Description Block together with a few observable packet
prefixes, and points at the specific original interface involved when two
interfaces share a remark but disagree on their link type.

Usage::

    python examples/probe_handoff_audit.py capture.pcapng [--checklist list.ini]

The optional checklist is an ini file with one section per interface,
keyed by its label in this report, for example::

    [section 0 / interface 0]
    link_type = 1
"""

from __future__ import print_function

import argparse
import sys

from pcapng import FileScanner
from pcapng.handoff import (
    check_handoff,
    collect_interfaces,
    find_remark_conflicts,
    load_checklist,
)


def _print_prefix(prefix, indent):
    pad = " " * indent
    if prefix["rule"] is None:
        print(
            "{pad}no prefix rule for this link type; "
            "raw leading bytes: {hex}".format(pad=pad, hex=prefix["raw_hex"])
        )
        return

    print("{pad}prefix: {rule}".format(pad=pad, rule=prefix["rule"]))
    detail = ", ".join(
        "{0}={1}".format(key, value)
        for key, value in prefix["fields"].items()
    )
    print("{pad}fields: {detail}".format(pad=pad, detail=detail))


def print_report(records, checklist=None):
    print("Observed interfaces: {0}".format(len(records)))
    print("")

    for record in records:
        print("== {0} ==".format(record.label))
        if record.remark is not None:
            print("  interface remark : {0!r}".format(record.remark))
        else:
            print("  interface remark : (none recorded)")

        if record.link_type_known:
            print(
                "  declared link type: {0} ({1})".format(
                    record.link_type, record.link_type_name
                )
            )
        else:
            # Unfamiliar link type: only state the numeric value, never
            # invent a name or packet structure for it.
            print(
                "  declared link type: {0} (not known to this library; "
                "no further interpretation available)".format(record.link_type)
            )

        print("  snap length      : {0}".format(record.snaplen))
        print("  packets observed : {0}".format(record.packet_count))

        if record.packet_count == 0:
            print("  packet prefixes  : (no packets in file)")
        else:
            print("  packet prefixes  :")
            for prefix in record.prefixes:
                _print_prefix(prefix, indent=6)
        print("")

    conflicts = find_remark_conflicts(records)
    print("Shared-remark link type conflicts: {0}".format(len(conflicts)))
    for conflict in conflicts:
        print(
            "  remark {remark!r} is used by interfaces whose declared "
            "link types differ:".format(remark=conflict["remark"])
        )
        for record in conflict["interfaces"]:
            name = record.link_type_name or "unknown link type"
            print(
                "    - {label}: link type {value} ({name})".format(
                    label=record.label, value=record.link_type, name=name
                )
            )
    print("")

    if checklist is not None:
        mismatches = check_handoff(records, checklist)
        print("Handoff checklist mismatches: {0}".format(len(mismatches)))
        for mismatch in mismatches:
            record = mismatch["record"]
            expected_name = mismatch["expected_name"] or "unknown link type"
            observed_name = record.link_type_name or "unknown link type"
            print(
                "  - {label}: checklist expects {expected} ({ename}), "
                "block declares {actual} ({aname})".format(
                    label=record.label,
                    expected=mismatch["expected"],
                    ename=expected_name,
                    actual=record.link_type,
                    aname=observed_name,
                )
            )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcapng_file", help="path to the pcapng capture file")
    parser.add_argument(
        "--checklist",
        help="optional ini file describing the receivers' handoff checklist",
    )
    args = parser.parse_args(argv)

    checklist = None
    if args.checklist:
        with open(args.checklist, "r") as stream:
            checklist = load_checklist(stream)

    with open(args.pcapng_file, "rb") as stream:
        scanner = FileScanner(stream)
        records = collect_interfaces(scanner)

    print_report(records, checklist=checklist)
    return 0


if __name__ == "__main__":
    sys.exit(main())
