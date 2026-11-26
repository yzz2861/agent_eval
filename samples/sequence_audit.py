#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from Registry import Registry
from Registry.SequenceAudit import _open_key, audit_hives, load_approval_record


DEFAULT_BASELINE = os.path.join(ROOT, "tests", "reg_samples", "audit_recipients_baseline.hive")
DEFAULT_CURRENT = os.path.join(ROOT, "tests", "reg_samples", "audit_recipients_current.hive")
DEFAULT_APPROVALS = os.path.join(ROOT, "samples", "audit_approvals.json")


def multisz_value_names(hive_path, key_path):
    reg = Registry.Registry(hive_path)
    key = _open_key(reg, key_path)
    return [value.name() for value in key.values() if value.value_type() == Registry.RegMultiSZ]


def print_human(value_name, report):
    data = report.to_dict()
    print("")
    print("=== %s ===" % value_name)
    print("baseline : %s" % " | ".join("#%d=%r" % (m["ordinal"], m["value"]) for m in data["before"]["members"]))
    print("current  : %s" % " | ".join("#%d=%r" % (m["ordinal"], m["value"]) for m in data["after"]["members"]))

    if data["reorder_only"]:
        mapping = ", ".join("current #%d <- baseline #%d" % (m["after_ordinal"], m["before_ordinal"]) for m in data["matches"])
        print("sequence : reorder-only; %s" % mapping)
    elif data["added"]:
        print("sequence : added occurrence(s): %s" % ", ".join("current #%d %r" % (x["current_ordinal"], x["value"]) for x in data["added"]))
    else:
        print("sequence : unchanged")

    if data["set_misses_occurrence_change"]:
        print("set view : %r -> %r (set diff misses duplicate/order evidence)" % (data["set_before"], data["set_after"]))

    for decision in data["decisions"]:
        if decision["status"] == "authorized":
            print("approval : AUTHORIZED current #%d %r via %s -> original #%s" % (
                decision["current_ordinal"], decision["value"],
                decision.get("approval_id"), decision.get("baseline_ordinal")))
        else:
            print("approval : %s current #%d %r" % (
                decision["status"].upper(), decision["current_ordinal"], decision["value"]))
    print("verdict  : %s" % data["verdict"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare ordered REG_MULTI_SZ members in two offline hives")
    parser.add_argument("baseline", nargs="?", default=DEFAULT_BASELINE)
    parser.add_argument("current", nargs="?", default=DEFAULT_CURRENT)
    parser.add_argument("--key", default="AuditConfig")
    parser.add_argument("--value", default=None)
    parser.add_argument("--approvals", default=DEFAULT_APPROVALS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    approval_record = load_approval_record(args.approvals) if args.approvals else None
    aliases = approval_record.get("aliases") if isinstance(approval_record, dict) else None
    value_names = [args.value] if args.value else multisz_value_names(args.baseline, args.key)

    reports = {}
    for value_name in value_names:
        reports[value_name] = audit_hives(
            args.baseline, args.current, args.key, value_name,
            approval_record=approval_record, aliases=aliases
        )

    if args.json:
        print(json.dumps({name: report.to_dict() for name, report in reports.items()}, ensure_ascii=False, indent=2))
    else:
        for name, report in reports.items():
            print_human(name, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
