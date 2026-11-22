#!/usr/bin/env python
"""Report review coverage over one or more EVTX evidence scopes.

This command uses the read-only python-evtx parser.  It inventories real
record positions, loads optional receipts from a JSON file, and prints a
coverage ledger that distinguishes reusable receipts from stale ones.
"""

import argparse
import json
import sys

from Evtx.Ledger import CoverageLedger, FieldRequirements


DEFAULT_FIELDS = ["EventID", "TimeCreated", "EventRecordID"]


def _split_evidence(spec):
    if "=" not in spec:
        raise argparse.ArgumentTypeError("--evidence expects NAME=PATH")
    name, path = spec.split("=", 1)
    if not name or not path:
        raise argparse.ArgumentTypeError("--evidence expects NAME=PATH")
    return name, path


def _format_text(ledger, traces):
    lines = []
    requirements = ledger.requirements()
    lines.append("Requirements: {} ({})".format(requirements.name(), requirements.key()))
    lines.append("Fields: {}".format(", ".join(sorted(requirements.fields())) or "(none)"))
    lines.append("Reuse policy: {}".format(ledger.reuse_policy()))
    lines.append("")

    for scope in ledger.evidence_scopes():
        report = ledger.summary()["evidence"][scope]
        lines.append("Evidence: {}".format(scope))
        lines.append(
            "  records={} reviewed={} anomalies={}".format(
                report["records"], report["reviewed_records"], report["anomalies"]
            )
        )
        if report["reviewed_intervals"]:
            lines.append("  reviewed record intervals: {}".format(report["reviewed_intervals"]))
        if report["reviewed_positions"]:
            lines.append("  reviewed positions:")
            for position in report["reviewed_positions"]:
                lines.append(
                    "    record {} at offset {} ({}) receipts={}".format(
                        position["record_num"],
                        position["offset"],
                        position["timestamp"],
                        ",".join(position["receipt_ids"]),
                    )
                )
        if report["unreviewed"]:
            lines.append("  unreviewed:")
            for item in report["unreviewed"]:
                lines.append(
                    "    record {} at offset {}: {}".format(
                        item["record_num"], item["offset"], " | ".join(item["reasons"])
                    )
                )
        if report["stale_receipts"]:
            lines.append("  stale receipts: {}".format(", ".join(report["stale_receipts"])))
        lines.append("")

    lines.append("Receipts:")
    if not ledger.receipts():
        lines.append("  (none)")
    for receipt in ledger.receipts():
        reasons = ledger.receipt_status(receipt)
        status = "active" if not reasons else "stale: {}".format("; ".join(reasons))
        lines.append(
            "  {} reviewer={} evidence={} records={} {}".format(
                receipt.receipt_id, receipt.reviewer, receipt.evidence, receipt.record_range(), status
            )
        )

    lines.append("")
    lines.append(
        "Reviewed log time: {} (overlap avoided: {:.1f}s)".format(
            ledger.reviewed_duration(), ledger.overlap_time_seconds()
        )
    )
    if traces:
        lines.append("")
        lines.append("Traces:")
        for (scope, record_num), hits in traces.items():
            if not hits:
                lines.append("  {} record {}: no receipt".format(scope, record_num))
                continue
            for hit in hits:
                status = "active" if hit.active else "stale: {}".format("; ".join(hit.reasons))
                lines.append(
                    "  {} record {} -> {} reviewer={} {}".format(
                        scope, record_num, hit.receipt.receipt_id, hit.receipt.reviewer, status
                    )
                )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Report review coverage per EVTX evidence scope using read-only parsing."
    )
    parser.add_argument("evtx", nargs="*", help="EVTX files; each path is used as its evidence scope")
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Explicit evidence scope name and EVTX path; may be repeated",
    )
    parser.add_argument("--receipts", help="JSON file with previously filed receipts")
    parser.add_argument("--requirements-name", default="case-review", help="Label for the active requirements")
    parser.add_argument(
        "--require-field",
        action="append",
        default=[],
        help="Field that the active review must certify; may be repeated",
    )
    parser.add_argument(
        "--reuse-policy",
        choices=["compatible", "exact", "any"],
        default="compatible",
        help="How old receipts are matched against the active field requirements",
    )
    parser.add_argument("--no-render", action="store_true", help="Skip XML rendering during inventory")
    parser.add_argument("--trace", action="append", default=[], metavar="EVIDENCE:RECORD", help="Trace a receipt")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    parser.add_argument("--output", help="Write the ledger JSON to this file instead of stdout")
    parser.add_argument(
        "--fail-on-unreviewed",
        action="store_true",
        help="Exit with status 2 when any unreviewed record or stale receipt remains",
    )
    args = parser.parse_args(argv)

    pairs = []
    for spec in args.evidence:
        try:
            pairs.append(_split_evidence(spec))
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
    for path in args.evtx:
        pairs.append((path, path))
    if not pairs:
        parser.error("provide at least one EVTX path or --evidence NAME=PATH")

    fields = args.require_field or DEFAULT_FIELDS
    ledger = CoverageLedger(
        FieldRequirements(args.requirements_name, fields),
        reuse_policy=args.reuse_policy,
    )

    for name, path in pairs:
        ledger.scan_file(name, path, render=not args.no_render)

    if args.receipts:
        with open(args.receipts, "r", encoding="utf-8") as handle:
            ledger.load_receipts(json.load(handle))

    traces = {}
    for spec in args.trace:
        if ":" not in spec:
            parser.error("--trace expects EVIDENCE:RECORD")
        scope, number = spec.rsplit(":", 1)
        try:
            record_num = int(number)
        except ValueError:
            parser.error("--trace expects an integer record number")
        traces[(scope, record_num)] = ledger.trace(scope, record_num=record_num)

    if args.output:
        ledger.write_json(args.output)
    payload = ledger.to_dict()

    if args.format == "text":
        text = _format_text(ledger, traces)
        if args.output:
            print("Wrote {}".format(args.output))
        else:
            print(text)
    elif not args.output:
        print(json.dumps(payload, indent=2, sort_keys=True))

    if args.fail_on_unreviewed:
        gaps = sum(len(report["unreviewed"]) for report in payload["evidence"].values())
        stale = sum(len(report["stale_receipts"]) for report in payload["evidence"].values())
        if gaps or stale:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
