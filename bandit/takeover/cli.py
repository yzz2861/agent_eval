# SPDX-License-Identifier: Apache-2.0
"""Command line entry point for the takeover adjudication layer.

Example::

    bandit-takeover \\
        --policy policy/ownership.yaml \\
        --current reports/bandit-current.json \\
        --legacy reports/bandit-legacy.json \\
        --approval-out approval.txt \\
        --json-out adjudication.json \\
        --legacy-json-out bandit-compat.json

The legacy-compatible report can also be generated on its own with
``--legacy-json-only``, leaving the adjudication pipeline untouched.
"""
from __future__ import annotations

import argparse
import datetime
import logging
import sys

from bandit.takeover.engine import AdjudicationEngine
from bandit.takeover.loader import PolicyError, load_policy, load_report
from bandit.takeover.reports import (
    render_approval_detail,
    render_approval_json,
    render_legacy_report,
)

LOG = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_INPUT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Adjudicate Bandit results against ownership policy, handoff "
            "records and the legacy findings backlog."
        )
    )
    parser.add_argument(
        "--policy",
        required=True,
        help="YAML/JSON ownership and handoff policy",
    )
    parser.add_argument(
        "--current", required=True, help="Bandit JSON report from this scan"
    )
    parser.add_argument(
        "--legacy",
        help="Previous Bandit JSON report holding the accepted legacy backlog",
    )
    parser.add_argument(
        "--approval-out",
        help="Write the human-readable approval detail to this path",
    )
    parser.add_argument(
        "--json-out",
        help="Write the machine-readable adjudication JSON to this path",
    )
    parser.add_argument(
        "--legacy-json-out",
        help="Write a legacy-format Bandit JSON report to this path",
    )
    parser.add_argument(
        "--legacy-json-only",
        action="store_true",
        help="Only regenerate the legacy-format report, then exit",
    )
    return parser


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def main(argv=None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        current_scan = load_report(args.current)
        if args.legacy_json_only:
            if not args.legacy_json_out:
                parser.error("--legacy-json-only requires --legacy-json-out")
            _write(args.legacy_json_out, render_legacy_report(current_scan))
            LOG.info("Wrote legacy-format report %s", args.legacy_json_out)
            return EXIT_OK

        bundle = load_policy(args.policy)
        legacy_report = load_report(args.legacy) if args.legacy else {}
        engine = AdjudicationEngine(
            ownership_policy=bundle.ownership_policy,
            handoff_ledger=bundle.handoff_ledger,
            path_map=bundle.path_map,
        )
        report = engine.adjudicate(
            current_scan=current_scan,
            legacy_report=legacy_report,
            manifest_directories=bundle.manifest_for(current_scan),
            generated_at=datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    except (OSError, PolicyError, ValueError) as exc:
        LOG.error("Input error: %s", exc)
        return EXIT_INPUT_ERROR

    approval_text = render_approval_detail(report)
    if args.approval_out:
        _write(args.approval_out, approval_text)
    else:
        print(approval_text)
    if args.json_out:
        _write(args.json_out, render_approval_json(report))
    if args.legacy_json_out:
        _write(args.legacy_json_out, render_legacy_report(current_scan))

    if report.gate_failed:
        LOG.error(
            "Gate FAILED: %s blocking finding(s), %s director(ies) with "
            "unknown risk",
            len(report.blocking()),
            len(report.unknown_risk_directories()),
        )
        return EXIT_GATE_FAILED
    LOG.info("Gate passed")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
