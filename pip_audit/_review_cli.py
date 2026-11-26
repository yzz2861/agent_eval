"""Command-line entrypoint for offline candidate-lock review."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pip_audit._review import (
    ReviewError,
    ReviewOptions,
    load_audit_reports,
    load_candidates,
    reconcile,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pip-audit-review",
        description=(
            "reconcile pip-audit JSON output with candidate dependency locks without network access"
        ),
    )
    parser.add_argument(
        "--audit",
        dest="audits",
        type=Path,
        action="append",
        required=True,
        metavar="FILE",
        help="pip-audit JSON output; may be supplied multiple times",
    )
    parser.add_argument(
        "--candidates",
        type=Path,
        required=True,
        metavar="FILE",
        help="JSON or TOML candidate lock artifacts",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="write the report to FILE instead of stdout",
    )
    parser.add_argument(
        "--max-artifacts",
        type=int,
        default=None,
        metavar="N",
        help="only enumerate combinations of at most N artifacts",
    )
    parser.add_argument(
        "--max-combinations",
        type=int,
        default=65536,
        metavar="N",
        help="refuse to enumerate more than N combinations (default: 65536)",
    )
    parser.add_argument(
        "--max-alternatives",
        type=int,
        default=20,
        metavar="N",
        help="retain at most N approval-required alternatives (default: 20)",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="exit 0 even when no recommended plan closes every advisory",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline review CLI and return its exit status."""

    args = _parser().parse_args(argv)
    try:
        reports = load_audit_reports(args.audits)
        candidates = load_candidates(args.candidates)
        report = reconcile(
            reports,
            candidates,
            options=ReviewOptions(
                max_artifacts=args.max_artifacts,
                max_combinations=args.max_combinations,
                max_alternatives=args.max_alternatives,
            ),
        )
    except (ReviewError, OSError) as exc:
        print(f"pip-audit-review: error: {exc}", file=sys.stderr)
        return 2

    rendered = report.to_json() if args.format == "json" else report.to_text()
    try:
        if args.output is None:
            print(rendered)
        else:
            args.output.write_text(rendered + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"pip-audit-review: error: {exc}", file=sys.stderr)
        return 2

    if report.complete or args.allow_incomplete:
        return 0
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
