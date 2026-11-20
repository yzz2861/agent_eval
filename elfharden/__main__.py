"""Command line entry: python -m elfharden [--rule ...] FILE ..."""

from __future__ import annotations

import argparse
import json
import sys

from .audit import ALL_RULES, audit_elf
from .model import RuleId


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m elfharden",
        description="Offline ELF hardening audit (no execution, pyelftools only).",
    )
    parser.add_argument("files", nargs="+", help="ELF files to audit")
    parser.add_argument(
        "--rule",
        action="append",
        choices=[rule.value for rule in ALL_RULES],
        help="restrict output to a rule; repeat to select several",
    )
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rules = [RuleId(item) for item in args.rule] if args.rule else None
    reports = [audit_elf(path, rules=rules).to_dict() for path in args.files]
    payload = reports[0] if len(reports) == 1 else reports
    json.dump(payload, sys.stdout, indent=args.indent, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
