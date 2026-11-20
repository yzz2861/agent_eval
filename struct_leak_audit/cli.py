"""Command line entry point for the structure leak audit."""
from __future__ import annotations

import argparse

from .analyzer import AuditConfig
from .report import audit_file, to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="C source file (no compilation needed)")
    parser.add_argument("--struct", required=True, help="public struct tag to audit")
    parser.add_argument("--exit", action="append", default=[],
                        help="host reporting function (repeatable)")
    parser.add_argument("--projection", action="append", default=[],
                        help="trusted projection function (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = AuditConfig(
        public_struct=args.struct,
        report_functions=tuple(args.exit),
        projection_functions=tuple(args.projection),
    )
    result = audit_file(args.source, config)
    print(to_json(result) if args.json else to_text(result), end="")
    return 0 if result.verdict.name != "UNSAFE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
