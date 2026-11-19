"""Command line entry point for release checks.

    python -m policy_audit audit BASE.yaml OVERLAY.yaml [...]
    python -m policy_audit compare --old BASE.yaml OVERLAY.yaml \
        --new BASE.yaml OVERLAY_SWAPPED.yaml
"""

from __future__ import annotations

import argparse
import sys

from .analyze import analyze_policy
from .compare import compare_policies
from .loader import load_policy
from .report import render_comparison, render_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="policy_audit")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_parser = sub.add_parser("audit", help="audit one merged policy")
    audit_parser.add_argument("files", nargs="+")

    compare_parser = sub.add_parser(
        "compare", help="show which deployment scope changes hands"
    )
    compare_parser.add_argument("--old", nargs="+", required=True)
    compare_parser.add_argument("--new", nargs="+", required=True)

    args = parser.parse_args(argv)

    if args.command == "audit":
        policy = load_policy(args.files)
        verdicts, issues, domain = analyze_policy(policy)
        print(render_report(policy, verdicts, issues, domain))
        blocking = [v for v in verdicts if v.verdict == "fully_shadowed"]
        return 1 if blocking or issues else 0

    changes, _, _ = compare_policies(args.old, args.new)
    print(render_comparison(changes, args.old, args.new))
    return 0


if __name__ == "__main__":
    sys.exit(main())
