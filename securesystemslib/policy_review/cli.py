"""Command line interface for offline signing-policy review.

Example:
    python -m securesystemslib.policy_review policy.json roster.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from securesystemslib.policy_review.models import PolicyReviewError
from securesystemslib.policy_review.policy import load_policy
from securesystemslib.policy_review.report import report_to_dict, report_to_markdown
from securesystemslib.policy_review.review import review
from securesystemslib.policy_review.roster import load_roster


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="policy-review",
        description=
        "Offline review of DSSE signing combinations against a frozen "
        "control-domain roster.",
    )
    parser.add_argument("policy", type=Path,
        help="path to the DSSE policy JSON document")
    parser.add_argument("roster", type=Path,
        help="path to the frozen roster JSON document")
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="output format (default: markdown)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write the report here instead of stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        roster = load_roster(args.roster)
        report = review(policy, roster)
    except PolicyReviewError as error:
        print(f"policy review failed: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = json.dumps(report_to_dict(report), indent=2, sort_keys=True)
    else:
        rendered = report_to_markdown(report)

    if args.output is None:
        print(rendered)
    else:
        args.output.write_text(rendered + chr(10))
    # Input problems are reported inside the document but do not by themselves
    # make the tool fail; structural failures raise PolicyReviewError above.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
