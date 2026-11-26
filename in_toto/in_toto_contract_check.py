# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""CLI for offline Windows/Linux path contract checks."""

import argparse
import json
import sys

from in_toto.contract_check import (
    ContractError,
    check_contract,
    load_contract,
    render_markdown,
)


def create_parser():
    """Create and return a configured ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Run an offline contract check for artifact paths and in-toto rules.

The contract simulates the path mapping exported by each platform profile and
the material/product rule matching for those paths. It does not read build
artifacts or walk the filesystem. The report states whether rules matched the
original or a normalized name, lists ambiguous mapping candidates, and shows
which rule's applicable set expanded between the 'before' and 'after'
policies.

The command exits 1 if the selected policy is divergent or ambiguous, and 0 if
all platforms reached the same decision. Use --report-only to always exit 0.
""",
    )
    parser.add_argument(
        "contract",
        metavar="<contract.json>",
        help="path to the JSON contract description",
    )
    parser.add_argument(
        "-p",
        "--policy",
        choices=["before", "after"],
        default="after",
        help="policy used for the primary cross-platform verdict (default: after)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="report format (default: markdown)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="<path>",
        help="write the report to this file instead of stdout",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="always exit 0 after writing the report",
    )
    return parser


def main():
    """Run the contract check CLI."""
    parser = create_parser()
    args = parser.parse_args()

    try:
        contract = load_contract(args.contract)
        result = check_contract(contract, policy_name=args.policy)
    except (ContractError, OSError, json.JSONDecodeError) as exception:
        parser.error(str(exception))

    if args.format == "json":
        report = json.dumps(result, indent=2, sort_keys=True) + "\n"
    else:
        report = render_markdown(result) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fileobj:
            fileobj.write(report)
    else:
        sys.stdout.write(report)

    if args.report_only:
        return 0

    failed = any(
        case["cross_platform"][args.policy]["status"]
        in {"DIVERGENT", "AMBIGUOUS"}
        for case in result["cases"]
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
