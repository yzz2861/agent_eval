# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""CLI for the optional artifact-usage review."""

import argparse
import json
import logging
import sys

from in_toto import __version__, reviewlib
from in_toto.common_args import (
    VERBOSE_ARGS,
    VERBOSE_KWARGS,
    sort_action_groups,
    title_case_action_groups,
)
from in_toto.models.metadata import Metadata

LOG = logging.getLogger("in_toto")


def create_parser():
    """Create and return configured ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Review how copies of an approved artifact are renamed and "
            "consumed across the actual steps of an in-toto layout. The "
            "review follows material/product rule paths instead of only "
            "comparing content hashes."
        ),
    )
    named_args = parser.add_argument_group("required named arguments")
    named_args.add_argument(
        "-l",
        "--layout",
        type=str,
        required=True,
        metavar="<path>",
        help="path to layout metadata.",
    )
    parser.add_argument(
        "--link-dir",
        dest="link_dir",
        type=str,
        default=".",
        metavar="<path>",
        help=(
            "directory containing link metadata; defaults to the current "
            "working directory."
        ),
    )
    parser.add_argument(
        "--usage-declarations",
        dest="usage_declarations",
        type=str,
        metavar="<path>",
        help=(
            "path to a JSON document declaring approved purposes and build "
            "uses."
        ),
    )
    parser.add_argument(
        "--strict",
        dest="strict",
        action="store_true",
        help="raise on out-of-scope or unknown conclusions.",
    )
    parser.add_argument(
        "--json",
        dest="json",
        action="store_true",
        help="print the review result as JSON.",
    )
    parser.add_argument(*VERBOSE_ARGS, **VERBOSE_KWARGS)
    parser.add_argument(
        "--version",
        action="version",
        version=f"{parser.prog} {__version__}",
    )

    title_case_action_groups(parser)
    sort_action_groups(parser)
    return parser


def main():
    """Parse arguments, run the review, and return an exit code."""
    parser = create_parser()
    args = parser.parse_args()
    LOG.setLevelVerboseOrQuiet(args.verbose, False)

    layout = Metadata.load(args.layout).get_payload()
    try:
        result = reviewlib.review_material_usage(
            layout,
            args.link_dir,
            args.usage_declarations,
            strict=args.strict,
        )
    except reviewlib.ArtifactScopeError as error:
        LOG.error("(in-toto-review) %s: %s", type(error).__name__, error)
        sys.exit(1)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Artifact usage review: {result.status}")
        for finding in result.findings:
            if finding.status == reviewlib.IN_SCOPE:
                continue
            location = finding.path or finding.step or "<unknown>"
            print(
                f"  {finding.status}: {finding.kind} {location} "
                f"{finding.message}"
            )

    if result.status == reviewlib.IN_SCOPE:
        sys.exit(0)
    if result.status == reviewlib.OUT_OF_SCOPE:
        sys.exit(1)
    sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    main()
