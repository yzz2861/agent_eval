# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Audit standalone link metadata for artifact absence completeness."""

import argparse
import json
import logging
import sys

from in_toto import __version__, acceptance
from in_toto.common_args import (
    OPTS_TITLE,
    QUIET_ARGS,
    QUIET_KWARGS,
    VERBOSE_ARGS,
    VERBOSE_KWARGS,
    sort_action_groups,
    title_case_action_groups,
)
from in_toto.models._signer import load_public_key_from_file
from in_toto.models.metadata import Metadata

LOG = logging.getLogger("in_toto")


def create_parser():
    """Create and return configured ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Audit one or more link metadata files for a forbidden artifact"
            " class. An empty artifact table is only accepted if a signed"
            " enumeration declaration proves that the checked scope was"
            " enumerated."
        ),
    )

    parser.usage = "%(prog)s <named arguments> [" + OPTS_TITLE.lower() + "]"

    named_args = parser.add_argument_group("required named arguments")
    named_args.add_argument(
        "--link",
        dest="links",
        nargs="+",
        required=True,
        metavar="<path>",
        help="path(s) to link metadata files to audit.",
    )
    named_args.add_argument(
        "--verification-keys",
        dest="verification_keys",
        nargs="+",
        required=True,
        metavar="<path>",
        help=(
            "public key file(s) used to verify that each link signature is"
            " valid before its signed declaration is trusted."
        ),
    )
    named_args.add_argument(
        "--forbid-artifact",
        dest="forbid_artifacts",
        nargs="+",
        required=True,
        metavar="<pattern>",
        help="glob pattern(s) of the forbidden artifact class.",
    )

    parser.add_argument(
        "--artifact-scope",
        dest="artifact_scope",
        nargs="+",
        metavar="<path>",
        default=["."],
        help=(
            "path(s) or prefix(es) that must be covered by the signed"
            " enumeration boundary. Defaults to the current directory."
        ),
    )
    parser.add_argument(
        "--artifact-direction",
        dest="artifact_direction",
        choices=("products", "materials", "both"),
        default="products",
        help="artifact table(s) to check for forbidden artifacts.",
    )
    parser.add_argument(
        "--require-confirmed-artifacts",
        dest="require_confirmed_artifacts",
        action="store_true",
        help=(
            "treat allowed_omission as a failure; only confirmed_none passes."
        ),
    )
    parser.add_argument(
        "--artifact-report",
        dest="artifact_report",
        metavar="<path>",
        help="write the audit report as JSON to <path>.",
    )

    verbosity_args = parser.add_mutually_exclusive_group(required=False)
    verbosity_args.add_argument(*VERBOSE_ARGS, **VERBOSE_KWARGS)
    verbosity_args.add_argument(*QUIET_ARGS, **QUIET_KWARGS)

    parser.add_argument(
        "--version", action="version", version=f"{parser.prog} {__version__}"
    )

    title_case_action_groups(parser)
    sort_action_groups(parser)
    return parser


def _verified_keyid(metadata, keys):
    """Return the keyid of the first key that verifies ``metadata``."""
    for key in keys:
        try:
            metadata.verify_signature(key)
        except Exception:  # noqa: BLE001, S112
            continue
        return key["keyid"]
    return None


def main():
    """Parse arguments, verify signatures and print the audit report."""
    parser = create_parser()
    args = parser.parse_args()
    LOG.setLevelVerboseOrQuiet(args.verbose, args.quiet)

    check = acceptance.ArtifactAbsenceCheck(
        patterns=args.forbid_artifacts,
        scope=args.artifact_scope,
        direction=args.artifact_direction,
        allow_omission=not args.require_confirmed_artifacts,
    )

    keys = [load_public_key_from_file(path) for path in args.verification_keys]

    observations = []
    for path in args.links:
        try:
            metadata = Metadata.load(path)
        except Exception as e:  # noqa: BLE001
            observations.append(
                acceptance.Observation(
                    source=path,
                    step="",
                    direction=check.direction,
                    status=acceptance.EVIDENCE_MISSING,
                    reason=f"cannot load metadata: {e}",
                )
            )
            continue

        keyid = _verified_keyid(metadata, keys)
        if keyid is None:
            observations.append(
                acceptance.Observation(
                    source=path,
                    step="",
                    direction=check.direction,
                    status=acceptance.EVIDENCE_MISSING,
                    reason="no passed key verifies the link signature",
                )
            )
            continue

        observations.append(
            acceptance.audit_metadata(
                metadata,
                check,
                label=f"{path} [{keyid[:8]}]",
            )
        )

    report = acceptance.AcceptanceReport(check, links=observations)
    print(report.format_text())

    if args.artifact_report:
        with open(args.artifact_report, "w", encoding="utf8") as fp:
            json.dump(report.to_dict(), fp, indent=2, sort_keys=True)
            fp.write("\n")

    sys.exit(0 if report.ok() else 1)


if __name__ == "__main__":
    main()
