# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  in_toto_reverify.py

<Purpose>
  Provides a command line interface for
  ``reverification.verify_and_build_plan``.

<Return Codes>
  2 if an exception occurred during argument parsing
  1 if an exception occurred (verification failed)
  0 if a re-verification plan was produced

"""

import argparse
import json
import logging
import sys
from collections.abc import Mapping

from securesystemslib._gpg import functions as gpg_interface

from in_toto import __version__, reverification
from in_toto.common_args import (
    GPG_HOME_ARGS,
    GPG_HOME_KWARGS,
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
from in_toto.settings import LINK_CMD_EXEC_TIMEOUT

# Command line interfaces should use in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger("in_toto")


def create_parser():
    """Create and return configured ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
in-toto-reverify verifies a supply chain layout and its link metadata and
produces a plan that says, for every step, whether the existing link can be
reused or the step has to be executed and recorded again.

The plan is dependency-aware. A step is only treated as downstream of another
step if a MATCH rule in the layout really connects their artifacts and their
hash dictionaries are equal. Withdrawing an artifact therefore cuts the
dependency branch that uses that artifact; another branch that happens to use
the same file name but a different digest remains reusable.

Withdrawn artifacts are passed as a JSON file. The file can contain a list of
artifact objects, for example:

  [
    {"step": "build-a", "name": "payload.bin", "sha256": "..."},
    {"hashes": {"sha256": "..."}}
  ]

``step`` and ``name`` are optional. Hashes provide the artifact identity and
are required. If ``step`` is present, the withdrawal applies only to a product
of that step or to a material that is really matched to that step's product.

Verification includes layout signatures, layout expiration, link signature
thresholds, sublayouts, command alignment, and step artifact rules. Inspection
commands are not executed; pass ``--verify-inspections`` to opt in.
""",
    )

    parser.usage = f"%(prog)s <named arguments> [{OPTS_TITLE.lower()}]"

    named_args = parser.add_argument_group("required named arguments")
    named_args.add_argument(
        "-l",
        "--layout",
        type=str,
        required=True,
        metavar="<path>",
        help="path to the root layout to verify.",
    )
    named_args.add_argument(
        "--verification-keys",
        type=str,
        dest="verification_keys",
        metavar="<path>",
        nargs="+",
        help=(
            "paths to public key files used to verify the layout signatures. "
            "Pass at least one key using '--verification-keys' and/or '--gpg'."
        ),
    )
    named_args.add_argument(
        "-g",
        "--gpg",
        nargs="+",
        metavar="<id>",
        help=(
            "GPG keyid(s) used to verify the layout signatures. Pass at least "
            "one key using '--verification-keys' and/or '--gpg'."
        ),
    )

    parser.add_argument(
        "--link-dir",
        dest="link_dir",
        type=str,
        metavar="<path>",
        default=".",
        help=(
            "directory from which link metadata files for layout steps are "
            "loaded. Defaults to the current working directory."
        ),
    )
    parser.add_argument(
        "-w",
        "--withdrawn-artifacts",
        "--withdrawn-artifact",
        dest="withdrawn_artifacts",
        type=str,
        metavar="<path>",
        help="path to a JSON file listing explicitly withdrawn artifacts.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="<path>",
        help="write the JSON plan to this path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the plan as JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--verify-inspections",
        dest="verify_inspections",
        action="store_true",
        help=(
            "also execute inspection commands and verify inspection rules. "
            "Inspections are not run by default."
        ),
    )

    parser.add_argument(*GPG_HOME_ARGS, **GPG_HOME_KWARGS)
    parser.add_argument(
        "--inspection-timeout",
        dest="inspect_timeout",
        type=int,
        default=LINK_CMD_EXEC_TIMEOUT,
        help=(
            "maximum time in seconds for an inspection or sublayout command. "
            f"Default is '{LINK_CMD_EXEC_TIMEOUT}' seconds."
        ),
    )

    verbosity_args = parser.add_mutually_exclusive_group(required=False)
    verbosity_args.add_argument(*VERBOSE_ARGS, **VERBOSE_KWARGS)
    verbosity_args.add_argument(*QUIET_ARGS, **QUIET_KWARGS)

    parser.add_argument(
        "--version",
        action="version",
        version=f"{parser.prog} {__version__}",
    )

    title_case_action_groups(parser)
    sort_action_groups(parser)
    return parser


def load_withdrawn_artifacts(path):
    """Load a withdrawn-artifact list from a JSON file."""
    if path is None:
        return []

    with open(path, encoding="utf8") as file_object:
        data = json.load(file_object)

    if isinstance(data, Mapping):
        for key in ("withdrawn_artifacts", "withdrawals", "withdrawn"):
            if key in data:
                data = data[key]
                break
        else:
            data = [data]

    if not isinstance(data, list):
        raise ValueError(
            "The withdrawn-artifacts file must contain a list or a mapping."
        )

    return data


def main():
    """Parse arguments, verify the layout, and print a plan."""
    parser = create_parser()
    args = parser.parse_args()

    LOG.setLevelVerboseOrQuiet(args.verbose, args.quiet)

    if not (args.gpg or args.verification_keys):
        parser.print_help()
        parser.error(
            "wrong arguments: specify at least one layout verification key:"
            " '--verification-keys path [path ...]' and/or '--gpg id [id ...]'."
        )

    try:
        LOG.info("Loading layout...")
        layout = Metadata.load(args.layout)

        layout_key_dict = {}
        if args.gpg is not None:
            LOG.info("Loading layout gpg key(s)...")
            layout_key_dict.update(
                gpg_interface.export_pubkeys(args.gpg, homedir=args.gpg_home)
            )

        if args.verification_keys:
            for path in args.verification_keys:
                key = load_public_key_from_file(path)
                layout_key_dict[key["keyid"]] = key

        withdrawn_artifacts = load_withdrawn_artifacts(args.withdrawn_artifacts)
        plan = reverification.verify_and_build_plan(
            layout,
            layout_key_dict,
            link_dir_path=args.link_dir,
            withdrawn_artifacts=withdrawn_artifacts,
            inspect_timeout=args.inspect_timeout,
            verify_inspections=args.verify_inspections,
        )

        if args.output:
            with open(args.output, "w", encoding="utf8") as file_object:
                file_object.write(plan.to_json())
                file_object.write("\n")

    except Exception as e:  # noqa: BLE001
        LOG.error("(in-toto-reverify) %s: %s", type(e).__name__, e)
        sys.exit(1)

    if args.json:
        print(plan.to_json())
    else:
        print(reverification.render_plan(plan))

    sys.exit(0)


if __name__ == "__main__":
    main()
