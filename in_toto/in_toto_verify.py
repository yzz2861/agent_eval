# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  in_toto_verify.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Oct 3, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides a command line interface for verifylib.in_toto_verify.

<Return Codes>
  2 if an exception occurred during argument parsing
  1 if an exception occurred (verification failed)
  0 if no exception occurred (verification passed)

"""

import argparse
import json
import logging
import sys

from securesystemslib._gpg import functions as gpg_interface

from in_toto import __version__, acceptance, verifylib
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
in-toto-verify is the main verification tool of the suite, and it is used to
verify that the software supply chain of the delivered product was carried out
as defined in the passed in-toto supply chain layout. Evidence for supply chain
steps must be available in the form of link metadata files named
'<step name>.<functionary keyid prefix>.link'.

Both 'in-toto-run' and 'in-toto-record' generate link metadata named in this
manner. If you require special handling of the in-toto link metadata files,
please take a look at the library api to modify this behavior.

The verification includes the following checks:
  * the layout is signed with the passed keys,
  * the layout has not expired,
  * a threshold of link metadata files exists for each step of the layout,
  * link files are signed by the authorized functionaries,
  * the materials and products for each step, as reported by the corresponding
    link files, adhere to the artifact rules specified by the step.

Additionally, inspection commands defined in the layout are executed
sequentially, followed by processing the inspections' artifact rules.

If the layout includes sublayouts, the verification routine will recurse into a
subdirectory named '<step name>.<keyid prefix>', where all the links relevant
to that sublayout must exist. The sublayout itself must be in the same
directory as the other links of the superlayout. (i.e. '<step name>.<keyid
prefix>.link')

The verification workflow is performed in isolation and does not rely on
information about keys that are available through external sources. For example,
in-toto does not rely on the creation time, revocation status, and usage flags
for PGP keys.

The command returns 2 if it is called with wrong arguments, 1 if in-toto
verification fails and 0 if verification passes. """,
    )

    parser.usage = f"%(prog)s <named arguments> [{OPTS_TITLE.lower()}]"

    parser.epilog = f"""EXAMPLE USAGE

Verify supply chain in 'root.layout', signed with private part of
'key_file.pub'.

  {parser.prog} --layout root.layout --verification-keys key_file.pub


Verify supply chain as above but load links corresponding to steps of
'root.layout' from 'link_dir'.

  {parser.prog} --layout root.layout --verification-keys key_file.pub \\
      --link-dir link_dir


Verify supply chain in 'root.layout', signed with GPG key '...7E0C8A17',
for which the public part can be found in the GPG keyring at '~/.gnupg'.

  {parser.prog} --layout root.layout \\
      --gpg 8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17 \\
      --gpg-home ~/.gnupg


"""

    named_args = parser.add_argument_group("required named arguments")

    named_args.add_argument(
        "-l",
        "--layout",
        type=str,
        required=True,
        metavar="<path>",
        help=(
            "path to root layout specifying the software supply chain to be"
            " verified."
        ),
    )
    named_args.add_argument(
        "--verification-keys",
        type=str,
        dest="verification_keys",
        metavar="<path>",
        nargs="+",
        help=(
            "paths to public key files used to verify the passed root layout's"
            " signatures. Supported keytypes are rsa, ed25519, ecdsa (nistp256)"
            " in a standard subjectPublicKeyInfo/PEM format. Passing at least"
            " one key using '--verification-keys' and/or '--gpg' is required."
            " For each passed key the layout must carry a valid signature."
        ),
    )

    named_args.add_argument(
        "-g",
        "--gpg",
        nargs="+",
        metavar="<id>",
        help=(
            "GPG keyid, identifying a public key in the GPG keyring used to verify"
            " the passed root layout's signatures."
            " Passing at least one key using '--verification-keys' and/or '--gpg' is"
            " required. For each passed key the layout must carry a valid"
            " signature."
        ),
    )

    parser.add_argument(
        "--link-dir",
        dest="link_dir",
        type=str,
        metavar="<path>",
        default=".",
        help=(
            "path to directory from which link metadata files for steps defined"
            " in the root layout should be loaded. If not passed, links are"
            " loaded from the current working directory."
        ),
    )

    parser.add_argument(*GPG_HOME_ARGS, **GPG_HOME_KWARGS)
    parser.add_argument(
        "--inspection-timeout",
        dest="inspect_timeout",
        type=int,
        default=LINK_CMD_EXEC_TIMEOUT,
        help=(
            "integer that represents the max timeout in seconds for the "
            "   in-toto-verify command for inspect subprocess."
            f"   Default is '{LINK_CMD_EXEC_TIMEOUT}' seconds."
        ),
    )

    parser.add_argument(
        "--forbid-artifact",
        dest="forbid_artifacts",
        nargs="+",
        metavar="<pattern>",
        help=(
            "enable the optional artifact absence completeness check for"
            " the passed glob pattern(s), for example *.debug. An empty"
            " product table only passes if a signed enumeration declaration"
            " in the link metadata proves that the checked scope was"
            " enumerated."
        ),
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
        help=("artifact table(s) to check for forbidden artifacts."),
    )
    parser.add_argument(
        "--require-confirmed-artifacts",
        dest="require_confirmed_artifacts",
        action="store_true",
        help=(
            "treat allowed_omission as a failure; only a signed, complete"
            " enumeration (confirmed_none) passes."
        ),
    )
    parser.add_argument(
        "--artifact-report",
        dest="artifact_report",
        metavar="<path>",
        help="write the artifact acceptance audit report as JSON to <path>.",
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


def main():
    """Parse arguments and call in_toto_verify."""
    parser = create_parser()
    args = parser.parse_args()

    LOG.setLevelVerboseOrQuiet(args.verbose, args.quiet)

    # For verifying at least one public key must be specified
    if not (args.gpg or args.verification_keys):
        parser.print_help()
        parser.error(
            "wrong arguments: specify at least one layout verification key:"
            " '--verification-keys path [path ...]' and/or '--gpg id [id ...]'."
        )

    artifact_absence_check = None
    acceptance_report_callback = None
    if args.forbid_artifacts:
        artifact_absence_check = acceptance.ArtifactAbsenceCheck(
            patterns=args.forbid_artifacts,
            scope=args.artifact_scope,
            direction=args.artifact_direction,
            allow_omission=not args.require_confirmed_artifacts,
        )

        def acceptance_report_callback(report):
            print(report.format_text())
            if args.artifact_report:
                with open(args.artifact_report, "w", encoding="utf8") as fp:
                    json.dump(report.to_dict(), fp, indent=2, sort_keys=True)
                    fp.write("\n")

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

        verifylib.in_toto_verify(
            layout,
            layout_key_dict,
            args.link_dir,
            inspect_timeout=args.inspect_timeout,
            artifact_absence_check=artifact_absence_check,
            acceptance_report_callback=acceptance_report_callback,
        )

    except Exception as e:  # noqa: BLE001
        LOG.error("(in-toto-verify) %s: %s", type(e).__name__, e)
        sys.exit(1)

    sys.exit(0)
