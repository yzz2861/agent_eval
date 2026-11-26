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
import logging
import sys

from securesystemslib._gpg import functions as gpg_interface

from in_toto import __version__, verifylib
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

    parser.add_argument(
        "--offline",
        dest="offline",
        action="store_true",
        help=(
            "enable offline approval reporting, separating signature "
            "threshold shortfalls from valid signed rejection tickets."
        ),
    )
    parser.add_argument(
        "--rejection-tickets",
        "--offline-tickets",
        "--veto-tickets",
        "--rejections",
        dest="rejection_tickets",
        type=str,
        nargs="+",
        metavar="<path>",
        help="paths to separately signed offline rejection ticket files.",
    )
    parser.add_argument(
        "--rejection-ticket",
        dest="rejection_ticket_paths",
        action="append",
        type=str,
        metavar="<path>",
        help="path to one separately signed offline rejection ticket file.",
    )
    parser.add_argument(
        "--approver-keys",
        "--approver-public-keys",
        "--reviewer-keys",
        dest="approver_keys",
        type=str,
        nargs="+",
        metavar="<path>",
        help="public key files trusted to sign offline rejection tickets.",
    )
    parser.add_argument(
        "--approver-key",
        dest="approver_key_paths",
        action="append",
        type=str,
        metavar="<path>",
        help="public key file trusted to sign offline rejection tickets.",
    )
    parser.add_argument(
        "--verification-time",
        "--now",
        "--as-of",
        "--at",
        dest="verification_time",
        type=str,
        default=None,
        help="ISO-8601 verification time used for ticket validity checks.",
    )
    parser.add_argument(
        "--layout-version",
        dest="layout_version",
        type=str,
        default=None,
        help="expected externally assigned layout version for tickets.",
    )
    parser.add_argument(
        "--offline-report",
        dest="offline_report",
        type=str,
        default=None,
        metavar="<path>",
        help="optional path where the JSON offline report is written.",
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
    args.rejection_tickets = (args.rejection_tickets or []) + (
        args.rejection_ticket_paths or []
    )
    args.approver_keys = (args.approver_keys or []) + (
        args.approver_key_paths or []
    )

    LOG.setLevelVerboseOrQuiet(args.verbose, args.quiet)

    # For verifying at least one public key must be specified
    offline_with_approvers = (
        args.offline or args.rejection_tickets
    ) and args.approver_keys
    if not (
        args.gpg or args.verification_keys or offline_with_approvers
    ):
        parser.print_help()
        parser.error(
            "wrong arguments: specify at least one verification key:"
            " '--verification-keys path [path ...]', '--gpg id [id ...]',"
            " or offline '--approver-keys path [path ...]'."
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

        if args.offline or args.rejection_tickets:
            approver_key_dict = {}
            if args.approver_keys:
                for path in args.approver_keys:
                    key = load_public_key_from_file(path)
                    approver_key_dict[key["keyid"]] = key

            report = verifylib.verify_offline(
                layout,
                layout_key_dict,
                link_dir_path=args.link_dir,
                rejection_tickets=args.rejection_tickets,
                approver_key_dict=approver_key_dict,
                verification_time=args.verification_time,
                layout_version=args.layout_version,
            )

            report_json = report.to_json(indent=2)
            if args.offline_report:
                with open(args.offline_report, "w", encoding="utf8") as handle:
                    handle.write(report_json)
            print(report_json)

            if not report.verified:
                sys.exit(1)
            sys.exit(0)

        verifylib.in_toto_verify(
            layout,
            layout_key_dict,
            args.link_dir,
            inspect_timeout=args.inspect_timeout,
        )

    except Exception as e:  # noqa: BLE001
        LOG.error("(in-toto-verify) %s: %s", type(e).__name__, e)
        sys.exit(1)

    sys.exit(0)
