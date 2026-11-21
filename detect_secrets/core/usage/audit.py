import argparse
from typing import cast


def add_audit_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'audit',
        help='Manually assesses a baseline to determine validity of secrets found.',
        description=(
            'Auditing a baseline allows analysts to label results, and optimize plugins for '
            'the highest signal-to-noise ratio for their environment.'
        ),
    )

    parser.add_argument(
        'filename',
        nargs='*',
        help=(
            'Audit a given baseline file to distinguish the difference '
            'between false and true positives.'
        ),
    )

    _add_mode_parser(parser)
    _add_report_module(parser)
    _add_statistics_module(parser)
    _add_vendor_module(parser)
    return cast(argparse.ArgumentParser, parser)


def _add_mode_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--diff',
        action='store_true',
        help=(
            'Allows the comparison of two baseline files, in order to '
            'effectively distinguish the difference between various '
            'plugin configurations.'
        ),
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help=(
            'Displays the results of an interactive auditing session '
            'which have been saved to a baseline file.'
        ),
    )

    parser.add_argument(
        '--report',
        action='store_true',
        help=(
            'Displays a report with the secrets detected'
        ),
    )


def _add_report_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='reporting',
        description=(
            'Display a report with all the findings and the made decisions. '
            'To be used with the report mode (--report).'
        ),
    )

    report_parser = parser.add_mutually_exclusive_group()
    report_parser.add_argument(
        '--only-real',
        action='store_true',
        help=(
            'Only includes real secrets in the report'
        ),
    )

    report_parser.add_argument(
        '--only-false',
        action='store_true',
        help=(
            'Only includes false positives in the report'
        ),
    )


def _add_statistics_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='analytics',
        description=(
            'Quantify the success of your plugins based on the labelled results '
            'in your baseline. To be used with the statistics mode (--stats).'
        ),
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Outputs results in a machine-readable format.',
    )


def _add_vendor_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='vendor distribution',
        description=(
            'Export redacted findings to separately responsible vendors, then merge their '
            'offline responses. Vendor exports only contain paths assigned to that vendor. '
            'Signed-off accepted decisions are preserved even when late feedback arrives.'
        ),
    )

    parser.add_argument(
        '--vendor-manifest',
        metavar='<path>',
        help=(
            'JSON manifest assigning repository paths to vendors. Paths may overlap for '
            'jointly-reviewed directories.'
        ),
    )

    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        '--export-vendors',
        metavar='<dir>',
        help=(
            'Write one redacted export per vendor (plus master-state.json) to this directory. '
            'Requires --vendor-manifest and one baseline file.'
        ),
    )
    modes.add_argument(
        '--merge-vendor-responses',
        metavar='<path>',
        nargs='+',
        help=(
            'Merge one or more edited vendor exports back into master state. A directory '
            'containing vendor JSON files may also be supplied.'
        ),
    )
    modes.add_argument(
        '--report-conflicts',
        action='store_true',
        help=(
            'Show findings where vendors reached contradictory conclusions, or where '
            'feedback challenges a signed-off accepted decision.'
        ),
    )
    modes.add_argument(
        '--sign-off-accepted',
        action='store_true',
        help=(
            'Freeze the currently accepted, reviewed decisions. Later feedback remains '
            'visible but cannot silently replace them.'
        ),
    )

    parser.add_argument(
        '--vendor-state',
        metavar='<path>',
        help=(
            'Master state file created by --export-vendors. Required for report/sign-off '
            'modes; inferred from the response directory for merge mode when omitted.'
        ),
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.action != 'audit':
        return

    vendor_mode = bool(
        args.export_vendors or
        args.merge_vendor_responses or
        args.report_conflicts or
        args.sign_off_accepted,
    )
    regular_mode = bool(args.diff or args.stats or args.report)

    if vendor_mode and regular_mode:
        raise argparse.ArgumentTypeError(
            'Vendor distribution modes cannot be combined with --diff, --stats, or --report.',
        )

    if args.export_vendors:
        if len(args.filename) != 1:
            raise argparse.ArgumentTypeError(
                '--export-vendors requires exactly one baseline file.',
            )
        if not args.vendor_manifest:
            raise argparse.ArgumentTypeError(
                '--export-vendors requires --vendor-manifest.',
            )
        return

    if args.merge_vendor_responses:
        if len(args.filename) > 1:
            raise argparse.ArgumentTypeError(
                '--merge-vendor-responses accepts at most one baseline file.',
            )
        return

    if args.report_conflicts or args.sign_off_accepted:
        if not args.vendor_state and len(args.filename) == 1:
            args.vendor_state = args.filename[0]

        if not args.vendor_state:
            raise argparse.ArgumentTypeError(
                '--report-conflicts and --sign-off-accepted require --vendor-state.',
            )
        if len(args.filename) > 1:
            raise argparse.ArgumentTypeError(
                'This vendor mode accepts at most one baseline file.',
            )
        return

    if args.diff and len(args.filename) != 2:
        raise argparse.ArgumentTypeError(
            '--diff mode requires two files to compare with each other.',
        )
    elif not args.diff and len(args.filename) != 1:
        raise argparse.ArgumentTypeError(
            'Can only specify one baseline at a time.',
        )
