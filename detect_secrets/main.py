import argparse
import json
import os
import sys
from typing import List
from typing import Optional

from . import audit
from .core import baseline
from .core import plugins
from .core.log import log
from .core.scan import get_files_to_scan
from .core.scan import scan_for_allowlisted_secrets_in_file
from .core.scan import scan_line
from .core.secrets_collection import SecretsCollection
from .core.usage import ParserBuilder
from .exceptions import InvalidBaselineError
from .settings import get_plugins
from .settings import get_settings


def main(argv: Optional[List[str]] = None) -> int:
    if not argv and len(sys.argv) == 1:     # pragma: no cover
        argv = ['--help']

    args = parse_args(argv)
    if args.verbose:    # pragma: no cover
        log.set_debug_level(args.verbose)

    if args.action == 'scan':
        handle_scan_action(args)
    elif args.action == 'audit':
        return handle_audit_action(args)

    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    return ParserBuilder().add_console_use_arguments().parse_args(argv)


def handle_scan_action(args: argparse.Namespace) -> None:
    if args.list_all_plugins:
        # NOTE: If there was a baseline provided, it would already have been parsed and
        # settings populated by the time it reaches here.
        print('\n'.join(get_settings().plugins))
        return

    if args.string:
        line = args.string
        if isinstance(args.string, bool):
            # Support stdin usage, rather than specifying on CLI.
            line = sys.stdin.read().splitlines()[0]

        print(scan_adhoc_string(line))
        return

    if args.only_allowlisted:
        secrets = SecretsCollection(root=args.custom_root)
        for filename in get_files_to_scan(
            *args.path,
            should_scan_all_files=args.all_files,
            root=args.custom_root,
        ):
            for secret in scan_for_allowlisted_secrets_in_file(filename):
                secrets[secret.filename].add(secret)

        print(json.dumps(baseline.format_for_output(secrets), indent=2))
        return

    secrets = baseline.create(
        *args.path,
        should_scan_all_files=args.all_files,
        root=args.custom_root,
        num_processors=args.num_cores,
    )
    if args.baseline is not None:
        # The pre-commit hook's baseline upgrade is to trim the supplied baseline for non-existent
        # secrets, and to upgrade the format to the latest version. This is because the pre-commit
        # hook is not supposed to allow any new secrets to enter commit history.
        #
        # Unlike that, this scan's intention is to re-catalog the secrets in the repository. This
        # means that we should favor (and allow) the newly found secrets, and create a baseline
        # with them. It should also upgrade the format to the latest version, which is done by
        # default.
        secrets.merge(args.baseline)

        baseline.save_to_file(secrets, args.baseline_filename)
    else:
        print(json.dumps(baseline.format_for_output(secrets, is_slim_mode=args.slim), indent=2))


def scan_adhoc_string(line: str) -> str:
    registered_plugins = get_plugins()

    results = {
        plugin.secret_type: 'False'
        for plugin in registered_plugins
    }

    for secret in scan_line(line):
        results[secret.type] = (
            plugins.initialize.from_secret_type(secret.type)    # type: ignore
            .format_scan_result(secret)
        )

    # Pretty formatting
    longest_plugin_name_length = max([
        len(plugin.__class__.__name__)
        for plugin in registered_plugins
    ])
    return '\n'.join([
        ('{:%d}: {}' % longest_plugin_name_length).format(
            plugin.__class__.__name__,
            results[plugin.secret_type],
        )
        for plugin in sorted(registered_plugins, key=lambda x: str(x.__class__.__name__))
    ])


def handle_audit_action(args: argparse.Namespace) -> int:
    try:
        if args.export_vendors:
            summary = audit.vendor.export_vendor_packages(
                baseline_file=args.filename[0],
                manifest_file=args.vendor_manifest,
                output_dir=args.export_vendors,
            )
            print(json.dumps(summary, indent=2))
        elif args.merge_vendor_responses:
            state_file = args.vendor_state
            if not state_file:
                first_response = args.merge_vendor_responses[0]
                response_dir = (
                    first_response
                    if os.path.isdir(first_response)
                    else os.path.dirname(first_response)
                ) or '.'
                state_file = os.path.join(response_dir, 'master-state.json')

            result = audit.vendor.merge_vendor_responses(
                state_file=state_file,
                response_files=args.merge_vendor_responses,
                baseline_file=args.filename[0] if args.filename else None,
            )
            print(json.dumps(result, indent=2))
        elif args.report_conflicts:
            report = audit.vendor.report_conflicts(args.vendor_state)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(audit.vendor.format_conflict_report(report))
        elif args.sign_off_accepted:
            result = audit.vendor.sign_off_accepted(args.vendor_state)
            print(json.dumps(result, indent=2))
        elif args.stats:
            stats = audit.analytics.calculate_statistics_for_baseline(args.filename[0])
            if args.diff:
                # TODO
                raise NotImplementedError

            if args.json:
                print(json.dumps(stats.json(), indent=2))
            else:
                print(str(stats))
        elif args.report:
            class_to_print = None
            if args.only_real:
                class_to_print = audit.report.SecretClassToPrint.REAL_SECRET
            elif args.only_false:
                class_to_print = audit.report.SecretClassToPrint.FALSE_POSITIVE
            print(
                json.dumps(
                    audit.report.generate_report(args.filename[0], class_to_print),
                    indent=4,
                    sort_keys=True,
                ),
            )
        else:
            # Starts interactive session.
            if args.diff:
                # Show changes
                audit.compare_baselines(args.filename[0], args.filename[1])
            else:
                # Label secrets
                audit.audit_baseline(args.filename[0])
    except InvalidBaselineError:
        return 0
    except audit.vendor.VendorDistributionError as e:
        print(str(e), file=sys.stderr)
        return 1

    return 0
