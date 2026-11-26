import argparse
from typing import cast


COMMAND_NAMES = (
    'import-review',
    'review-import',
    'import-manifest',
    'reconcile',
    'review-manifest',
    'check-manifest',
)


def add_review_action(parent: argparse._SubParsersAction, name: str = 'import-review') -> argparse.ArgumentParser:
    aliases = [candidate for candidate in COMMAND_NAMES if candidate != name]
    parser = parent.add_parser(
        name,
        aliases=aliases,
        help='Import an adjudicated review manifest and reconcile it with a baseline.',
        description=(
            'Offline reconciliation of a review-tool manifest with a detect-secrets '
            'baseline. Only the supplied manifest and baseline are read; the original '
            'source files are never opened. Emits summary/location check results.'
        ),
    )
    parser.add_argument(
        'baseline_file',
        nargs='?',
        default=None,
        metavar='BASELINE',
        help='Baseline JSON file (optional if the manifest embeds one).',
    )
    parser.add_argument(
        'manifest_positional',
        nargs='?',
        default=None,
        metavar='manifest',
        help='Review manifest JSON file.',
    )
    parser.add_argument(
        '--manifest', '--review-manifest', '--import-review', '--review-file',
        dest='review_manifest',
        default=None,
        metavar='FILE',
        help='Review manifest JSON file.',
    )
    parser.add_argument(
        '--save', '--write-baseline',
        dest='save_imported',
        action='store_true',
        default=False,
        help='Write imported decisions back into the baseline file.',
    )
    return cast(argparse.ArgumentParser, parser)


def parse_args(args: argparse.Namespace) -> None:
    if getattr(args, 'action', None) not in COMMAND_NAMES:
        return
    if not getattr(args, 'review_manifest', None):
        positional_manifest = getattr(args, 'manifest_positional', None)
        if positional_manifest:
            args.review_manifest = positional_manifest
    # Allow ``detect-secrets reconcile MANIFEST`` (no baseline) by shifting.
    if not getattr(args, 'review_manifest', None) and getattr(args, 'baseline_file', None):
        args.review_manifest = args.baseline_file
        args.baseline_file = None
