import argparse
from typing import cast


def add_provenance_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'feedback',
        aliases=['provenance', 'generated-sources', 'generation-feedback'],
        help='Attributes scan hits to verifiable generated sources.',
        description=(
            'Groups hits in generated files by their upstream source, while retaining every '
            'original scan location. Ambiguous or stale provenance is returned as a rescan '
            'request instead of being silently suppressed.'
        ),
    )

    parser.add_argument(
        'baseline_path',
        nargs='?',
        help='Baseline (or scan output) whose hits should be attributed.',
    )
    parser.add_argument(
        '-b',
        '--baseline-file',
        '--baseline',
        dest='baseline_path_option',
        help='Baseline (or scan output) whose hits should be attributed.',
    )
    parser.add_argument(
        '--generation-sources',
        '--generation-source',
        '--generated-sources',
        '--generated-source-declaration',
        '--generated-source-manifest',
        '--generation-source-declaration',
        '--source-manifest',
        '--generation-config',
        '--source-declaration',
        '--sources',
        '--manifest',
        '--provenance',
        dest='generation_sources',
        required=True,
        help='Caller-provided generation source declaration (JSON or YAML).',
    )
    parser.add_argument(
        '--config-version',
        '--configuration-version',
        '--generation-config-version',
        dest='config_version',
        help='Configuration version used for the scan.',
    )
    parser.add_argument(
        '--previous-feedback',
        '--baseline-feedback',
        '--previous',
        dest='previous_feedback',
        help='Previous feedback output, used to identify newly pending hits.',
    )
    parser.add_argument(
        '--previous-sources',
        '--previous-generation-sources',
        dest='previous_generation_sources',
        help='Previous generation source declaration.',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Emit machine-readable JSON (the default and only format).',
    )

    return cast(argparse.ArgumentParser, parser)


def parse_args(args: argparse.Namespace) -> None:
    if args.action not in {'feedback', 'provenance', 'generated-sources', 'generation-feedback'}:
        return

    if not args.baseline_path and not getattr(args, 'baseline_path_option', None):
        raise argparse.ArgumentTypeError('A baseline file is required.')

    args.baseline_path = args.baseline_path_option or args.baseline_path
