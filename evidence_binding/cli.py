"""Command line entry point for the read-only binding inspection."""

import argparse
import sys

from .inspector import inspect_bundle
from .reporting import write_binding_output


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            'Read-only python-registry evidence binding check: verifies '
            'reachability and layer-by-layer source citations and only binds '
            'occurrences with a proven common source.'
        )
    )
    parser.add_argument('bundle', help='case bundle directory to inspect')
    parser.add_argument(
        'output',
        help='directory that will receive the two-generation binding tree',
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='only print the output directory and a compact summary',
    )
    args = parser.parse_args(argv)

    result = inspect_bundle(args.bundle)
    write_binding_output(result, args.output)

    bound = sum(1 for exhibit in result['exhibits'] if len(exhibit.occurrences) > 1)
    print('Binding directory: %s' % args.output)
    print(
        'Artifacts: %d  Occurrences: %d  Exhibits: %d  Multi-occurrence exhibits: %d'
        % (
            len(result['artifacts']),
            len(result['occurrences']),
            len(result['exhibits']),
            bound,
        )
    )
    if result['warnings'] and not args.quiet:
        print('Warnings:')
        for warning in result['warnings']:
            print('  - %s' % warning)
    return 0


if __name__ == '__main__':
    sys.exit(main())
