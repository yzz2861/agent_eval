#!/usr/bin/env python
#-------------------------------------------------------------------------------
# scripts/cfi_compare.py
#
# Read-only comparison of DWARF call-frame information from two ELF files.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import json
import sys

# For running from the development directory. It should take precedence over
# an installed pyelftools.
sys.path.insert(0, '.')

from elftools.dwarf.cfi_compare import (
    AddressMap,
    FrameCompareError,
    FrameComparison,
    FrameFile,
    FramePair,
    compare_frame_files,
)


def _int_argument(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f'invalid integer: {value!r}') from error


def _format_source(source: object) -> str:
    if source is None:
        return '<none>'
    path = getattr(source, 'path', '?')
    section = getattr(source, 'section', '?')
    fde_offset = getattr(source, 'fde_offset', None)
    line_index = getattr(source, 'line_index', None)
    pc = getattr(source, 'pc', None)
    details = []
    if fde_offset is not None:
        details.append(f'fde+{fde_offset:#x}')
    if line_index is not None:
        details.append(f'line {line_index}')
    if pc is not None:
        details.append(f'pc {pc:#x}')
    suffix = ' '.join(details)
    return f'{path}:{section}' + (f' ({suffix})' if suffix else '')


def _format_interval(interval: object) -> str:
    start = getattr(interval, 'start')
    end = getattr(interval, 'end')
    status = getattr(interval, 'status')
    details = []
    for difference in getattr(interval, 'differences', ()):
        details.append(
            f'{difference.field}: {difference.left} != {difference.right}')
    for rule in getattr(interval, 'incomparable_rules', ()):
        expression = (
            rule.expression.hex() if rule.expression is not None else '<none>')
        details.append(
            f'{rule.side} {rule.field} {rule.rule_type} '
            f'expr={expression} source={_format_source(rule.source)}')
    suffix = '; '.join(details)
    return (
        f'  {start:#x}..{end:#x}  {status.value}'
        + (f'  [{suffix}]' if suffix else ''))


def _print_report(report: FrameComparison) -> None:
    print('CFI comparison (read-only)')
    print(f'  left : {report.left_file.path}')
    print(
        f'         {report.left_file.section} '
        f'@ {report.left_file.section_address:#x}, '
        f'sha256={report.left_file.sha256}')
    print(f'  right: {report.right_file.path}')
    print(
        f'         {report.right_file.section} '
        f'@ {report.right_file.section_address:#x}, '
        f'sha256={report.right_file.sha256}')
    print(
        '  map  : left = right '
        f'{report.pair.right_to_left.offset:+#x}')
    print('  FDE pairs:')
    for matched in report.matched_fdes:
        print(
            f'    {matched.start:#x}: '
            f'left [{matched.left_range[0]:#x}, {matched.left_range[1]:#x}) '
            f'right [{matched.right_range[0]:#x}, '
            f'{matched.right_range[1]:#x})')
    print('  Intervals:')
    for interval in report.intervals:
        print(_format_interval(interval))
    for warning in report.warnings:
        print(f'  warning: {warning}')
    summary = ', '.join(
        f'{status}={count}' for status, count in report.summary().items())
    print(f'  summary: {summary}')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Compare decoded DWARF call-frame rules from two ELF files.')
    parser.add_argument('left', help='artifact ELF file')
    parser.add_argument('right', help='external debug ELF file')
    parser.add_argument(
        '--left-section',
        choices=('.eh_frame', '.debug_frame', 'auto'),
        default='auto',
        help='left CFI section (default: auto, preferring .eh_frame)')
    parser.add_argument(
        '--right-section',
        choices=('.eh_frame', '.debug_frame', 'auto'),
        default='auto',
        help='right CFI section (default: auto, preferring .debug_frame)')
    parser.add_argument(
        '--right-to-left-offset',
        '--right-offset',
        dest='right_offset',
        type=_int_argument,
        default=0,
        help='left = right + this bias; applied before comparing')
    parser.add_argument(
        '--json',
        action='store_true',
        help='write the full result as JSON')
    args = parser.parse_args(argv)

    try:
        report = compare_frame_files(FramePair(
            left=FrameFile(args.left, args.left_section),
            right=FrameFile(args.right, args.right_section),
            right_to_left=AddressMap(args.right_offset)))
    except (FrameCompareError, OSError) as error:
        print(f'cfi_compare: {error}', file=sys.stderr)
        return 2

    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        _print_report(report)

    return 0 if report.is_clean else 1


if __name__ == '__main__':
    sys.exit(main())
