#!/usr/bin/env python3
"""Read-only disclosure audit for ELF symbol material.

The tool joins symbol tables, section ranges, DWARF source references and
separate debug/symbol files, then checks every recoverable symbol name and
source path against an explicit approval policy.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elftools.common.exceptions import DWARFError, ELFError  # noqa: E402
from elftools.elf.disclosure import (  # noqa: E402
    DisclosurePolicy,
    DisclosureReport,
    audit_path,
)


def _read_policy(path: str | None) -> dict[str, Any]:
    if path is None:
        return {}
    with open(path, encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError('policy must be a JSON object')
    return data


def _policy_for_object(
    manifest: dict[str, Any],
    object_path: str,
) -> DisclosurePolicy:
    """Resolve a policy manifest.

    A manifest may be a single policy object with ``symbols`` /
    ``compile_units`` / ``sources`` keys, or map object paths (or basenames)
    to separate policy objects. ``_default`` is used as a fallback.
    """
    policy_keys = {
        'symbols', 'allow_symbols', 'allowed_symbols',
        'compile_units', 'cus', 'allow_compile_units',
        'allowed_compile_units', 'sources', 'allow_sources',
        'allowed_sources', 'allow_undefined_symbols',
        'allow_raw_debug_paths',
    }
    if not manifest or policy_keys.intersection(manifest):
        return DisclosurePolicy.from_dict(manifest)

    basename = os.path.basename(object_path)
    chunks: list[dict[str, Any]] = []
    default = manifest.get('_default')
    if isinstance(default, dict):
        chunks.append(default)
    direct = manifest.get(object_path) or manifest.get(basename)
    if isinstance(direct, dict):
        chunks.append(direct)

    objects = manifest.get('objects')
    if isinstance(objects, list):
        for item in objects:
            if not isinstance(item, dict):
                continue
            target = str(item.get('path', ''))
            if target in (object_path, basename):
                chunks.append(item)

    if not chunks:
        raise ValueError(
            f'no policy entry for {object_path!r} (use _default or objects)')
    return DisclosurePolicy.from_dict({
        key: value
        for chunk in chunks
        for key, value in chunk.items()
    })


def _merge_cli_policy(
    policy: DisclosurePolicy,
    args: argparse.Namespace,
) -> DisclosurePolicy:
    symbols = set(policy.symbols).union(args.allow_symbol or ())
    compile_units = set(policy.compile_units).union(args.allow_cu or ())
    sources = set(policy.sources).union(args.allow_source or ())
    return DisclosurePolicy(
        symbols=frozenset(symbols),
        compile_units=frozenset(compile_units),
        sources=frozenset(sources),
        allow_undefined_symbols=(
            policy.allow_undefined_symbols or args.allow_undefined),
        allow_raw_debug_paths=(
            policy.allow_raw_debug_paths or args.allow_raw_debug_paths),
    )


def _parse_ranges(values: list[str] | None) -> list[tuple[int, int]] | None:
    if not values:
        return None
    ranges: list[tuple[int, int]] = []
    for value in values:
        if '-' not in value:
            raise ValueError(f'invalid range {value!r}; expected START-END')
        start, end = value.split('-', 1)
        begin = int(start, 0)
        finish = int(end, 0)
        if finish <= begin:
            raise ValueError(f'invalid empty range {value!r}')
        ranges.append((begin, finish))
    return ranges


def _format_range(value: dict[str, int] | None) -> str:
    if not value:
        return '-'
    return f'[0x{value["start"]:x},0x{value["end"]:x})'


def _print_report(report: DisclosureReport) -> None:
    identity = report.identity
    print(f'== {report.object_path} ==')
    print(
        f'ELF{identity["elf_class"]} '
        f'{"LSB" if identity["little_endian"] else "MSB"} '
        f'{identity["type"]} {identity["machine"]}; '
        f'{len(report.sections)} sections; '
        f'build-id={identity.get("build_id") or "-"}')
    if report.debug_file:
        print(f'separate symbol/debug file: {report.debug_file}')

    print(f'approved symbols ({len(report.symbols)}):')
    for symbol in report.symbols:
        print(
            f'  {symbol.name}  {symbol.section or "?"} '
            f'section={_format_range(symbol.section_range)} '
            f'file={_format_range(symbol.file_range)} '
            f'type={symbol.type}/{symbol.binding}')
        for location in symbol.source_locations:
            print(
                f'    {location["path"]}:{location["line"]}'
                f':{location["column"]} ({location["via"]})')

    print(f'associated compilation units ({len(report.compile_units)}):')
    for unit in report.compile_units:
        state = 'approved' if unit.approved else 'OUT-OF-SCOPE'
        print(
            f'  {unit.source or unit.name or "?"} '
            f'{unit.ranges} association={unit.association} {state}')
        for path in unit.files:
            print(f'    file: {path}')

    print(f'findings ({len(report.findings)}):')
    for finding in report.findings:
        print(f'  {finding.severity.upper()} {finding.code}: '
              f'{finding.message}')
        if finding.via:
            print(f'    via: {", ".join(finding.via)}')

    print(f'RESULT: {"PASS" if report.approved else "FAIL"}')
    print()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            'Read-only ELF disclosure audit. Only symbols and compilation '
            'units covered by the policy are included in the public view; '
            'any extra recoverable symbol name or source path fails the '
            'review.'))
    parser.add_argument(
        'elf', nargs='+', metavar='ELF',
        help='ELF object(s) to audit')
    parser.add_argument(
        '--policy', metavar='JSON',
        help='approval policy JSON (single policy or per-object manifest)')
    parser.add_argument(
        '--allow-symbol', action='append', metavar='NAME',
        help='allow a public symbol name (repeatable, shell globs accepted)')
    parser.add_argument(
        '--allow-cu', action='append', metavar='PATH',
        help='allow a compilation-unit source path (repeatable)')
    parser.add_argument(
        '--allow-source', action='append', metavar='PATH',
        help='allow an additional source/header path (repeatable)')
    parser.add_argument(
        '--debug-file', metavar='PATH',
        help=('separate symbol/debug ELF; if omitted, .gnu_debuglink is '
              'resolved next to the object'))
    parser.add_argument(
        '--object-range', action='append', metavar='START-END',
        help=('address range used to isolate a shared debug file '
              '(repeatable)'))
    parser.add_argument(
        '--allow-undefined', action='store_true',
        help='do not report undefined symbol names')
    parser.add_argument(
        '--allow-raw-debug-paths', action='store_true',
        help='do not scan unreferenced .debug_str/.debug_line_str paths')
    parser.add_argument(
        '--json', action='store_true',
        help='emit a machine-readable report')
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        manifest = _read_policy(args.policy)
        ranges = _parse_ranges(args.object_range)
        if ranges is not None and len(args.elf) != 1:
            raise ValueError('--object-range requires exactly one ELF input')
        reports = []
        for path in args.elf:
            policy = _merge_cli_policy(
                _policy_for_object(manifest, path), args)
            reports.append(audit_path(
                path,
                policy,
                debug_file=args.debug_file,
                object_ranges=ranges,
            ))
    except (OSError, ValueError, ELFError, DWARFError,
            json.JSONDecodeError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2

    approved = all(report.approved for report in reports)
    if args.json:
        print(json.dumps({
            'approved': approved,
            'read_only': True,
            'objects': [report.to_dict() for report in reports],
        }, indent=2, sort_keys=True))
    else:
        for report in reports:
            _print_report(report)
    return 0 if approved else 1


if __name__ == '__main__':
    raise SystemExit(main())
