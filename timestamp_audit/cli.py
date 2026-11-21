# coding: utf-8
"""
Command line entry point for the offline time-stamp inventory.

Example:
    python -m timestamp_audit audit \
        --receipt materials/summary_a.tsr --receipt materials/summary_b.tsr \
        --exhibit EX-01=materials/exhibit1.pdf \
        --exhibit EX-02=materials/exhibit2.pdf \
        --verdicts verdicts.json --output report.json

Everything is computed from local bytes; no network access is performed.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import argparse
import json
import sys

from .inventory import build_inventory
from .matching import (
    ALGORITHM_UNINTERPRETABLE,
    EXHIBIT_BYTES_MISSING,
    NO_LOCAL_MATCH,
)


def _load_json(path):
    with open(path, 'rb') as f:
        return json.loads(f.read().decode('utf-8'))


def _parse_exhibit_argument(value):
    if '=' not in value:
        raise argparse.ArgumentTypeError(
            "exhibit argument must look like EXHIBIT_ID=/path/to/file, got %r" % value
        )
    exhibit_id, path = value.split('=', 1)
    return {'exhibit_id': exhibit_id, 'path': path}


def _merge_manifest(args, manifest):
    receipt_files = list(manifest.get('receipt_files', []))
    receipt_files.extend(args.receipt or [])

    exhibits = []
    for exhibit in manifest.get('exhibits', []):
        if isinstance(exhibit, dict):
            exhibits.append((exhibit['exhibit_id'], exhibit['path']))
        else:
            exhibits.append((exhibit[0], exhibit[1]))
    exhibits.extend(
        (exhibit['exhibit_id'], exhibit['path']) for exhibit in (args.exhibit or [])
    )

    verdicts = dict(manifest.get('signature_verdicts', {}))
    if args.verdicts:
        verdicts.update(_load_json(args.verdicts))

    return receipt_files, exhibits, verdicts


def _render_text(report):
    lines = []
    summary = report['summary']
    lines.append('Offline time-stamp inventory')
    lines.append('  matching basis: algorithm OID + imprint digest over local bytes '
                 '(genTime excluded)')
    lines.append('  time-stamp tokens: %d (%d nested); matched: %d, unmatched: %d, '
                 'uninterpretable algorithm: %d' % (
                     summary['time_stamp_tokens_total'],
                     summary['nested_tokens_total'],
                     summary['matched_tokens_total'],
                     summary['unmatched_tokens_total'],
                     summary['uninterpretable_algorithm_tokens_total'],
                 ))
    lines.append('  exhibits: %d, missing bytes: %d, without own receipt: %d' % (
        summary['exhibits_total'],
        summary['exhibits_missing_bytes_total'],
        summary['exhibits_without_receipt_total'],
    ))

    lines.append('')
    lines.append('Receipts')
    for receipt in report['receipts']:
        lines.append('  - %s depth=%d %s' % (
            receipt['receipt_id'][:12],
            receipt['depth'],
            receipt['match_status'],
        ))
        lines.append('      origin: %s' % receipt['origin_path'])
        lines.append('      gen_time: %s (display only, not used for matching)'
                     % receipt['gen_time'])
        lines.append('      algorithm: %s (%s)' % (
            receipt['digest_algorithm_name'] or 'unknown',
            receipt['digest_algorithm_oid'],
        ))
        lines.append('      imprint: %s' % receipt['message_imprint_digest_hex'])
        if receipt['nested_receipt_ids']:
            lines.append('      nested receipts: %s'
                         % ', '.join(rid[:12] for rid in receipt['nested_receipt_ids']))
        lines.append('      signature verdict: %s' % receipt['signature_verdict'])

    lines.append('')
    lines.append('Exhibits without their own receipt')
    for exhibit in report['exhibits_without_receipt']:
        lines.append('  - %s [%s] %s' % (
            exhibit['exhibit_id'], exhibit['status'], exhibit['path'],
        ))

    lines.append('')
    lines.append('Summary pages sharing the same displayed gen_time')
    for group in report['same_gen_time_groups']:
        lines.append('  - gen_time %s: %s statuses=%s' % (
            group['gen_time'],
            ', '.join(rid[:12] for rid in group['receipt_ids']),
            ','.join(group['match_statuses']),
        ))

    if report['parse_errors']:
        lines.append('')
        lines.append('Parse errors')
        for error in report['parse_errors']:
            lines.append('  - %s: %s (%s)' % (
                error['origin_path'], error['error'], error['detail'],
            ))

    return '\n'.join(lines)


def _build_parser():
    parser = argparse.ArgumentParser(
        prog='timestamp_audit',
        description='Offline CMS time-stamp receipt inventory for exhibit review',
    )
    subparsers = parser.add_subparsers(dest='command')

    audit = subparsers.add_parser('audit', help='build an offline inventory report')
    audit.add_argument(
        '--receipt', action='append', metavar='PATH',
        help='path to a DER/PEM CMS ContentInfo or TimeStampResp (repeatable)',
    )
    audit.add_argument(
        '--exhibit', action='append', type=_parse_exhibit_argument,
        metavar='EXHIBIT_ID=PATH',
        help='exhibit identifier and local file path (repeatable)',
    )
    audit.add_argument(
        '--manifest', metavar='PATH',
        help='JSON manifest with receipt_files, exhibits and signature_verdicts',
    )
    audit.add_argument(
        '--verdicts', metavar='PATH',
        help='JSON mapping of receipt id to {"verdict": ..., "note": ...}',
    )
    audit.add_argument(
        '--output', metavar='PATH',
        help='write the full JSON report here (defaults to stdout alongside text)',
    )
    audit.add_argument(
        '--json-only', action='store_true',
        help='print only the JSON report instead of the human-readable summary',
    )
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != 'audit':
        parser.print_help()
        return 2

    manifest = _load_json(args.manifest) if args.manifest else {}
    receipt_files, exhibits, verdicts = _merge_manifest(args, manifest)
    if not receipt_files:
        parser.error('at least one --receipt path or manifest receipt_files entry is required')

    report = build_inventory(receipt_files, exhibits, signature_verdicts=verdicts)
    report_json = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report_json)

    if args.json_only:
        sys.stdout.write(report_json + '\n')
    else:
        sys.stdout.write(_render_text(report) + '\n')
        if args.output:
            sys.stdout.write('\nJSON report written to %s\n' % args.output)

    has_blocking_issue = bool(report['parse_errors']) or any(
        receipt['match_status'] in (NO_LOCAL_MATCH, ALGORITHM_UNINTERPRETABLE)
        for receipt in report['receipts']
    ) or any(
        exhibit['status'] == EXHIBIT_BYTES_MISSING for exhibit in report['exhibits']
    )
    return 1 if has_blocking_issue else 0


if __name__ == '__main__':
    sys.exit(main())
