"""Command line entry point for the evidence timeline sample workflow."""

from __future__ import unicode_literals

import argparse
import json
import os

from .analyzer import TimelineAnalyzer
from .model import TrustInput, TrustInputs
from .samples import (
    build_repackaged_record,
    build_replacement_middle_record,
    build_three_stage_sample,
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Synthetic CMS receipt timeline demo (parse-only).',
    )
    parser.add_argument(
        '--out-dir',
        default='sample_output',
        help='directory for generated .der sample records',
    )
    parser.add_argument(
        '--scenario',
        choices=('clean', 'repackaged', 'replaced-middle'),
        default='clean',
        help='which sample scenario to demonstrate',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='emit the timeline as JSON in addition to the text table',
    )
    args = parser.parse_args(argv)

    records, trust = build_three_stage_sample()
    if args.scenario == 'repackaged':
        records[0] = build_repackaged_record(records[0])
    elif args.scenario == 'replaced-middle':
        records[1] = build_replacement_middle_record()

    if not os.path.isdir(args.out_dir):
        os.makedirs(args.out_dir)
    for record in records:
        with open(os.path.join(args.out_dir, record.record_id + '.der'), 'wb') as handle:
            handle.write(record.blob)

    analyzer = TimelineAnalyzer(TrustInputs(token_verdicts=trust))
    for record in records:
        analyzer.add_record(record.record_id, record.blob)
    timeline = analyzer.build()

    print(render_text(timeline, args.scenario))
    if args.json:
        print(json.dumps(to_jsonable(timeline), indent=2, sort_keys=True, default=str))
    return 0


def render_text(timeline, scenario):
    lines = []
    lines.append('Scenario: %s' % scenario)
    lines.append('')
    lines.append('Supplied records:')
    for record in timeline.records:
        lines.append(
            '  - %s (%s, %d bytes, sha256=%s)' % (
                record.record_id,
                record.content_type,
                record.blob_length,
                record.record_digest.hex(),
            )
        )
    lines.append('')
    lines.append('Receipt timeline (oldest first):')
    for entry in timeline.timeline:
        commitment = entry.commitment
        ranges = ', '.join(str(item) for item in commitment.byte_ranges) or '-'
        lines.append('  %s @ %s in %s' % (
            entry.token_id,
            entry.generation_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            entry.record_id,
        ))
        lines.append('    imprint hash : %s:%s' % (
            entry.hash_algorithm,
            entry.message_imprint.hex(),
        ))
        lines.append('    commitment   : %s / %s (%s)' % (
            commitment.status,
            commitment.kind,
            commitment.description,
        ))
        lines.append('    byte ranges  : %s' % ranges)
        predecessor = entry.predecessor
        if predecessor is None:
            predecessor_text = 'none (first receipt, commits to signature bytes)'
        elif predecessor == 'unresolved':
            predecessor_text = 'MISSING predecessor material'
        else:
            predecessor_text = predecessor
        lines.append('    predecessor  : %s' % predecessor_text)
        flags = []
        if entry.repackaged:
            flags.append('outer packaging changed; original commitment still verifiable')
        flags.append('caller trust=' + entry.trust)
        lines.append('    flags        : %s' % '; '.join(flags))
    lines.append('')
    if timeline.gaps:
        lines.append('Provable history gaps:')
        for gap in timeline.gaps:
            lines.append('  - after %s: %s' % (gap.after_token_id, gap.reason))
            lines.append(
                '    only the segment from %s onward is provable from the '
                'supplied bytes; the missing original is not reconstructed' %
                gap.still_provable_from,
            )
    else:
        lines.append('Provable history gaps: none')
    lines.append('Provable window (caller-trusted, hash-matched): %s' % (
        ' -> '.join(timeline.provable_window) or '-',
    ))
    return '\n'.join(lines)


def to_jsonable(timeline):
    return {
        'records': [
            {
                'record_id': record.record_id,
                'content_type': record.content_type,
                'record_digest_sha256': record.record_digest.hex(),
                'blob_length': record.blob_length,
                'envelope_path': record.envelope_path,
            }
            for record in timeline.records
        ],
        'timeline': [
            {
                'token_id': entry.token_id,
                'record_id': entry.record_id,
                'generation_time': entry.generation_time.isoformat(),
                'hash_algorithm': entry.hash_algorithm,
                'message_imprint': entry.message_imprint.hex(),
                'commitment': {
                    'status': entry.commitment.status,
                    'kind': entry.commitment.kind,
                    'description': entry.commitment.description,
                    'byte_ranges': [
                        {
                            'record_id': item.record_id,
                            'start': item.start,
                            'end': item.end,
                        }
                        for item in entry.commitment.byte_ranges
                    ],
                    'matched_bytes': entry.commitment.matched_bytes,
                },
                'predecessor': entry.predecessor,
                'repackaged': entry.repackaged,
                'caller_trust': entry.trust,
            }
            for entry in timeline.timeline
        ],
        'gaps': [gap.__dict__ for gap in timeline.gaps],
        'provable_window': timeline.provable_window,
    }


if __name__ == '__main__':
    raise SystemExit(main())
