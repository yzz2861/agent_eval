# -*- coding: utf-8 -*-

"""Command line entry point for building the re-review list."""

from __future__ import absolute_import

import argparse
import json

from .data import ATTACHMENTS, HISTORY
from .engine import evaluate
from .policy import POLICIES, build_rereview_list
from .rules import RULES


REASON_LABELS = {
    'rule-retired': 'old approval rule retired',
    'matched-rule-changed': 'matched rule changed (same format name)',
    'format-changed': 'recognized format changed',
    'evidence-insufficient': 'header evidence below policy floor',
    'unrecognized-format': 'no current rule matches',
    'format-not-allowed': 'format not on policy allowlist',
    'no-prior-approval': 'no prior approval on record',
}


def _print_scan_inventory():
    scans = evaluate(ATTACHMENTS)
    floor = max(policy.evidence_floor for policy in POLICIES.values())
    print('Current filetype capability: %d ordered rules (policy evidence '
          'floor: %dB)' % (len(RULES), floor))
    print('-' * 72)
    for attachment in ATTACHMENTS:
        scan = scans[attachment['attachment_id']]
        alternatives = ', '.join(
            rule.rule_id for rule in scan.matching_rules) or '-'
        gateway_ok = scan.sufficient and scan.header_length >= floor
        print('%-9s %-24s format=%-5s rule=%-18s also=[%s] evidence=%s (%dB)'
              % (
                  attachment['attachment_id'],
                  attachment['filename'][:24],
                  scan.format or '-',
                  scan.rule_id or '-',
                  alternatives,
                  'ok' if gateway_ok else 'weak',
                  scan.header_length,
              ))


def _print_policy_report(name):
    result = build_rereview_list(ATTACHMENTS, HISTORY, name)
    policy = POLICIES[name]
    print('=' * 72)
    print('Policy: %s (approval scope: %s, evidence floor: %dB)'
          % (policy.name, policy.approval_scope, policy.evidence_floor))
    print(policy.description)
    print('Re-review count: %d' % result['rereview_count'])
    print('-' * 72)
    for item in result['rereview']:
        labels = '; '.join(REASON_LABELS.get(reason, reason)
                           for reason in item['reasons'])
        print('%-9s %-5s -> %-5s rule %-24s %s' % (
            item['attachment_id'],
            item['previous_format'] or '-',
            item['current_format'] or '-',
            item['current_rule_id'] or '-',
            labels,
        ))
    print('Cleared without re-sign-off: %s' % ', '.join(result['cleared']))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Compute the quarantine attachment re-review list.')
    parser.add_argument(
        '--json', action='store_true',
        help='emit both policy results as JSON instead of the text report')
    args = parser.parse_args(argv)

    if args.json:
        payload = {
            name: build_rereview_list(ATTACHMENTS, HISTORY, name)
            for name in sorted(POLICIES)
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    _print_scan_inventory()
    for name in sorted(POLICIES):
        _print_policy_report(name)


if __name__ == '__main__':
    main()
