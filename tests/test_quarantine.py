# -*- coding: utf-8 -*-

from __future__ import absolute_import

import glob
import os
import struct
import unittest

import filetype

from quarantine.data import ATTACHMENTS, HISTORY
from quarantine.engine import scan_buffer, scan_path
from quarantine.policy import (
    EVIDENCE_INSUFFICIENT,
    FORMAT_CHANGED,
    NOT_ALLOWED,
    RULE_CHANGED,
    RULE_RETIRED,
    build_rereview_list,
)
from quarantine.rules import RULES, find_rule, rules_for_format


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'fixtures')


class RuleRegistryTests(unittest.TestCase):
    def test_registry_order_follows_filetype_types(self):
        import itertools
        from filetype.types import TYPES

        compressed = [key for key, _ in itertools.groupby(
            rule.extension for rule in RULES)]
        self.assertEqual(compressed, [matcher.extension for matcher in TYPES])

    def test_rule_ids_are_unique(self):
        ids = [rule.rule_id for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_multi_rule_formats_are_split(self):
        self.assertEqual(
            [rule.rule_id for rule in rules_for_format('zst')],
            ['zst.frame', 'zst.skippable'],
        )
        self.assertEqual(len(rules_for_format('doc')), 3)
        self.assertEqual(
            [rule.rule_id for rule in rules_for_format('dcm')],
            ['dcm.image-group', 'dcm.archive-group'],
        )

    def test_retired_rule_id_is_unknown(self):
        self.assertIsNone(find_rule('tar.legacy-ustar'))
        self.assertIsNotNone(find_rule('tar'))


class MatchingOrderTests(unittest.TestCase):
    def test_engine_matches_filetype_on_every_fixture(self):
        for path in sorted(glob.glob(os.path.join(FIXTURES, 'sample*'))):
            scan = scan_path(os.path.basename(path), path)
            kind = filetype.guess(path)
            self.assertEqual(scan.format, kind.extension)
            self.assertEqual(scan.mime, kind.mime)

    def test_first_matching_rule_wins_and_alternatives_are_recorded(self):
        scan = scan_path('docx', os.path.join(FIXTURES, 'sample.docx'))
        self.assertEqual(scan.rule_id, 'docx')
        self.assertIn('zip.local-header',
                      [rule.rule_id for rule in scan.matching_rules])

    def test_docx_falls_back_to_zip_when_document_evidence_is_truncated(self):
        with open(os.path.join(FIXTURES, 'sample.docx'), 'rb') as fp:
            header = fp.read(512)
        scan = scan_buffer('docx-partial', header)
        self.assertEqual(scan.format, 'zip')
        self.assertEqual(scan.rule_id, 'zip.local-header')

    def test_three_doc_variants_hit_different_rules(self):
        expected = {
            'sample.doc': 'doc.worddoc-stream',
            'sample_1.doc': 'doc.root-entry',
            'sample_2.doc': 'doc.root-entry-name',
        }
        for name, rule_id in expected.items():
            scan = scan_path(name, os.path.join(FIXTURES, name))
            self.assertEqual(scan.rule_id, rule_id)


class ZstdRuleTests(unittest.TestCase):
    def _skippable_only_header(self):
        with open(os.path.join(FIXTURES, 'sample.zst'), 'rb') as fp:
            regular_frame = fp.read(8)
        payload = b'USERDATA'
        return (struct.pack('<II', 0x184D2A50, len(payload))
                + payload + regular_frame)

    def test_regular_frame_matches_frame_rule_only(self):
        with open(os.path.join(FIXTURES, 'sample.zst'), 'rb') as fp:
            scan = scan_buffer('zst', fp.read(8))
        self.assertEqual(scan.rule_id, 'zst.frame')
        self.assertEqual(
            [rule.rule_id for rule in scan.matching_rules],
            ['zst.frame'],
        )

    def test_skippable_header_matches_skippable_rule_only(self):
        scan = scan_buffer('zst', self._skippable_only_header())
        self.assertEqual(scan.rule_id, 'zst.skippable')
        self.assertEqual(
            [rule.rule_id for rule in scan.matching_rules],
            ['zst.skippable'],
        )
        self.assertTrue(scan.sufficient)

    def test_skippable_frame_needs_full_evidence(self):
        truncated = self._skippable_only_header()[:12]
        scan = scan_buffer('zst', truncated)
        self.assertIsNone(scan.format)
        self.assertFalse(scan.sufficient)


class EvidenceTests(unittest.TestCase):
    def test_matcher_can_fire_below_gateway_evidence_floor(self):
        with open(os.path.join(FIXTURES, 'sample.jpg'), 'rb') as fp:
            three_bytes = fp.read(3)
        self.assertEqual(filetype.guess(three_bytes).extension, 'jpg')
        scan = scan_buffer('jpg', three_bytes)
        self.assertEqual(scan.rule_id, 'jpg')
        self.assertEqual(scan.header_length, 3)

    def test_truncated_unknown_header_is_unrecognized(self):
        scan = scan_buffer('unknown', b'\x00' * 16)
        self.assertIsNone(scan.format)
        self.assertFalse(scan.sufficient)


class PolicyTests(unittest.TestCase):
    def _reasons(self, result, attachment_id):
        for item in result['rereview']:
            if item['attachment_id'] == attachment_id:
                return item['reasons']
        return []

    def test_acceptance_same_format_name_requires_signoff_under_rule_scope(self):
        legacy = build_rereview_list(ATTACHMENTS, HISTORY, 'legacy-rule')
        format_level = build_rereview_list(
            ATTACHMENTS, HISTORY, 'format-level')

        self.assertIn(RULE_CHANGED, self._reasons(legacy, 'ATT-002'))
        self.assertEqual([], self._reasons(format_level, 'ATT-002'))
        self.assertIn('ATT-002', format_level['cleared'])

        item = next(row for row in legacy['rereview']
                    if row['attachment_id'] == 'ATT-002')
        self.assertEqual(item['previous_format'], 'zst')
        self.assertEqual(item['current_format'], 'zst')
        self.assertEqual(item['current_rule_id'], 'zst.skippable')
        self.assertEqual(item['previous_rule_id'], 'zst.frame')

    def test_rule_change_inside_same_format_family_is_detected(self):
        legacy = build_rereview_list(ATTACHMENTS, HISTORY, 'legacy-rule')
        self.assertIn(RULE_CHANGED, self._reasons(legacy, 'ATT-003'))
        format_level = build_rereview_list(
            ATTACHMENTS, HISTORY, 'format-level')
        self.assertEqual([], self._reasons(format_level, 'ATT-003'))

    def test_evidence_floor_applies_under_both_policies(self):
        for policy_name in ('legacy-rule', 'format-level'):
            result = build_rereview_list(
                ATTACHMENTS, HISTORY, policy_name)
            self.assertIn(EVIDENCE_INSUFFICIENT,
                          self._reasons(result, 'ATT-006'))

    def test_format_change_is_required_under_both_policies(self):
        for policy_name in ('legacy-rule', 'format-level'):
            result = build_rereview_list(
                ATTACHMENTS, HISTORY, policy_name)
            self.assertIn(FORMAT_CHANGED,
                          self._reasons(result, 'ATT-007'))

    def test_allowlist_difference_only_affects_legacy_policy(self):
        legacy = build_rereview_list(ATTACHMENTS, HISTORY, 'legacy-rule')
        format_level = build_rereview_list(
            ATTACHMENTS, HISTORY, 'format-level')
        self.assertIn(NOT_ALLOWED, self._reasons(legacy, 'ATT-008'))
        self.assertEqual([], self._reasons(format_level, 'ATT-008'))

    def test_retired_rule_is_reviewed_under_rule_scope_only(self):
        legacy = build_rereview_list(ATTACHMENTS, HISTORY, 'legacy-rule')
        format_level = build_rereview_list(
            ATTACHMENTS, HISTORY, 'format-level')
        self.assertIn(RULE_RETIRED, self._reasons(legacy, 'ATT-009'))
        self.assertEqual([], self._reasons(format_level, 'ATT-009'))

    def test_overall_counts_and_stable_attachments(self):
        legacy = build_rereview_list(ATTACHMENTS, HISTORY, 'legacy-rule')
        format_level = build_rereview_list(
            ATTACHMENTS, HISTORY, 'format-level')
        self.assertEqual(legacy['rereview_count'], 6)
        self.assertEqual(format_level['rereview_count'], 2)
        for attachment_id in ('ATT-001', 'ATT-004', 'ATT-005', 'ATT-010'):
            self.assertIn(attachment_id, legacy['cleared'])
            self.assertIn(attachment_id, format_level['cleared'])


if __name__ == '__main__':
    unittest.main()
