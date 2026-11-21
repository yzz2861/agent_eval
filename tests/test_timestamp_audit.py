# coding: utf-8
"""
Tests for the offline CMS time-stamp receipt inventory (timestamp_audit).
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from timestamp_audit import build_inventory, parse_receipt_file
from timestamp_audit.cli import main as cli_main
from timestamp_audit.matching import (
    ALGORITHM_UNINTERPRETABLE,
    EXHIBIT_BYTES_MISSING,
    EXHIBIT_OK,
    MATCHED,
    NO_LOCAL_MATCH,
)
from timestamp_audit.receipts import TIMESTAMP_ATTR_TYPES

from .timestamp_audit_data import write_fixtures


class TimestampAuditTests(unittest.TestCase):
    def setUp(self):
        self.base_dir = tempfile.mkdtemp()
        self.fixtures = write_fixtures(self.base_dir)

    def tearDown(self):
        shutil.rmtree(self.base_dir, ignore_errors=True)

    def _report(self, verdicts=None):
        return build_inventory(
            self.fixtures['receipt_files'],
            self.fixtures['exhibits'],
            signature_verdicts=verdicts,
        )

    def _receipts_by_serial(self, report):
        return {
            record['serial_number']: record
            for record in report['receipts']
        }

    def test_parse_extracts_declared_algorithm_and_imprint(self):
        records, errors = parse_receipt_file(self.fixtures['receipt_files'][0])
        self.assertEqual([], errors)
        self.assertEqual(1, len(records))
        record = records[0]
        self.assertTrue(record['is_time_stamp_token'])
        self.assertEqual(
            '2.16.840.1.101.3.4.2.1', record['digest_algorithm_oid']
        )
        self.assertEqual('sha256', record['digest_algorithm_name'])
        self.assertEqual(
            self.fixtures['expected']['exhibit_a_digest_sha256_hex'],
            record['message_imprint_digest_hex'],
        )
        self.assertEqual(32, record['message_imprint_digest_length'])

    def test_pem_and_timestamp_resp_wrappers_are_accepted(self):
        pem_records, pem_errors = parse_receipt_file(self.fixtures['receipt_files'][1])
        self.assertEqual([], pem_errors)
        self.assertEqual(1, len(pem_records))

        resp_records, resp_errors = parse_receipt_file(self.fixtures['receipt_files'][3])
        self.assertEqual([], resp_errors)
        self.assertEqual(1, len(resp_records))
        bare_records, bare_errors = parse_receipt_file(self.fixtures['receipt_files'][0])
        self.assertEqual([], bare_errors)
        self.assertEqual(
            bare_records[0]['message_imprint_digest_hex'],
            resp_records[0]['message_imprint_digest_hex'],
        )
        self.assertEqual(bare_records[0]['receipt_id'], resp_records[0]['receipt_id'])
        self.assertEqual(
            self.fixtures['expected']['exhibit_b_digest_sha256_hex'],
            pem_records[0]['message_imprint_digest_hex'],
        )

    def test_nested_receipt_provenance_chain(self):
        records, errors = parse_receipt_file(self.fixtures['receipt_files'][2])
        self.assertEqual([], errors)
        self.assertEqual(2, len(records))
        outer, inner = records
        self.assertEqual(0, outer['depth'])
        self.assertEqual(1, inner['depth'])
        self.assertIn(inner['receipt_id'], outer['nested_receipt_ids'])
        self.assertEqual(outer['receipt_id'], inner['provenance_chain'][0]['parent_receipt_id'])
        self.assertEqual(
            'signature_time_stamp_token',
            inner['provenance_chain'][0]['attribute_type'],
        )
        self.assertIn(
            inner['provenance_chain'][0]['attribute_type'], TIMESTAMP_ATTR_TYPES
        )

    def test_matching_uses_local_bytes_not_displayed_time(self):
        report = self._report()
        by_serial = self._receipts_by_serial(report)

        token_a = by_serial[1001]
        token_b = by_serial[1002]
        # Same gen_time, different content: matching must still split them.
        self.assertEqual(token_a['gen_time'], token_b['gen_time'])
        self.assertEqual(MATCHED, token_a['match_status'])
        self.assertEqual(MATCHED, token_b['match_status'])
        self.assertEqual(['EX-A'], [m['exhibit_id'] for m in token_a['matched_exhibits']])
        self.assertEqual(['EX-B'], [m['exhibit_id'] for m in token_b['matched_exhibits']])

        # The nested inner receipt protects EX-C bytes.
        inner = by_serial[2001]
        self.assertEqual(MATCHED, inner['match_status'])
        self.assertEqual(['EX-C'], [m['exhibit_id'] for m in inner['matched_exhibits']])

    def test_same_gen_time_group_does_not_imply_identity(self):
        report = self._report()
        groups = report['same_gen_time_groups']
        self.assertTrue(groups)
        group = groups[0]
        self.assertEqual(self.fixtures['expected']['gen_time'], group['gen_time'])
        # Distinct imprint keys prove the equally-timed pages differ.
        self.assertGreater(len(group['imprint_keys']), 1)

    def test_missing_bytes_marked_separately_and_listed_without_receipt(self):
        report = self._report()
        missing = next(
            exhibit for exhibit in report['exhibits']
            if exhibit['exhibit_id'] == 'EX-MISSING'
        )
        self.assertEqual(EXHIBIT_BYTES_MISSING, missing['status'])
        self.assertIsNone(missing['bytes_sha256'])

        without_receipt = {
            item['exhibit_id']: item for item in report['exhibits_without_receipt']
        }
        self.assertIn('EX-MISSING', without_receipt)
        self.assertEqual(EXHIBIT_BYTES_MISSING, without_receipt['EX-MISSING']['status'])

    def test_uninterpretable_algorithm_is_distinct_status(self):
        report = self._report()
        by_serial = self._receipts_by_serial(report)
        unknown = by_serial[3001]
        self.assertEqual(ALGORITHM_UNINTERPRETABLE, unknown['match_status'])
        self.assertFalse(unknown['algorithm_interpretable'])
        self.assertIsNone(unknown['hashlib_name'])
        self.assertEqual(
            self.fixtures['expected']['unknown_algorithm_oid'],
            unknown['digest_algorithm_oid'],
        )
        # The imprint bytes themselves remain recorded for manual review.
        self.assertEqual(32, unknown['message_imprint_digest_length'])

    def test_unmatched_receipt_status(self):
        # The outer nested receipt timestamps a placeholder signature that no
        # exhibit contains, so it must be reported as no_local_match rather
        # than silently associated with an exhibit.
        report = self._report()
        by_serial = self._receipts_by_serial(report)
        outer = by_serial[2002]
        self.assertEqual(NO_LOCAL_MATCH, outer['match_status'])
        self.assertEqual([], outer['matched_exhibits'])

    def test_signature_verdict_is_caller_supplied(self):
        report = self._report()
        target_id = report['receipts'][0]['receipt_id']
        self.assertEqual('unprovided', report['receipts'][0]['signature_verdict'])

        report = self._report({
            target_id: {'verdict': 'valid', 'note': 'verified against TSA chain'},
            'deadbeef' * 8: {'verdict': 'valid'},
        })
        record = next(r for r in report['receipts'] if r['receipt_id'] == target_id)
        self.assertEqual('valid', record['signature_verdict'])
        self.assertEqual('verified against TSA chain', record['signature_verdict_note'])
        self.assertIn('deadbeef' * 8, report['verdict_warnings']['unresolved_keys'])

    def test_receipt_id_is_sha256_of_token_der(self):
        report = self._report()
        expected = hashlib.sha256(self.fixtures['token_a_der']).hexdigest()
        record = self._receipts_by_serial(report)[1001]
        self.assertEqual(expected, record['receipt_id'])
        self.assertEqual(expected, record['token_der_sha256'])

    def test_parse_error_is_reported_not_raised(self):
        report = self._report()
        self.assertEqual(1, len(report['parse_errors']))
        self.assertEqual('unparseable_container', report['parse_errors'][0]['error'])
        self.assertTrue(report['parse_errors'][0]['origin_path'].endswith('broken.tsr'))

    def test_report_is_json_serialisable_and_complete(self):
        report = self._report()
        encoded = json.dumps(report)
        decoded = json.loads(encoded)
        self.assertEqual(report['summary'], decoded['summary'])
        self.assertEqual(
            report['summary']['exhibits_without_receipt_total'],
            len(report['exhibits_without_receipt']),
        )
        self.assertEqual(EXHIBIT_OK, decoded['exhibits'][0]['status'])

    def test_cli_json_and_manifest_flow(self):
        manifest_path = os.path.join(self.base_dir, 'manifest.json')
        output_path = os.path.join(self.base_dir, 'report.json')
        verdict_target = hashlib.sha256(self.fixtures['token_a_der']).hexdigest()
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump({
                'receipt_files': self.fixtures['receipt_files'],
                'exhibits': [
                    {'exhibit_id': exhibit_id, 'path': path}
                    for exhibit_id, path in self.fixtures['exhibits']
                ],
                'signature_verdicts': {
                    verdict_target: {'verdict': 'valid'},
                },
            }, f)

        exit_code = cli_main([
            'audit', '--manifest', manifest_path,
            '--output', output_path, '--json-only',
        ])
        # Exit code 1 because the scenario intentionally contains parse errors,
        # missing bytes and an unexplained algorithm.
        self.assertEqual(1, exit_code)
        with open(output_path, 'rb') as f:
            on_disk = json.loads(f.read().decode('utf-8'))
        self.assertEqual(
            1, on_disk['summary']['exhibits_missing_bytes_total']
        )
        record = next(
            receipt for receipt in on_disk['receipts']
            if receipt['receipt_id'] == verdict_target
        )
        self.assertEqual('valid', record['signature_verdict'])


if __name__ == '__main__':
    unittest.main()
