# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import json
import os
import unittest

from asn1crypto import pkcs12

from ._synthetic_pkcs12 import build_synthetic_directory


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class PKCS12DirectoryTests(unittest.TestCase):

    def _report(self):
        package, registry, certificate_a, certificate_b, certificate_c = build_synthetic_directory()
        return (
            pkcs12.directory(package, registry),
            registry,
            certificate_a,
            certificate_b,
            certificate_c,
        )

    def test_independent_sections(self):
        report, registry, certificate_a, certificate_b, certificate_c = self._report()

        self.assertEqual(2, len(report['resolved']))
        self.assertEqual(2, len(report['conflicts']))
        self.assertEqual(2, len(report['not_visible']))
        self.assertEqual(0, len(report['unmatched']))

        self.assertEqual(report['resolved'], report['claimed'])
        self.assertEqual(report['not_visible'], report['placeholders'])
        self.assertEqual(report['conflicts'], report['ambiguous'])

    def test_two_same_name_entries_only_one_claim(self):
        report, registry, certificate_a, certificate_b, certificate_c = self._report()

        shared = None
        for group in report['conflicts']:
            if group['name'] == 'Shared Legacy':
                shared = group
                break
        self.assertIsNotNone(shared)
        self.assertEqual(2, shared['entry_count'])
        self.assertEqual(1, len(shared['claimable']))
        self.assertEqual(1, len(shared['unclaimed']))
        self.assertEqual(
            'auth_safe.authenticated_safe[0].safe_contents[0]',
            shared['claimable'][0]['path_text']
        )
        self.assertEqual(
            'auth_safe.authenticated_safe[0].safe_contents[1]',
            shared['unclaimed'][0]['path_text']
        )

        claimed_basis = shared['claimable'][0]['claim']['basis']
        self.assertEqual('sha256', claimed_basis)
        self.assertIn('only', shared['explanation'])
        self.assertIn('sha256', shared['explanation'])
        self.assertIn('not unique', shared['explanation'])

    def test_placeholder_bags_preserve_hierarchy(self):
        report, registry, certificate_a, certificate_b, certificate_c = self._report()

        placeholder_paths = [entry['path'] for entry in report['not_visible']]
        self.assertIn(
            ('auth_safe', 'authenticated_safe', 0, 'safe_contents', 3),
            placeholder_paths
        )
        self.assertIn(
            ('auth_safe', 'authenticated_safe', 1, 'encrypted_data'),
            placeholder_paths
        )

        key_bag = report['not_visible'][0]
        self.assertEqual('private_key', key_bag['kind'])
        self.assertTrue(key_bag['placeholder'])
        self.assertFalse(key_bag['material_visible'])
        self.assertTrue(key_bag['redacted'])
        self.assertEqual('Visible Only', key_bag['friendly_name'])
        self.assertEqual(
            1,
            key_bag['container']['safe_contents_depth']
        )
        self.assertEqual(3, key_bag['container']['bag_index'])
        self.assertEqual([0, 3], key_bag['index_path'])
        self.assertTrue(key_bag['binding']['placeholder'])
        self.assertFalse(key_bag['binding']['material_visible'])

    def test_report_does_not_contain_private_material(self):
        report, registry, certificate_a, certificate_b, certificate_c = self._report()
        report_text = json.dumps(report.to_dict())
        self.assertNotIn('SYNTHETIC-PLACEHOLDER-NOT-A-PRIVATE-KEY', report_text)
        self.assertNotIn('SYNTHETIC-ENCRYPTED-SAFE-PLACEHOLDER', report_text)

        for entry in report['not_visible']:
            if entry['kind'] == 'private_key':
                self.assertIsNone(entry['certificate'])
                self.assertNotIn('private_key', entry)
                self.assertNotIn('encrypted_data', entry)
                self.assertNotIn('bag_value', entry)

    def test_name_only_registration_claims_unique_visible_certificate(self):
        report, registry, certificate_a, certificate_b, certificate_c = self._report()

        visible = None
        for entry in report['resolved']:
            if entry['friendly_name'] == 'Visible Only':
                visible = entry
                break
        self.assertIsNotNone(visible)
        self.assertEqual('friendly_name', visible['claim']['basis'])
        self.assertEqual('REG-002', visible['claim']['record_id'])

        visible_group = None
        for group in report['conflicts']:
            if group['name'] == 'Visible Only':
                visible_group = group
                break
        self.assertIsNotNone(visible_group)
        self.assertIn('Placeholder entries have no readable certificate material', visible_group['explanation'])

    def test_review_table_explains_duplicate_name(self):
        report, registry, certificate_a, certificate_b, certificate_c = self._report()
        table = report.format_review_table()
        self.assertIn('Shared Legacy', table)
        self.assertIn('REG-001', table)
        self.assertIn('Placeholder', table)
        self.assertIn('only', table)
        self.assertIn('not unique', table)

        rows = report.review_table()
        conflict_rows = [row for row in rows if row['section'] == 'conflict']
        self.assertEqual(1, len([row for row in conflict_rows if row['friendly_name'] == 'Shared Legacy']))

    def test_registry_forms_and_pfx_object(self):
        package, registry, certificate_a, certificate_b, certificate_c = build_synthetic_directory()
        loaded = pkcs12.Pfx.load(package)

        by_object = pkcs12.directory(loaded, registry)
        by_method = loaded.directory(registry)
        by_mapping = pkcs12.directory(package, {
            'Shared Legacy': {'record_id': 'REG-001', 'sha256': certificate_a.sha256},
            'Visible Only': {'record_id': 'REG-002'},
        })
        self.assertEqual(2, len(by_object['resolved']))
        self.assertEqual(2, len(by_method['resolved']))
        self.assertEqual(2, len(by_mapping['resolved']))
        self.assertEqual(
            by_object['resolved'][0]['claim']['record_id'],
            by_mapping['resolved'][0]['claim']['record_id']
        )

    def test_fixture_contains_only_synthetic_certs_and_placeholders(self):
        fixture_path = os.path.join(fixtures_dir, 'synthetic-directory.p12')
        self.assertTrue(os.path.exists(fixture_path))
        with open(fixture_path, 'rb') as handle:
            report = pkcs12.directory(handle.read(), [
                {'friendly_name': 'Shared Legacy'},
                {'friendly_name': 'Visible Only'},
            ])
        certificates = [
            entry for entry in report['catalog']
            if entry['kind'] == 'certificate'
        ]
        self.assertEqual(3, len(certificates))
        for entry in certificates:
            self.assertEqual(
                'Synthetic Archive',
                entry['certificate']['subject']['native']['organization_name']
            )
            self.assertFalse(entry['placeholder'])
        bag_ids = [entry['bag_id'] for entry in report['catalog']]
        self.assertNotIn('key_bag', bag_ids)
        self.assertIn('pkcs8_shrouded_key_bag', bag_ids)
        self.assertIn('encrypted_data', bag_ids)

    def test_synthetic_fixture_file_if_present(self):
        fixture_path = os.path.join(fixtures_dir, 'synthetic-directory.p12')
        if not os.path.exists(fixture_path):
            return
        with open(fixture_path, 'rb') as handle:
            package = handle.read()
        report = pkcs12.directory(package, [
            {
                'record_id': 'REG-001',
                'friendly_name': 'Shared Legacy',
                'sha256': '6aff31adcd9203230f39f377d3e0b37e3f7dd32276a05c1192b6d49495609e1b',
            },
            {'record_id': 'REG-002', 'friendly_name': 'Visible Only'},
        ])
        self.assertEqual(2, len(report['resolved']))
        self.assertIn('Shared Legacy', report.format_review_table())
