#!/usr/bin/env python
from __future__ import print_function

import hashlib
import json
import os
import unittest

import jks
from jks import truststore


CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, 'keystores')


def load_certs():
    source = jks.KeyStore.load(os.path.join(KS_PATH, 'jks', '3certs.jks'), '12345678')
    return source.entries['cert1'].cert, source.entries['cert2'].cert


def make_store(items):
    entries = []
    for alias, der in items:
        entries.append(jks.TrustedCertEntry.new(alias, der))
    return jks.KeyStore.new('jks', entries)


def fingerprint(der, algorithm='sha256'):
    return hashlib.new(algorithm, der).hexdigest().lower()


class PurposePlanTests(unittest.TestCase):
    def setUp(self):
        self.cert_a, self.cert_b = load_certs()

    def test_same_certificate_is_justified_separately_for_each_purpose(self):
        store = make_store([
            ('issuance-test', self.cert_a),
            ('history-test', self.cert_a),
            ('unapproved-copy', self.cert_a),
        ])
        plan = truststore.plan_truststores(store, [
            {'alias': 'issuance-test', 'purpose': 'issuance_review'},
            {'alias': 'history-test', 'purpose': 'historical_verification'},
        ])
        self.assertTrue(plan.ok)
        issuance = plan.manifests['issuance_review']
        history = plan.manifests['historical_verification']
        self.assertEqual(len(issuance), 1)
        self.assertEqual(len(history), 1)
        self.assertEqual(issuance.entries[0].source_alias, 'issuance-test')
        self.assertEqual(history.entries[0].source_alias, 'history-test')
        self.assertEqual(issuance.entries[0].fingerprint,
                         history.entries[0].fingerprint)
        self.assertIn('issuance-test', issuance.entries[0].reason)
        self.assertIn('history-test', history.entries[0].reason)
        self.assertIn('does not inherit', issuance.entries[0].reason)
        self.assertIn('does not inherit', history.entries[0].reason)
        self.assertEqual(len(plan.review.shared_certificates), 1)
        self.assertNotIn('unapproved-copy', issuance.source_aliases)
        self.assertNotIn('unapproved-copy', history.source_aliases)
        self.assertTrue(issuance.verify(store).ok)
        self.assertTrue(history.verify(store).ok)

    def test_denied_alias_does_not_gain_approval_from_another_alias(self):
        store = make_store([
            ('issuance-test', self.cert_a),
            ('history-test', self.cert_a),
        ])
        plan = truststore.plan_truststores(store, [
            {'alias': 'issuance-test', 'purpose': 'issuance_review'},
            {'alias': 'history-test', 'purpose': 'historical_verification',
             'approved': False},
        ])
        self.assertTrue(plan.ok)
        self.assertEqual(plan.manifests['issuance_review'].source_aliases,
                         ['issuance-test'])
        self.assertEqual(plan.manifests['historical_verification'].source_aliases, [])
        self.assertEqual(len(plan.review.rejected), 1)
        self.assertIn('not approved', plan.review.rejected[0].reason)

    def test_one_alias_can_be_approved_for_both_purposes(self):
        store = make_store([('both', self.cert_a)])
        plan = truststore.plan_truststores(store, {
            'issuance_review': ['both'],
            'historical_verification': ['both'],
        })
        self.assertTrue(plan.ok)
        for purpose in ('issuance_review', 'historical_verification'):
            self.assertEqual(plan.manifests[purpose].source_aliases, ['both'])
            self.assertIn('both', plan.manifests[purpose].entries[0].reason)

    def test_duplicate_certificate_is_kept_once_per_purpose(self):
        store = make_store([('copy-b', self.cert_a), ('copy-a', self.cert_a)])
        plan = truststore.plan_truststores(store, {
            'issuance_review': ['copy-a', 'copy-b'],
        })
        manifest = plan.manifests['issuance_review']
        self.assertEqual(len(manifest), 1)
        self.assertEqual(manifest.entries[0].source_aliases,
                         ['copy-a', 'copy-b'])
        self.assertEqual(len(plan.review.deduplicated), 1)
        self.assertFalse(plan.review.deduplicated[0].selected)

    def test_missing_alias_is_a_conflict(self):
        store = make_store([('present', self.cert_a)])
        plan = truststore.plan_truststores(store, {'issuance_review': ['missing']})
        self.assertFalse(plan.ok)
        self.assertEqual(plan.conflicts[0].code, 'missing_source_alias')
        self.assertEqual(len(plan.manifests['issuance_review']), 0)

    def test_fingerprint_mismatch_is_a_conflict(self):
        store = make_store([('cert', self.cert_a)])
        plan = truststore.plan_truststores(store, [{
            'alias': 'cert',
            'purpose': 'issuance_review',
            'fingerprint': '00' * 32,
        }])
        self.assertFalse(plan.ok)
        self.assertEqual(plan.conflicts[0].code, 'fingerprint_mismatch')

    def test_sha1_declaration_is_accepted(self):
        store = make_store([('cert', self.cert_a)])
        plan = truststore.plan_truststores(store, [{
            'alias': 'cert',
            'purpose': 'issuance_review',
            'fingerprint': fingerprint(self.cert_a, 'sha1'),
        }])
        self.assertTrue(plan.ok)
        entry = plan.manifests['issuance_review'].entries[0]
        self.assertEqual(entry.fingerprint_algorithm, 'sha1')
        self.assertEqual(entry.fingerprint, fingerprint(self.cert_a, 'sha1'))
        self.assertTrue(plan.manifests['issuance_review'].verify(store).ok)

    def test_conflicts_are_reported(self):
        store = make_store([('a', self.cert_a), ('b', self.cert_b)])
        duplicate = truststore.plan_truststores(store, {'issuance_review': ['a', 'a']})
        self.assertEqual(duplicate.conflicts[0].code, 'duplicate_declaration')
        destination = truststore.plan_truststores(store, [
            {'alias': 'a', 'purpose': 'issuance_review', 'destination_alias': 'x'},
            {'alias': 'b', 'purpose': 'issuance_review', 'destination_alias': 'x'},
        ])
        self.assertEqual(destination.conflicts[0].code, 'destination_alias_conflict')
        denied = truststore.plan_truststores(store, [
            {'alias': 'a', 'purpose': 'issuance_review'},
            {'alias': 'a', 'purpose': 'issuance_review', 'approved': False},
        ])
        self.assertEqual(denied.conflicts[0].code, 'conflicting_approval')

    def test_source_mismatch_is_a_conflict(self):
        store = make_store([('a', self.cert_a)])
        plan = truststore.plan_truststores(store, [{
            'alias': 'a',
            'purpose': 'issuance_review',
            'source': 'another-intake.jks',
        }], store_name='intake.jks')
        self.assertFalse(plan.ok)
        self.assertEqual(plan.conflicts[0].code, 'source_mismatch')

    def test_manifest_json_roundtrip_detects_tampering(self):
        store = make_store([('a', self.cert_a)])
        plan = truststore.plan_truststores(store, {'issuance_review': ['a']})
        manifest = plan.manifests['issuance_review']
        restored = truststore.TruststoreManifest.from_json(manifest.to_json())
        self.assertTrue(restored.verify(store).ok)
        self.assertEqual(restored.sha256, manifest.sha256)
        data = json.loads(manifest.to_json())
        data['entries'][0]['reason'] = 'tampered'
        tampered = truststore.TruststoreManifest.from_dict(data)
        self.assertFalse(tampered.verify(store).ok)

    def test_manifest_detects_source_drift(self):
        store = make_store([('a', self.cert_a)])
        plan = truststore.plan_truststores(store, {'issuance_review': ['a']})
        manifest = plan.manifests['issuance_review']
        self.assertTrue(manifest.verify(store).ok)
        changed = make_store([('a', self.cert_b)])
        self.assertFalse(manifest.verify(changed).ok)

    def test_delivery_plan_json_roundtrip(self):
        store = make_store([('a', self.cert_a), ('b', self.cert_b)])
        declarations = {
            'issuance_review': ['a'],
            'historical_verification': ['b'],
        }
        plan = truststore.plan_truststores(store, declarations)
        restored = truststore.DeliveryPlan.from_json(plan.to_json())
        self.assertTrue(restored.ok)
        self.assertTrue(restored.verify(store, declarations).ok)
        self.assertEqual(restored.manifests['issuance_review'].sha256,
                         plan.manifests['issuance_review'].sha256)

    def test_planning_is_read_only(self):
        store = make_store([('a', self.cert_a), ('b', self.cert_b)])
        before = [(alias, entry.cert) for alias, entry in sorted(store.entries.items())]
        truststore.build_delivery_plan(store, {
            'issuance_review': ['a'],
            'historical_verification': ['b'],
        })
        after = [(alias, entry.cert) for alias, entry in sorted(store.entries.items())]
        self.assertEqual(before, after)

    def test_derived_truststore_contains_only_certificates(self):
        key_store = jks.KeyStore.load(
            os.path.join(KS_PATH, 'jks', 'RSA2048_3certs.jks'), '12345678')
        private_entry = key_store.entries['mykey']
        store = jks.KeyStore.new('jks', [
            private_entry,
            jks.TrustedCertEntry.new('trusted', self.cert_b),
        ])
        plan = truststore.plan_truststores(store, {
            'issuance_review': ['mykey', 'trusted'],
        })
        self.assertTrue(plan.ok)
        truststore_view = plan.build_truststore('issuance_review')
        self.assertEqual(sorted(truststore_view.entries), ['mykey', 'trusted'])
        for entry in truststore_view.entries.values():
            self.assertIsInstance(entry, jks.TrustedCertEntry)
        self.assertTrue(plan.manifests['issuance_review'].verify(store).ok)

    def test_secret_key_without_certificate_is_rejected(self):
        secret = jks.SecretKeyEntry(alias='secret', sealed_obj='not-a-cert')
        store = jks.KeyStore.new('jceks', [secret])
        plan = truststore.plan_truststores(store, {'issuance_review': ['secret']})
        self.assertFalse(plan.ok)
        self.assertEqual(plan.conflicts[0].code, 'missing_certificate')

    def test_verify_rejects_alias_not_approved_for_that_purpose(self):
        store = make_store([('a', self.cert_a)])
        plan = truststore.plan_truststores(store, {
            'issuance_review': ['a'],
            'historical_verification': ['a'],
        })
        manifest = plan.manifests['historical_verification']
        result = manifest.verify(store, {'issuance_review': ['a']})
        self.assertFalse(result.ok)
        self.assertIn('not approved', result.problems[0])


    def test_declaration_maps_source_alias_to_destination_alias(self):
        store = make_store([('source-a', self.cert_a)])
        plan = truststore.plan_truststores(store, [{
            'alias': 'dest-a',
            'source_alias': 'source-a',
            'purpose': 'issuance_review',
        }])
        self.assertTrue(plan.ok)
        entry = plan.manifests['issuance_review'].entries[0]
        self.assertEqual(entry.alias, 'dest-a')
        self.assertEqual(entry.source_alias, 'source-a')
        self.assertIn('dest-a', plan.build_truststore('issuance_review').entries)

    def test_approval_policy_builder(self):
        store = make_store([('a', self.cert_a)])
        policy = truststore.ApprovalPolicy()
        policy.approve('a', 'issuance_review')
        policy.deny('a', 'historical_verification')
        plan = truststore.plan_truststores(store, policy)
        self.assertTrue(plan.ok)
        self.assertEqual(plan.manifests['issuance_review'].source_aliases, ['a'])
        self.assertEqual(plan.manifests['historical_verification'].source_aliases, [])

    def test_default_plan_contains_both_delivery_purposes(self):
        store = make_store([('a', self.cert_a)])
        plan = truststore.plan_truststores(store, {'issuance_review': ['a']})
        self.assertEqual(sorted(plan.purposes),
                         ['historical_verification', 'issuance_review'])
        self.assertEqual(len(plan.manifests['historical_verification']), 0)


if __name__ == '__main__':
    unittest.main()
