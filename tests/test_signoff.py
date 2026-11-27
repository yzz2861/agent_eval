#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:

from __future__ import print_function

import os
import unittest

import jks
from . import expected


CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, "keystores")


class SignoffTests(unittest.TestCase):
    def setUp(self):
        self.leaf = expected.RSA2048_3certs.certs[0]
        self.intermediate = expected.RSA2048_3certs.certs[1]
        self.root = expected.RSA2048_3certs.certs[2]
        self.replacement = expected.RSA1024.certs[0]
        self.chain = [self.leaf, self.intermediate, self.root]

        self.previous_approvals = [
            self._record("old-tls", "jks/rollback.jks", 0, "tls-server", self.leaf, self.chain),
            self._record("old-client", "jks/rollback.jks", 1, "mtls-client", self.leaf, self.chain),
            self._record("old-vpn", "jks/rollback.jks", 2, "vpn", self.leaf, self.chain),
        ]

    def _record(self, entry_id, location, position, usage, leaf, chain):
        return {
            "entry_id": entry_id,
            "alias": entry_id,
            "container_location": location,
            "position": position,
            "usage": usage,
            "public_certificate": leaf,
            "certificate_chain": list(chain),
        }

    def test_same_public_certificate_can_be_reused_for_two_usages(self):
        manifest = [
            self._record("new-tls", "bks/current.bks", 3, "tls-server", self.leaf, self.chain),
            self._record("new-client", "bks/current.bks", 7, "mtls-client", self.leaf, self.chain),
        ]

        results = jks.check_signoff(manifest, self.previous_approvals)

        self.assertEqual([result.status for result in results], [
            jks.STATUS_APPROVED,
            jks.STATUS_APPROVED,
        ])
        self.assertEqual([result.entry_id for result in results], ["new-tls", "new-client"])
        self.assertEqual([result.position for result in results], [3, 7])
        self.assertTrue(all(result.container_location == "bks/current.bks" for result in results))
        self.assertTrue(all(result.differences == [] for result in results))

    def test_chain_certificate_change_requires_reapproval_with_precise_difference(self):
        changed_chain = [self.leaf, self.replacement, self.root]
        manifest = [self._record("new-vpn", "bks/current.bks", 9, "vpn", self.leaf, changed_chain)]

        result = jks.check_signoff(manifest, self.previous_approvals)[0]

        self.assertEqual(result.status, jks.STATUS_REAPPROVAL_REQUIRED)
        self.assertEqual(result.public_certificate_digest, jks.certificate_digest(self.leaf))
        self.assertEqual(len(result.differences), 1)
        difference = result.differences[0]
        self.assertEqual(difference["field"], "certificate_chain[1].certificate_digest")
        self.assertEqual(difference["index"], 1)
        self.assertEqual(difference["previous"], jks.certificate_digest(self.intermediate))
        self.assertEqual(difference["current"], jks.certificate_digest(self.replacement))

    def test_public_certificate_change_is_reported_once(self):
        changed_chain = [self.replacement, self.intermediate, self.root]
        manifest = [self._record("new-vpn", "bks/current.bks", 9, "vpn", self.replacement, changed_chain)]

        result = jks.check_signoff(manifest, self.previous_approvals)[0]

        self.assertEqual(result.status, jks.STATUS_REAPPROVAL_REQUIRED)
        self.assertEqual([difference["field"] for difference in result.differences], [
            "public_certificate_digest",
        ])

    def test_ordered_chain_change_is_reported_by_index(self):
        reordered_chain = [self.leaf, self.root, self.intermediate]
        manifest = [self._record("new-vpn", "bks/current.bks", 2, "vpn", self.leaf, reordered_chain)]

        result = jks.check_signoff(manifest, self.previous_approvals)[0]

        self.assertEqual(result.status, jks.STATUS_REAPPROVAL_REQUIRED)
        self.assertEqual([difference["index"] for difference in result.differences], [1, 2])
        self.assertEqual(result.differences[0]["previous"], jks.certificate_digest(self.intermediate))
        self.assertEqual(result.differences[0]["current"], jks.certificate_digest(self.root))

    def test_unknown_usage_requires_reapproval(self):
        manifest = [self._record("new-api", "bks/current.bks", 4, "api-auth", self.leaf, self.chain)]

        result = jks.check_signoff(manifest, self.previous_approvals)[0]

        self.assertEqual(result.status, jks.STATUS_REAPPROVAL_REQUIRED)
        self.assertEqual(result.differences, [{
            "field": "usage",
            "reason": "no_previous_approval",
            "previous": None,
            "current": "api-auth",
        }])

    def test_digest_only_records_are_checked_offline(self):
        leaf_digest = jks.certificate_digest(self.leaf)
        chain_digests = [jks.certificate_digest(certificate) for certificate in self.chain]
        previous = [{
            "entry_id": "old-tls",
            "usage": "tls-server",
            "container_location": "jks/rollback.jks",
            "position": 0,
            "public_certificate_digest": leaf_digest,
            "certificate_chain_digests": chain_digests,
        }]
        current = [{
            "entry_id": "new-tls",
            "usage": "tls-server",
            "container_location": "bks/current.bks",
            "position": 5,
            "public_certificate_digest": leaf_digest,
            "certificate_chain_digests": chain_digests,
        }]

        result = jks.check_signoff(current, previous)[0]

        self.assertEqual(result.status, jks.STATUS_APPROVED)
        self.assertEqual(result.certificate_chain, chain_digests)
        self.assertEqual(result.certificate_chain_digest, jks.chain_digest(chain_digests))

    def test_algorithm_names_are_normalized(self):
        expected_digest = jks.certificate_digest(self.leaf)

        self.assertEqual(jks.certificate_digest(self.leaf, "SHA-256"), expected_digest)
        self.assertEqual(jks.certificate_digest(self.leaf, "SHA256"), expected_digest)


class KeystoreManifestTests(unittest.TestCase):
    def test_manifest_preserves_jks_entry_identity_position_and_chain(self):
        keystore = jks.KeyStore.load(KS_PATH + "/jks/RSA2048_3certs.jks", "12345678")

        manifest = jks.manifest_from_keystore(
            keystore,
            usage_by_alias={"mykey": "tls-server"},
            container_location="jks/RSA2048_3certs.jks",
        )

        self.assertEqual(len(manifest), 1)
        record = manifest[0]
        self.assertEqual(record["entry_id"], "mykey")
        self.assertEqual(record["alias"], "mykey")
        self.assertEqual(record["position"], 0)
        self.assertEqual(record["container_location"], "jks/RSA2048_3certs.jks")
        self.assertEqual(record["store_type"], "jks")
        self.assertEqual(record["usage"], "tls-server")
        self.assertEqual(record["certificate_chain"], expected.RSA2048_3certs.certs)
        self.assertEqual(record["public_certificate"], expected.RSA2048_3certs.certs[0])

    def test_manifest_accepts_bks_entry_chain_objects(self):
        keystore = jks.bks.BksKeyStore.load(KS_PATH + "/bks/christmas.bksv2", "12345678")

        manifest = jks.manifest_from_keystore(keystore)

        private_key_index = list(keystore.entries.keys()).index("sealed_private_key")
        private_key_record = [record for record in manifest if record["alias"] == "sealed_private_key"][0]
        self.assertEqual(private_key_record["store_type"], "bks")
        self.assertEqual(private_key_record["position"], private_key_index)
        self.assertEqual(private_key_record["certificate_chain"], expected.bks_christmas.certs)
        self.assertEqual(private_key_record["public_certificate"], expected.bks_christmas.certs[0])

    def test_manifest_preserves_each_container_position(self):
        keystore = jks.KeyStore.load(KS_PATH + "/jks/3certs.jks", "12345678")

        manifest = jks.manifest_from_keystore(keystore)

        positions = dict((record["alias"], record["position"]) for record in manifest)
        self.assertEqual(positions, dict((alias, index) for index, alias in enumerate(keystore.entries.keys())))


if __name__ == "__main__":
    unittest.main()
