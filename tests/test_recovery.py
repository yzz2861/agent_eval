#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
from __future__ import print_function

import json
import os
import unittest

import jks
from jks import recovery


CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, "keystores", "jks")


def merged_entries():
    key_store = jks.KeyStore.load(os.path.join(KS_PATH, "RSA2048_3certs.jks"),
                                  "12345678", try_decrypt_keys=False)
    cert_store = jks.KeyStore.load(os.path.join(KS_PATH, "3certs.jks"),
                                   "12345678", try_decrypt_keys=False)
    entries = dict(key_store.entries)
    entries.update(cert_store.entries)
    return entries


class RecoveryCheckTests(unittest.TestCase):
    def setUp(self):
        self.entries = merged_entries()
        self.private = self.entries["mykey"]
        self.leaf = self.private.cert_chain[0][1]
        self.intermediate = self.private.cert_chain[1][1]

    def test_private_key_with_chain_supports_server_recovery(self):
        report = recovery.check_recovery(
            self.entries, "tls_server",
            [jks.PrivateKeyEntry, jks.TrustedCertEntry], self.leaf)
        self.assertTrue(report.ok)
        self.assertEqual(report.selected_alias, "mykey")
        self.assertEqual(report.missing_capabilities, [])
        self.assertEqual(report.matches[0].entry, self.private)
        self.assertEqual(report.matches[0].match_basis, "certificate_leaf")

    def test_complete_chain_alone_does_not_satisfy_private_key_purpose(self):
        report = recovery.check_recovery(
            self.entries, "tls_server", [jks.TrustedCertEntry], self.leaf)
        self.assertFalse(report.ok)
        self.assertIn("private_key", report.missing_capabilities)
        self.assertIn("certificate_chain_without_private_key", report.warnings)
        self.assertEqual(report.matches[0].category, recovery.TRUSTED_CERT)

    def test_alternatives_are_ordered_by_value_and_match_strength(self):
        report = recovery.check_recovery(
            self.entries, "tls_server",
            [jks.PrivateKeyEntry, jks.TrustedCertEntry], self.leaf)
        self.assertEqual(report.precedence[:2], ["mykey", "cert1"])
        self.assertEqual([m.priority for m in report.matches[:2]], [1, 2])

        report = recovery.check_recovery(
            self.entries, "trust_anchor",
            [jks.PrivateKeyEntry, jks.TrustedCertEntry], self.leaf)
        self.assertEqual(report.precedence[:2], ["cert1", "mykey"])
        self.assertTrue(report.ok)

    def test_intermediate_certificate_matches_chain(self):
        report = recovery.check_recovery(
            self.entries, "tls_server",
            [jks.PrivateKeyEntry, jks.TrustedCertEntry], self.intermediate)
        self.assertTrue(report.ok)
        self.assertEqual(report.matches[0].alias, "mykey")
        self.assertEqual(report.matches[0].match_basis, "certificate_chain")

    def test_fingerprint_material_and_alias_mapping(self):
        import hashlib
        fingerprint = hashlib.sha256(self.leaf).hexdigest()
        report = recovery.check_recovery(
            {"unexpected-name": self.private}, "tls_server",
            [jks.PrivateKeyEntry], {"fingerprint": fingerprint})
        self.assertTrue(report.ok)
        self.assertEqual(report.matches[0].alias, "unexpected-name")

        report = recovery.check_recovery(
            self.entries, "tls_server",
            [jks.PrivateKeyEntry], {"mykey": {"cert": self.leaf}})
        self.assertTrue(report.ok)
        self.assertEqual(report.matches[0].alias, "mykey")

    def test_role_views_report_missing_capabilities_without_secrets(self):
        report = recovery.check_recovery(
            self.entries, "tls_server", [jks.TrustedCertEntry], self.leaf)
        self.assertFalse(report.ok)
        for role in ("recovery", "security", "operator", "auditor"):
            view = report.for_role(role)
            self.assertFalse(view.ok)
            self.assertIn("private_key", view.missing_capabilities)
            self.assertTrue(view.focus_missing_capabilities or
                            view.missing_capabilities)
            self.assertTrue(any(a["capability"] == "private_key"
                                for a in view.actions))

        payload = json.dumps(report.to_dict())
        self.assertNotIn("pkey", payload)
        self.assertNotIn("private_key_material\": \"", payload)
        self.assertFalse(report.contains_password)
        self.assertFalse(report.contains_private_key_material)

    def test_custom_purpose_and_allowed_category_classes(self):
        report = jks.check_recovery(
            self.entries,
            {"name": "server", "requires": ["private_key", "certificate_chain"]},
            [jks.PrivateKeyEntry], self.leaf)
        self.assertTrue(report.ok)

        report = recovery.check_recovery(
            self.entries,
            {"name": "key-only", "requires": "private_key"},
            [jks.TrustedCertEntry], self.leaf)
        self.assertFalse(report.ok)
        self.assertIn("private_key", report.missing_capabilities)

    def test_public_key_and_pem_material(self):
        from jks.util import as_pem
        pem = as_pem(self.leaf, "CERTIFICATE")
        report = recovery.check_recovery(
            self.entries, "tls_server",
            [jks.PrivateKeyEntry], pem)
        self.assertTrue(report.ok)
        self.assertEqual(report.selected_alias, "mykey")


if __name__ == "__main__":
    unittest.main()
