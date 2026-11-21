#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:

from __future__ import print_function

import json
import os
import unittest

import jks
try:
    from . import expected
except ImportError:
    import expected


PASSWORD = "store-password"


def make_store(entries, password=PASSWORD):
    return jks.KeyStore.new("jks", entries).saves(password)


def trusted(alias, cert):
    return jks.TrustedCertEntry.new(alias, cert)


def cert_a():
    return expected.RSA1024.certs[0]


def cert_b():
    return expected.RSA2048_3certs.certs[0]


def cert_c():
    return expected.DSA2048.certs[0]


class MigrationTests(unittest.TestCase):
    def test_same_certificate_under_new_alias_is_a_rename(self):
        old = make_store([trusted("legacy-web", cert_a())])
        new = make_store([trusted("web", cert_a())])

        report = jks.inspect_migration(
            [
                {"name": "old", "data": old, "password": PASSWORD},
                {"name": "new", "data": new, "password": PASSWORD},
            ],
            {"tls-server": {"aliases": ["legacy-web", "web"],
                            "risk": "high"}},
        )

        self.assertEqual(len(report.identities), 1)
        self.assertEqual(len(report.renames), 1)
        self.assertEqual(len(report.rotations), 0)
        rename = report.renames[0]
        self.assertEqual(rename["kind"], "rename")
        self.assertEqual(rename["from_alias"], "legacy-web")
        self.assertEqual(rename["to_alias"], "web")
        self.assertTrue(rename["identity_preserved"])
        self.assertEqual(rename["affected_high_risk_usages"], [])
        self.assertEqual(rename["identity"],
                         report.observations[0]["sha256"])

    def test_same_alias_with_new_certificate_is_a_rotation(self):
        old = make_store([trusted("web", cert_a())])
        new = make_store([trusted("web", cert_b())])

        report = jks.inspect_migration(
            [
                {"name": "old", "data": old, "password": PASSWORD},
                {"name": "new", "data": new, "password": PASSWORD},
            ],
            [
                {"purpose": "tls-server", "aliases": ["web"],
                 "risk": "high"},
                {"purpose": "internal-metrics", "aliases": ["web"],
                 "risk": "low"},
            ],
        )

        self.assertEqual(len(report.identities), 2)
        self.assertEqual(len(report.renames), 0)
        self.assertEqual(len(report.rotations), 1)
        rotation = report.rotations[0]
        self.assertEqual(rotation["kind"], "rotation")
        self.assertEqual(rotation["old_identity"],
                         __import__("hashlib").sha256(cert_a()).hexdigest())
        self.assertEqual(rotation["new_identity"],
                         __import__("hashlib").sha256(cert_b()).hexdigest())
        self.assertFalse(rotation["identity_preserved"])
        self.assertEqual(rotation["affected_high_risk_usages"],
                         ["tls-server"])

    def test_rename_and_rotation_are_separate_changes(self):
        old = make_store([trusted("legacy-web", cert_a())])
        middle = make_store([trusted("web", cert_a())])
        new = make_store([trusted("web", cert_b())])

        report = jks.inspect_migration(
            [
                {"name": "old", "data": old, "password": PASSWORD},
                {"name": "middle", "data": middle, "password": PASSWORD},
                {"name": "new", "data": new, "password": PASSWORD},
            ],
            {"tls-server": {"aliases": ["legacy-web", "web"],
                            "risk": "high"}},
        )

        self.assertEqual([c["kind"] for c in report.changes],
                         ["rename", "rotation"])
        self.assertTrue(report.renames[0]["identity_preserved"])
        self.assertEqual(report.rotations[0]["affected_high_risk_usages"],
                         ["tls-server"])

    def test_identity_is_not_alias(self):
        old = make_store([trusted("shared-name", cert_a())])
        new = make_store([trusted("shared-name", cert_b())])

        report = jks.inspect_migration(
            [
                {"name": "old", "data": old, "password": PASSWORD},
                {"name": "new", "data": new, "password": PASSWORD},
            ],
            {"tls-server": {"aliases": ["shared-name"], "risk": "high"}},
        )

        self.assertNotEqual(report.observations[0]["identity"],
                            report.observations[1]["identity"])
        self.assertEqual(len(report.identities), 2)
        self.assertEqual(len(report.rotations), 1)

    def test_private_key_is_never_read_or_reported(self):
        private_key = expected.RSA1024.private_key
        entry = jks.PrivateKeyEntry.new(
            "web", expected.RSA1024.certs, private_key)
        data = make_store([entry])

        report = jks.inspect_migration(
            [{"name": "old", "data": data, "password": PASSWORD}],
            {"tls-server": {"aliases": ["web"], "risk": "high"}},
        )
        serialized = json.dumps(report)

        self.assertEqual(len(report.identities), 1)
        self.assertEqual(report.observations[0]["entry_type"], "private_key")
        self.assertNotIn("PRIVATE KEY", serialized)
        self.assertNotIn(private_key.hex(), serialized)
        self.assertNotIn("pkey", serialized)
        self.assertNotIn(PASSWORD, serialized)

    def test_truncated_old_store_keeps_confirmed_handoffs(self):
        first = trusted("web", cert_a())
        second = trusted("api", cert_b())
        data = make_store([first, second])

        # Keep the first complete entry and only a prefix of the second.
        second_marker = data.index(b"api")
        truncated = data[:second_marker + 3]

        report = jks.inspect_migration(
            [
                {"name": "old", "data": truncated, "password": PASSWORD},
                {"name": "new", "data": make_store([trusted("web", cert_b())]),
                 "password": PASSWORD},
            ],
            {"tls-server": {"aliases": ["web", "api"], "risk": "high"}},
        )

        self.assertEqual(len(report.handoffs), 2)
        self.assertEqual([item["alias"] for item in report.handoffs],
                         ["web", "web"])
        self.assertTrue(report.incomplete)
        self.assertTrue(any(w["kind"] == "partial_keystore"
                            for w in report.warnings))
        # The complete first entry is still available for comparison.
        self.assertEqual(len(report.rotations), 1)

    def test_bad_password_salvages_public_certificates(self):
        data = make_store([trusted("web", cert_a())], PASSWORD)
        report = jks.inspect_migration(
            [{"name": "old", "data": data, "password": "wrong"}],
            {"tls-server": {"aliases": ["web"], "risk": "high"}},
        )

        self.assertEqual(len(report.identities), 1)
        self.assertEqual(report.sources[0]["integrity"], "unverified")
        self.assertTrue(any(w["kind"] == "integrity_unverified"
                            for w in report.warnings))

    def test_missing_source_does_not_discard_other_sources(self):
        new = make_store([trusted("web", cert_b())])
        report = jks.inspect_migration(
            [
                {"name": "missing", "path": os.path.join(
                    os.path.dirname(__file__), "does-not-exist.jks"),
                 "password": PASSWORD},
                {"name": "new", "data": new, "password": PASSWORD},
            ],
            {"tls-server": {"aliases": ["web"], "risk": "high"}},
        )

        self.assertEqual(len(report.errors), 1)
        self.assertEqual(len(report.identities), 1)
        self.assertEqual(len(report.handoffs), 1)
        self.assertTrue(report.incomplete)

    def test_usage_shapes_and_report_is_json_serializable(self):
        old = make_store([trusted("legacy", cert_a())])
        new = make_store([trusted("current", cert_a())])
        report = jks.inspect_migration(
            {"old": {"data": old, "password": PASSWORD},
             "new": {"data": new, "password": PASSWORD}},
            {"legacy": ["tls-server"], "current": ["tls-server"]},
        )

        self.assertEqual(len(report.renames), 1)
        json.dumps(report)
        self.assertEqual(report["changes"][0]["kind"], "rename")

    def test_loaded_keystore_objects_are_accepted(self):
        old_store = jks.KeyStore.loads(
            make_store([trusted("legacy", cert_a())]), PASSWORD,
            try_decrypt_keys=False)
        new_store = jks.KeyStore.loads(
            make_store([trusted("current", cert_a())]), PASSWORD,
            try_decrypt_keys=False)

        report = jks.inspect_migration(
            [old_store, new_store],
            [{"purpose": "tls-server", "aliases": ["legacy", "current"],
              "high_risk": True}],
        )

        self.assertEqual(len(report.identities), 1)
        self.assertEqual(len(report.renames), 1)

    def test_high_risk_usages_can_be_supplied_explicitly(self):
        old = make_store([trusted("web", cert_a())])
        new = make_store([trusted("web", cert_b())])
        report = jks.inspect_migration(
            [
                {"name": "old", "data": old, "password": PASSWORD},
                {"name": "new", "data": new, "password": PASSWORD},
            ],
            {"tls-server": {"aliases": ["web"]},
             "metrics": {"aliases": ["web"], "risk": "low"}},
            high_risk_usages=["tls-server"],
        )

        self.assertEqual(report.rotations[0]["affected_high_risk_usages"],
                         ["tls-server"])


if __name__ == "__main__":
    unittest.main()
