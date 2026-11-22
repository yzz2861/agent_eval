#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:

from __future__ import print_function

import json
import os
import unittest

import jks


CERT_SHARED = b"shared-certificate-example-der"
CERT_PARTNER = b"partner-certificate-example-der"
CERT_OTHER = b"other-certificate-example-der"


def sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def entry(alias, cert):
    return jks.TrustedCertEntry(type="X.509", cert=cert, timestamp=0, alias=alias)


class TrustImpactTests(unittest.TestCase):
    def shared_image(self):
        return [
            entry("legacy-shared", CERT_SHARED),
            entry("merged-shared", CERT_SHARED),
            entry("new-partner", CERT_PARTNER),
        ]

    def test_default_all_expands_and_keeps_duplicate_visible(self):
        report = jks.preview_trust_impact(
            {
                "default-store": {
                    "selection": "all",
                    "baseline": {"certificates": [sha(CERT_SHARED)]},
                }
            },
            self.shared_image(),
        )
        app = report["default-store"]
        self.assertEqual(app.trusted_entry_count, 3)
        self.assertEqual(app.trusted_certificate_count, 2)
        self.assertTrue(app.expanded)
        self.assertEqual(app.expansion_count, 1)
        self.assertEqual(
            app.transition,
            "local_authorization_to_multiple_trust_objects",
        )
        self.assertEqual(report.expanded_applications, ["default-store"])
        self.assertEqual(len(app.duplicate_certificates), 1)
        self.assertEqual(
            app.duplicate_certificates[0]["aliases"],
            ["legacy-shared", "merged-shared"],
        )

    def test_alias_selection_stays_local(self):
        report = jks.preview_trust_impact(
            {
                "legacy-alias": {
                    "aliases": ["legacy-shared"],
                    "baseline": {
                        "aliases": ["legacy-shared"],
                        "certificates": [sha(CERT_SHARED)],
                    },
                }
            },
            self.shared_image(),
        )
        app = report["legacy-alias"]
        self.assertEqual(app.trusted_aliases, ["legacy-shared"])
        self.assertEqual(app.trusted_certificate_count, 1)
        self.assertFalse(app.expanded)
        self.assertEqual(app.transition, None)
        self.assertEqual(app.duplicate_certificates, [])

    def test_missing_alias_is_reported_and_does_not_abort(self):
        report = jks.preview_trust_impact(
            {
                "broken": {
                    "aliases": ["missing-root"],
                    "baseline": {"aliases": ["missing-root"]},
                },
                "working": {"selection": "all", "baseline": {"certificates": []}},
            },
            self.shared_image(),
        )
        broken = report["broken"]
        self.assertEqual(broken.status, "missing_aliases")
        self.assertEqual(broken.missing_aliases, ["missing-root"])
        self.assertEqual(report.applications_with_missing_aliases, ["broken"])
        self.assertEqual(report["working"].trusted_certificate_count, 2)

    def test_missing_selection_record_is_not_treated_as_all_or_empty(self):
        report = jks.preview_trust_impact(
            {"unknown-record": {"selection": "all"}},
            self.shared_image(),
        )
        app = report["unknown-record"]
        self.assertEqual(app.baseline_record_status, "missing")
        self.assertIsNone(app.expanded)
        self.assertTrue(app.record_missing)
        self.assertEqual(app.status, "missing_selection_record")
        self.assertEqual(
            report.applications_missing_selection_records,
            ["unknown-record"],
        )
        self.assertEqual(report.expanded_applications, [])

    def test_explicit_empty_record_is_known_and_not_missing(self):
        report = jks.preview_trust_impact(
            {
                "new-app": {
                    "selection": "all",
                    "baseline": {"certificates": []},
                }
            },
            self.shared_image(),
        )
        app = report["new-app"]
        self.assertEqual(app.baseline_record_status, "recorded")
        self.assertTrue(app.baseline_known)
        self.assertTrue(app.expanded)
        self.assertEqual(app.transition, "no_trust_to_trust")

    def test_private_and_secret_entries_are_ignored_without_decryption(self):
        certs = [
            jks.TrustedCertEntry.new("public-root", CERT_SHARED),
        ]
        private_key = jks.PrivateKeyEntry(
            alias="private-entry",
            timestamp=0,
            cert_chain=[("X.509", CERT_PARTNER)],
            encrypted=b"opaque-private-material",
        )
        store = jks.KeyStore.new("jks", certs + [private_key])
        data = store.saves("12345678")

        original_decrypt = jks.PrivateKeyEntry.decrypt

        def fail_decrypt(*args, **kwargs):
            raise AssertionError("private key was decrypted")

        jks.PrivateKeyEntry.decrypt = fail_decrypt
        try:
            report = jks.preview_trust_impact(
                {"app": "all"},
                data,
                store_password="12345678",
            )
        finally:
            jks.PrivateKeyEntry.decrypt = original_decrypt

        self.assertEqual(report.image.private_entries_ignored, 1)
        self.assertEqual(report["app"].trusted_aliases, ["public-root"])
        self.assertEqual(len(report.public_entries), 1)

    def test_alias_pointing_at_private_entry_is_not_read(self):
        private_key = jks.PrivateKeyEntry(
            alias="private-entry",
            timestamp=0,
            cert_chain=[("X.509", CERT_PARTNER)],
            encrypted=b"opaque-private-material",
        )
        store = jks.KeyStore.new(
            "jks",
            [entry("public-root", CERT_SHARED), private_key],
        )
        report = jks.preview_trust_impact(
            {"app": {"aliases": ["private-entry"]}},
            store,
        )
        app = report["app"]
        self.assertEqual(app.status, "missing_public_entries")
        self.assertEqual(app.non_public_aliases, ["private-entry"])
        self.assertEqual(app.trusted_entry_count, 0)

    def test_baseline_image_identifies_new_certificates(self):
        baseline = [entry("legacy-shared", CERT_SHARED)]
        report = jks.preview_trust_impact(
            {"default-store": "all"},
            self.shared_image(),
            baseline_image=baseline,
        )
        app = report["default-store"]
        self.assertTrue(app.expanded)
        self.assertEqual(app.added_certificate_fingerprints, [
            ":".join(
                sha(CERT_PARTNER)[i:i + 2].upper()
                for i in range(0, len(sha(CERT_PARTNER)), 2)
            )
        ])
        self.assertEqual(len(report.new_certificates), 1)

    def test_records_mapping_supplies_real_selection(self):
        report = jks.preview_trust_impact(
            {
                "default-store": "all",
                "legacy-alias": {"aliases": ["legacy-shared"]},
            },
            self.shared_image(),
            records={
                "default-store": {"certificates": [sha(CERT_SHARED)]},
                "legacy-alias": {
                    "aliases": ["legacy-shared"],
                    "certificates": [sha(CERT_SHARED)],
                },
            },
        )
        self.assertTrue(report["default-store"].expanded)
        self.assertFalse(report["legacy-alias"].expanded)

    def test_shared_certificate_example_points_to_the_transitioning_app(self):
        preview, facts = jks.shared_certificate_example()
        self.assertEqual(facts["expanded_application"], "default-store")
        self.assertEqual(
            facts["transition"],
            "local_authorization_to_multiple_trust_objects",
        )
        self.assertEqual(
            facts["duplicate_aliases"],
            [["legacy-shared", "merged-shared"]],
        )
        self.assertIn("default-store", preview.expanded_applications)

    def test_json_serialisable(self):
        report = jks.preview_trust_impact(
            {"app": "all"},
            self.shared_image(),
            records={"app": {"certificates": [sha(CERT_SHARED)]}},
        )
        parsed = json.loads(report.to_json())
        self.assertEqual(parsed["expanded_applications"], ["app"])
        self.assertEqual(parsed["applications"][0]["trusted_certificate_count"], 2)

    def test_reversed_image_and_contracts_arguments(self):
        report = jks.preview_trust_impact(
            self.shared_image(),
            {"app": {"aliases": ["legacy-shared"]}},
        )
        self.assertEqual(report["app"].trusted_aliases, ["legacy-shared"])

    def test_tolerant_duplicate_alias_image_keeps_public_entries(self):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "keystores",
            "jks",
            "duplicate_aliases.jks",
        )
        report = jks.preview_trust_impact({"app": "all"}, path, store_password="12345678")
        self.assertGreaterEqual(len(report.public_entries), 1)
        self.assertTrue(any("Duplicate aliases" in w for w in report.warnings))


if __name__ == "__main__":
    unittest.main()
