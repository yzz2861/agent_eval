# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import os
import unittest

from asn1crypto import pem, x509, crl
from asn1crypto.util import timezone

from certvalidator import CertificateValidator, ValidationContext
from certvalidator.delegation import PolicyDelegation

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


# The two deployment manifests share the leaf certificate and this policy
POLICY_SHARED = '2.16.840.1.101.3.2.1.48.1'

# The manifests diverge on the cross-domain delegation of this policy
POLICY_CROSS_DOMAIN = '2.16.840.1.101.3.2.1.48.2'


class DelegationTests(unittest.TestCase):

    def _load_nist_cert(self, filename):
        with open(os.path.join(fixtures_dir, 'nist_pkits', 'certs', filename), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    def _load_nist_crl(self, filename):
        with open(os.path.join(fixtures_dir, 'nist_pkits', 'crls', filename), 'rb') as f:
            crl_bytes = f.read()
            if pem.detect(crl_bytes):
                _, _, crl_bytes = pem.unarmor(crl_bytes)
            return crl.CertificateList.load(crl_bytes)

    def _deployment_validator(self):
        # The same signing certificate shipped to both deployments
        cert = self._load_nist_cert('AllCertificatesSamePoliciesTest10EE.crt')
        ca_certs = [self._load_nist_cert('TrustAnchorRootCertificate.crt')]
        other_certs = [self._load_nist_cert('PoliciesP12CACert.crt')]
        crls = [
            self._load_nist_crl('PoliciesP12CACRL.crl'),
            self._load_nist_crl('TrustAnchorRootCRL.crl'),
        ]
        context = ValidationContext(
            trust_roots=ca_certs,
            crls=crls,
            revocation_mode='hard-fail'
        )
        return CertificateValidator(cert, other_certs, context)

    def _shared_delegation(self):
        # Both manifests carry this same-domain delegation of the shared
        # policy from the policy office
        return PolicyDelegation(
            POLICY_SHARED,
            source='policy-office',
            target='policy-office',
            not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
            allowed_usages=set(['component_signing', 'archival'])
        )

    def test_cross_domain_delegation_approved(self):
        # The normal-service deployment manifest: the policy officer
        # delegated approval of the second policy across domains
        chain = [
            self._shared_delegation(),
            PolicyDelegation(
                POLICY_CROSS_DOMAIN,
                source='policy-office',
                target='service-domain',
                not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
                not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
                allowed_usages=set(['component_signing'])
            ),
        ]
        validator = self._deployment_validator()
        review = validator.validate_delegation(chain, usage='component_signing')

        self.assertEqual(set([POLICY_SHARED, POLICY_CROSS_DOMAIN]), review.policy_oids)
        self.assertEqual('approved', review.conclusion)
        self.assertTrue(review.approved)

        # The validity window, usage restriction and intermediate revocation
        # of each delegation are evidenced separately
        checks = set(entry.check for entry in review.evidence)
        self.assertEqual(
            set(['validity_window', 'usage_restriction', 'intermediate_revocation']),
            checks
        )
        self.assertEqual(6, len(review.evidence))
        self.assertTrue(all(entry.passed for entry in review.evidence))

    def test_cross_domain_delegation_revoked_pending_manual(self):
        # The archive-repository deployment manifest: same leaf certificate
        # and same shared-policy delegation, but the cross-domain delegation
        # of the second policy was revoked by the policy authority
        chain = [
            self._shared_delegation(),
            PolicyDelegation(
                POLICY_CROSS_DOMAIN,
                source='policy-office',
                target='archive-domain',
                not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
                not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
                allowed_usages=set(['archival']),
                revoked=True
            ),
        ]
        validator = self._deployment_validator()
        review = validator.validate_delegation(chain, usage='archival')

        # The path itself still validated via the existing logic; only the
        # delivery conclusion is marked as pending manual review
        self.assertIsNotNone(review.path)
        self.assertEqual('pending_manual', review.conclusion)
        self.assertFalse(review.approved)

        # The intermediate revocation is evidenced separately from the
        # validity window and usage restriction, which both passed
        revocation_evidence = [
            entry for entry in review.evidence
            if entry.check == 'intermediate_revocation'
        ]
        self.assertEqual(2, len(revocation_evidence))
        failed = [entry for entry in revocation_evidence if not entry.passed]
        self.assertEqual(1, len(failed))
        self.assertEqual(POLICY_CROSS_DOMAIN, failed[0].delegation.policy_oid)
        self.assertTrue(failed[0].delegation.cross_domain)

        other_checks = [
            entry for entry in review.evidence
            if entry.check != 'intermediate_revocation'
        ]
        self.assertTrue(all(entry.passed for entry in other_checks))

    def test_no_approval_source_pending_manual(self):
        # A path without an approved source still validates, but the
        # delivery conclusion is pending manual review
        chain = [self._shared_delegation()]
        validator = self._deployment_validator()
        review = validator.validate_delegation(chain, usage='component_signing')

        self.assertIsNotNone(review.path)
        self.assertEqual('pending_manual', review.conclusion)
        self.assertFalse(review.approved)

        source_evidence = [
            entry for entry in review.evidence
            if entry.check == 'approval_source'
        ]
        self.assertEqual(1, len(source_evidence))
        self.assertFalse(source_evidence[0].passed)
        self.assertIsNone(source_evidence[0].delegation)

    def test_window_and_usage_evidenced_separately(self):
        # An expired cross-domain delegation that also does not cover the
        # requested usage fails both checks independently
        chain = [
            self._shared_delegation(),
            PolicyDelegation(
                POLICY_CROSS_DOMAIN,
                source='policy-office',
                target='service-domain',
                not_before=datetime(2020, 1, 1, tzinfo=timezone.utc),
                not_after=datetime(2021, 1, 1, tzinfo=timezone.utc),
                allowed_usages=set(['time_stamping'])
            ),
        ]
        validator = self._deployment_validator()
        review = validator.validate_delegation(chain, usage='component_signing')

        self.assertEqual('pending_manual', review.conclusion)

        failed_checks = set(
            entry.check for entry in review.evidence if not entry.passed
        )
        self.assertEqual(
            set(['validity_window', 'usage_restriction']),
            failed_checks
        )
