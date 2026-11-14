# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import datetime
import unittest
import os

from cryptography import x509 as cx
from cryptography.x509.oid import ObjectIdentifier

from asn1crypto import x509, pem
from certvalidator import crl_client
from certvalidator.context import ValidationContext
from certvalidator.validate import verify_crl
from certvalidator.errors import (
    RevokedError,
    CRLValidationIndeterminateError,
    CRLNoMatchesError,
)

from ._crl_helpers import build_crl, make_ca, make_end_entity, make_issued_certificate
from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


MOMENT = datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc)
PAST = MOMENT - datetime.timedelta(days=10)
RECENT = MOMENT - datetime.timedelta(days=2)
UNKNOWN_CRITICAL_OID = ObjectIdentifier('1.3.6.1.4.1.48066.1.1')


class CRLClientTests(unittest.TestCase):

    def test_fetch_crl(self):
        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            file_bytes = f.read()
            if pem.detect(file_bytes):
                _, _, file_bytes = pem.unarmor(file_bytes)
            intermediate = x509.Certificate.load(file_bytes)

        crls = crl_client.fetch(intermediate, timeout=3)
        context = ValidationContext(crls=crls)
        registry = context.certificate_registry
        path = registry.build_paths(intermediate)[0]

        verify_crl(intermediate, path, context)


class CRLSetValidationTests(unittest.TestCase):

    def setUp(self):
        self.ca_key, self.ca_cert = make_ca('CRL Test Root CA')
        self.ee_key, self.ee_cert = make_end_entity(
            self.ca_key, self.ca_cert, 'crl-test-end-entity', 1000, MOMENT
        )

    def _verify(self, crls, moment=None, trust_roots=None, other_certs=None):
        context = ValidationContext(
            trust_roots=trust_roots if trust_roots is not None else [self.ca_cert.asn1],
            other_certs=other_certs,
            crls=crls,
            moment=moment if moment is not None else MOMENT,
            revocation_mode='hard-fail'
        )
        path = context.certificate_registry.build_paths(self.ee_cert.asn1)[0]
        return verify_crl(self.ee_cert.asn1, path, context, cert_description='the end-entity certificate')

    def _verify_with_registry(self, crls, trust_roots, other_certs=None, moment=None):
        context = ValidationContext(
            trust_roots=trust_roots,
            other_certs=other_certs,
            crls=crls,
            moment=moment if moment is not None else MOMENT,
            revocation_mode='hard-fail'
        )
        registry = context.certificate_registry
        return verify_crl(
            self.ee_cert.asn1,
            registry.build_paths(self.ee_cert.asn1)[0],
            context,
            cert_description='the end-entity certificate'
        )

    def test_newer_complete_crl_revokes_old_revocation(self):
        old_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            10, MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=5)
        )
        new_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.remove_from_crl, RECENT)],
            11, RECENT, MOMENT + datetime.timedelta(days=10)
        )

        # Processing order must not affect the conclusion.
        self._verify([old_crl, new_crl])
        self._verify([new_crl, old_crl])

    def test_delta_chain_remove_from_crl_clears_base_revocation(self):
        base_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            10, MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            freshest_url='http://crl.example/delta.crl'
        )
        delta_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.remove_from_crl, RECENT)],
            12, RECENT, MOMENT + datetime.timedelta(days=5),
            delta_indicator=10
        )

        self._verify([base_crl, delta_crl])

    def test_multiple_delta_crls_use_highest_consistent_number(self):
        base_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            10, MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            freshest_url='http://crl.example/delta.crl'
        )
        early_delta = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, RECENT)],
            11, MOMENT - datetime.timedelta(days=4), MOMENT + datetime.timedelta(days=5),
            delta_indicator=10
        )
        latest_delta = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.remove_from_crl, RECENT)],
            12, MOMENT - datetime.timedelta(days=2), MOMENT + datetime.timedelta(days=5),
            delta_indicator=10
        )

        self._verify([base_crl, early_delta, latest_delta])

    def test_delta_crl_without_matching_base_is_indeterminate(self):
        base_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            10, MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            freshest_url='http://crl.example/delta.crl'
        )
        orphan_delta = build_crl(
            self.ca_key, self.ca_cert,
            [], 12, RECENT, MOMENT + datetime.timedelta(days=5), delta_indicator=99
        )

        with self.assertRaises(CRLValidationIndeterminateError) as cm:
            self._verify([base_crl, orphan_delta])
        messages = ' '.join(failure[0] for failure in cm.exception.failures)
        self.assertIn('base CRL', messages)

    def test_expired_crl_is_indeterminate_not_revoked(self):
        expired_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            9, MOMENT - datetime.timedelta(days=30), MOMENT - datetime.timedelta(days=1)
        )

        with self.assertRaises(CRLValidationIndeterminateError) as cm:
            self._verify([expired_crl])
        self.assertEqual(
            'CRL should have been regenerated by the validation time',
            cm.exception.failures[0][0]
        )

    def test_conflicting_scope_crls_are_indeterminate(self):
        user_scope = cx.IssuingDistributionPoint(
            full_name=None,
            relative_name=None,
            only_contains_user_certs=True,
            only_contains_ca_certs=False,
            only_some_reasons=None,
            indirect_crl=False,
            only_contains_attribute_certs=False,
        )
        ca_scope = cx.IssuingDistributionPoint(
            full_name=None,
            relative_name=None,
            only_contains_user_certs=False,
            only_contains_ca_certs=True,
            only_some_reasons=None,
            indirect_crl=False,
            only_contains_attribute_certs=False,
        )
        user_crl = build_crl(
            self.ca_key, self.ca_cert, [], 10,
            MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            issuing_distribution_point=user_scope
        )
        ca_only_crl = build_crl(
            self.ca_key, self.ca_cert, [], 11,
            MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            issuing_distribution_point=ca_scope
        )

        # The user-cert CRL covers the end-entity cert on its own, so the
        # conflicting CA-only CRL must not turn this into a definite result in
        # either direction. Removing the in-scope CRL leaves only the
        # conflicting CA-only CRL, which cannot be used for this EE cert.
        self._verify([user_crl, ca_only_crl])
        with self.assertRaises(CRLValidationIndeterminateError):
            self._verify([ca_only_crl])

    def test_unknown_critical_extension_is_indeterminate_not_revoked(self):
        bad_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            10, MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            unknown_critical_oid=UNKNOWN_CRITICAL_OID
        )

        with self.assertRaises(CRLValidationIndeterminateError) as cm:
            self._verify([bad_crl])
        self.assertIn('unrecognized critical extensions', cm.exception.failures[0][0])

    def test_indirect_crl_requires_crl_issuer_certificate(self):
        # The CRL is signed by a separate indirect CRL issuer that is not
        # provided, so no complete set can be validated and the result is a
        # non-match rather than a definite revocation.
        indirect_key, indirect_issuer = make_issued_certificate(
            self.ca_key, self.ca_cert, 'Indirect CRL Issuer'
        )
        indirect_idp = cx.IssuingDistributionPoint(
            full_name=None,
            relative_name=None,
            only_contains_user_certs=False,
            only_contains_ca_certs=False,
            only_some_reasons=None,
            indirect_crl=True,
            only_contains_attribute_certs=False,
        )
        indirect_crl = build_crl(
            indirect_key, indirect_issuer,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            10, MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            issuing_distribution_point=indirect_idp
        )

        with self.assertRaises((CRLNoMatchesError, CRLValidationIndeterminateError)):
            self._verify_with_registry([indirect_crl], [self.ca_cert.asn1])

    def test_indirect_crl_signed_by_known_issuer_is_used(self):
        indirect_key, indirect_issuer = make_issued_certificate(
            self.ca_key, self.ca_cert, 'Indirect CRL Issuer'
        )
        indirect_idp = cx.IssuingDistributionPoint(
            full_name=None,
            relative_name=None,
            only_contains_user_certs=False,
            only_contains_ca_certs=False,
            only_some_reasons=None,
            indirect_crl=True,
            only_contains_attribute_certs=False,
        )
        indirect_crl = build_crl(
            indirect_key, indirect_issuer,
            [], 10, MOMENT - datetime.timedelta(days=5), MOMENT + datetime.timedelta(days=10),
            issuing_distribution_point=indirect_idp
        )

        self._verify_with_registry(
            [indirect_crl],
            [self.ca_cert.asn1],
            other_certs=[indirect_issuer.asn1]
        )

    def test_error_messages_do_not_contain_certificate_subject(self):
        expired_crl = build_crl(
            self.ca_key, self.ca_cert,
            [(1000, cx.ReasonFlags.key_compromise, PAST)],
            9, MOMENT - datetime.timedelta(days=30), MOMENT - datetime.timedelta(days=1)
        )

        with self.assertRaises(CRLValidationIndeterminateError) as cm:
            self._verify([expired_crl])
        rendered = str(cm.exception)
        for failure in cm.exception.failures:
            rendered += ' ' + failure[0]
        self.assertNotIn('crl-test-end-entity', rendered)
        self.assertNotIn(self.ee_cert.asn1.subject.human_friendly, rendered)


class CRLLookupCacheTests(unittest.TestCase):

    def test_retrieve_crls_cache_is_keyed_by_issuer(self):
        first_key, first_ca = make_ca('First Issuer CA')
        second_key, second_ca = make_ca('Second Issuer CA')
        _, first_ee = make_end_entity(first_key, first_ca, 'first-end-entity', 2001, MOMENT)
        _, second_ee = make_end_entity(second_key, second_ca, 'second-end-entity', 2002, MOMENT)

        first_crl = build_crl(
            first_key, first_ca, [], 1,
            MOMENT - datetime.timedelta(days=1), MOMENT + datetime.timedelta(days=10)
        )
        second_crl = build_crl(
            second_key, second_ca, [], 1,
            MOMENT - datetime.timedelta(days=1), MOMENT + datetime.timedelta(days=10)
        )

        calls = []

        def fake_fetch(cert, use_deltas=True, user_agent=None, timeout=10):
            calls.append(cert.issuer.sha256)
            if cert.issuer == first_ca.asn1.subject:
                return [first_crl]
            return [second_crl]

        original_fetch = crl_client.fetch
        crl_client.fetch = fake_fetch
        try:
            context = ValidationContext(allow_fetching=True, revocation_mode='hard-fail')
            self.assertEqual([first_crl], context.retrieve_crls(first_ee.asn1))
            self.assertEqual([second_crl], context.retrieve_crls(second_ee.asn1))
            # A second certificate from the first issuer reuses the cache.
            _, first_ee_other = make_end_entity(first_key, first_ca, 'first-end-entity-2', 2003, MOMENT)
            self.assertEqual([first_crl], context.retrieve_crls(first_ee_other.asn1))
        finally:
            crl_client.fetch = original_fetch

        self.assertEqual(2, len(calls))
        self.assertNotEqual(first_ee.asn1.issuer.sha256, second_ee.asn1.issuer.sha256)
