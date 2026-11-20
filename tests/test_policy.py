# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest

from asn1crypto import core, keys, pem, policy, x509


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')
policy_fixtures_dir = os.path.join(fixtures_dir, 'policy')

POLICY_OID = '1.2.3.4.5.6.7.8.1'
UNKNOWN_QUALIFIER_OID = '1.2.3.4.5.6.7.99.1'


class _RawQualifierSequence(core.Sequence):
    # Allows encoding a qualifier OID paired with contents of the wrong ASN.1
    # type, which the regular PolicyQualifierInfo constructor rejects.
    _fields = [('oid', x509.PolicyQualifierId), ('contents', core.UTF8String)]


class _RawPolicyInformation(core.Sequence):
    _fields = [('id', x509.PolicyIdentifier), ('qualifiers', x509.PolicyQualifierInfos)]


def _wrap_policies(policy_information_bytes):
    header = bytearray([0x30, len(policy_information_bytes)])
    return x509.CertificatePolicies.load(bytes(header) + policy_information_bytes)


class PolicyEvidenceTests(unittest.TestCase):

    def _load_cert(self, filename):
        with open(os.path.join(policy_fixtures_dir, filename), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    def test_samples_share_policy_oid_but_differ_in_qualifiers(self):
        cps_cert = self._load_cert('policy-qualifier-cps.der')
        unknown_cert = self._load_cert('policy-qualifier-unknown.der')

        cps_evidence = policy.policy_evidence(cps_cert)
        unknown_evidence = policy.policy_evidence(unknown_cert)

        self.assertEqual(1, len(cps_evidence))
        self.assertEqual(1, len(unknown_evidence))
        self.assertEqual(POLICY_OID, cps_evidence[0].policy_identifier_dotted)
        self.assertEqual(POLICY_OID, unknown_evidence[0].policy_identifier_dotted)

        cps_qualifier = cps_evidence[0].qualifiers[0]
        unknown_qualifier = unknown_evidence[0].qualifiers[0]
        self.assertEqual(policy.CPS_QUALIFIER_OID, cps_qualifier.qualifier_id_dotted)
        self.assertEqual(UNKNOWN_QUALIFIER_OID, unknown_qualifier.qualifier_id_dotted)

    def test_ordering_and_original_type_are_preserved(self):
        cert = self._load_cert('policy-qualifier-unknown.der')
        evidence = policy.policy_evidence(cert)
        qualifier = evidence[0].qualifiers[0]

        self.assertEqual(0, evidence[0].index)
        self.assertEqual(0, qualifier.index)
        self.assertEqual('universal', qualifier.original_type['class'])
        self.assertEqual(core.UTF8String.tag, qualifier.original_type['tag'])
        self.assertEqual('utf8_string', qualifier.original_type['tag_name'])
        # Raw bytes are the complete DER encoding including the type header.
        self.assertEqual(b'\x0c', qualifier.raw[0:1])

    def test_default_selection_understands_nothing(self):
        cert = self._load_cert('policy-qualifier-cps.der')
        evidence = policy.policy_evidence(cert)
        qualifier = evidence[0].qualifiers[0]

        self.assertTrue(qualifier.implemented)
        self.assertFalse(qualifier.explicitly_selected)
        self.assertFalse(qualifier.understood)
        self.assertIsNone(qualifier.value)

    def test_explicit_selection_interprets_implemented_qualifier(self):
        cert = self._load_cert('policy-qualifier-cps.der')
        evidence = policy.policy_evidence(
            cert,
            ['certification_practice_statement'],
        )
        qualifier = evidence[0].qualifiers[0]

        self.assertTrue(qualifier.implemented)
        self.assertTrue(qualifier.explicitly_selected)
        self.assertTrue(qualifier.understood)
        self.assertEqual('https://example.com/cps.pdf', qualifier.value)
        self.assertEqual('ia5_string', qualifier.original_type['tag_name'])

    def test_dotted_oid_selection_is_accepted(self):
        cert = self._load_cert('policy-qualifier-cps.der')
        evidence = policy.policy_evidence(cert, [policy.CPS_QUALIFIER_OID])
        self.assertTrue(evidence[0].qualifiers[0].understood)

    def test_unimplemented_qualifier_is_never_released(self):
        cert = self._load_cert('policy-qualifier-unknown.der')
        evidence = policy.policy_evidence(cert, [UNKNOWN_QUALIFIER_OID])
        qualifier = evidence[0].qualifiers[0]

        self.assertFalse(qualifier.implemented)
        # The caller can name it, but the library still cannot interpret it.
        self.assertTrue(qualifier.explicitly_selected)
        self.assertFalse(qualifier.understood)
        self.assertIsNone(qualifier.value)
        self.assertIsNone(qualifier.error)

    def test_unknown_identifier_raises(self):
        cert = self._load_cert('policy-qualifier-cps.der')
        with self.assertRaises(ValueError):
            policy.policy_evidence(cert, ['not-an-oid'])

    def test_review_distinguishes_the_two_local_samples(self):
        understood = ['certification_practice_statement']

        cps_review = policy.review_policy_basis(
            self._load_cert('policy-qualifier-cps.der'),
            understood,
        )
        unknown_review = policy.review_policy_basis(
            self._load_cert('policy-qualifier-unknown.der'),
            understood,
        )

        self.assertTrue(cps_review['approved'])
        self.assertTrue(cps_review['policies'][0]['has_understood_qualifier'])
        self.assertEqual([], cps_review['policies'][0]['reasons'])

        self.assertFalse(unknown_review['approved'])
        self.assertFalse(unknown_review['policies'][0]['has_understood_qualifier'])
        reasons = unknown_review['policies'][0]['reasons']
        self.assertEqual(1, len(reasons))
        self.assertIn(UNKNOWN_QUALIFIER_OID, reasons[0])
        self.assertIn('not implemented', reasons[0])

    def test_review_flags_implemented_but_unselected_qualifier(self):
        cert = self._load_cert('policy-qualifier-cps.der')
        review = policy.review_policy_basis(cert, ['user_notice'])

        self.assertFalse(review['approved'])
        reasons = review['policies'][0]['reasons']
        self.assertEqual(1, len(reasons))
        self.assertIn(policy.CPS_QUALIFIER_OID, reasons[0])
        self.assertIn('not explicitly selected', reasons[0])

    def test_policy_without_qualifiers_has_no_basis(self):
        policies = x509.CertificatePolicies([
            x509.PolicyInformation({'policy_identifier': POLICY_OID}),
        ])
        review = policy.review_policy_basis(
            policies,
            ['certification_practice_statement'],
        )

        self.assertFalse(review['approved'])
        self.assertFalse(review['policies'][0]['has_understood_qualifier'])
        self.assertEqual(['policy has no qualifiers'], review['policies'][0]['reasons'])

    def test_malformed_understood_qualifier_fails_closed(self):
        raw_qualifier = _RawQualifierSequence({
            'oid': 'certification_practice_statement',
            'contents': 'not an ia5 string',
        }).dump()
        malformed = x509.PolicyQualifierInfo.load(raw_qualifier)
        raw_policy = _RawPolicyInformation({
            'id': POLICY_OID,
            'qualifiers': x509.PolicyQualifierInfos([malformed]),
        }).dump()
        policies = _wrap_policies(raw_policy)

        evidence = policy.policy_evidence(
            policies,
            ['certification_practice_statement'],
        )
        qualifier = evidence[0].qualifiers[0]
        self.assertFalse(qualifier.understood)
        self.assertIsNotNone(qualifier.error)
        self.assertEqual('utf8_string', qualifier.original_type['tag_name'])
        self.assertIn(b'not an ia5 string', qualifier.raw)

        review = policy.review_policy_basis(
            policies,
            ['certification_practice_statement'],
        )
        self.assertFalse(review['approved'])
        self.assertIn('could not be parsed', review['policies'][0]['reasons'][0])

    def test_certificate_without_policy_extension_returns_none(self):
        tbs = x509.TbsCertificate({
            'version': 'v3',
            'serial_number': 8,
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': x509.Name.build({'common_name': 'bare.example'}),
            'validity': {
                'not_before': x509.Time('utc_time', '260101000000Z'),
                'not_after': x509.Time('utc_time', '491231235959Z'),
            },
            'subject': x509.Name.build({'common_name': 'bare.example'}),
            'subject_public_key_info': {
                'algorithm': {'algorithm': 'rsa'},
                'public_key': core.ParsableOctetBitString(
                    keys.RSAPublicKey({
                        'modulus': 1,
                        'public_exponent': 1,
                    }).dump()
                ),
            },
        })
        cert = x509.Certificate({'tbs_certificate': tbs})
        self.assertIsNone(policy.policy_evidence(cert))
        self.assertFalse(policy.review_policy_basis(cert, ['user_notice'])['approved'])

    def test_regular_certificate_parsing_is_unchanged(self):
        cps_cert = self._load_cert('policy-qualifier-cps.der')
        unknown_cert = self._load_cert('policy-qualifier-unknown.der')

        native_cps = cps_cert.certificate_policies_value.native
        native_unknown = unknown_cert.certificate_policies_value.native
        self.assertEqual(POLICY_OID, native_cps[0]['policy_identifier'])
        self.assertEqual(POLICY_OID, native_unknown[0]['policy_identifier'])
        self.assertEqual(
            'certification_practice_statement',
            native_cps[0]['policy_qualifiers'][0]['policy_qualifier_id'],
        )
        self.assertEqual(
            UNKNOWN_QUALIFIER_OID,
            native_unknown[0]['policy_qualifiers'][0]['policy_qualifier_id'],
        )
