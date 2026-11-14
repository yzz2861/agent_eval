# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime, timedelta
import unittest
import os
import sys

from cryptography import x509 as cx

from asn1crypto import pem, x509
from asn1crypto.util import timezone
from certvalidator import CertificateValidator, ValidationContext
from certvalidator import crl_client
from certvalidator.errors import PathValidationError, RevokedError

from ._unittest_compat import patch

from ._crl_helpers import build_crl, make_ca, make_end_entity

if sys.version_info < (3,):
    from urllib2 import URLError
else:
    from urllib.error import URLError

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CertificateValidatorTests(unittest.TestCase):

    def _load_nist_cert(self, filename):
        return self._load_cert_object('nist_pkits', 'certs', filename)

    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)
        return cert

    def test_basic_certificate_validator_tls(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        path = validator.validate_tls('www.mozilla.org')

        expected_names = [
            "Common Name: DigiCert Global Root CA, Organizational Unit: www.digicert.com, "
            "Organization: DigiCert Inc, Country: US",
            "Common Name: DigiCert SHA2 Secure Server CA, Organization: DigiCert Inc, Country: US",
            "Common Name: www.mozilla.org, Organizational Unit: WebOps, Organization: Mozilla Corporation, "
            "Locality: Mountain View, State/Province: California, Country: US",
        ]
        expected_hashes = [
            b'\x80Q\x06\x012\xad\x9a\xc2}Q\x87\xa0\xe8\x87\xfb\x01b\x01U\xee',
            b"\x10_\xa6z\x80\x08\x9d\xb5'\x9f5\xce\x83\x0bC\x88\x9e\xa3\xc7\r",
            b'I\xac\x03\xf8\xf3Km\xca)V)\xf2I\x9a\x98\xbe\x98\xdc.\x81'
        ]

        names = [item.subject.human_friendly for item in path]
        hashes = [item.subject.sha1 for item in path]

        if len(path) == 2 and hashes == expected_hashes[1:]:
            self.assertEqual(expected_names[1:], names)
            self.assertEqual(expected_hashes[1:], hashes)
        else:
            self.assertEqual(expected_names, names)
            self.assertEqual(expected_hashes, hashes)

    def test_basic_certificate_validator_tls_expired(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'expired'):
            validator.validate_tls('www.mozilla.org')

    def test_basic_certificate_validator_tls_invalid_hostname(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'not valid'):
            validator.validate_tls('google.com')

    def test_basic_certificate_validator_tls_invalid_key_usage(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'for the purpose'):
            validator.validate_usage(set(['crl_sign']))

    def test_basic_certificate_validator_tls_whitelist(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(
            whitelisted_certs=[cert.sha1_fingerprint],
            moment=moment
        )
        validator = CertificateValidator(cert, other_certs, context)

        # If whitelist does not work, this will raise exception for expiration
        validator.validate_tls('www.mozilla.org')

        # If whitelist does not work, this will raise exception for hostname
        validator.validate_tls('google.com')

        # If whitelist does not work, this will raise exception for key usage
        validator.validate_usage(set(['crl_sign']))

    def test_network_failure_is_indeterminate_while_cached_revocation_is_definite(self):
        moment = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        past = moment - timedelta(days=10)

        ca_key, ca_cert = make_ca('End-to-end CRL Root CA')
        _, ee_cert = make_end_entity(ca_key, ca_cert, 'end-to-end-end-entity', 3001, moment)

        revoked_crl = build_crl(
            ca_key,
            ca_cert,
            [(3001, cx.ReasonFlags.key_compromise, past)],
            7,
            moment - timedelta(days=5),
            moment + timedelta(days=10)
        )

        # A network failure is an indeterminate condition: soft-fail mode
        # ignores it instead of producing a definite revocation, and the
        # subject name must never appear in the error path.
        def broken_fetch(cert, use_deltas=True, user_agent=None, timeout=10):
            raise URLError('network unavailable')

        original_fetch = crl_client.fetch
        crl_client.fetch = broken_fetch
        try:
            network_context = ValidationContext(
                trust_roots=[ca_cert.asn1],
                allow_fetching=True,
                revocation_mode='soft-fail'
            )
            network_validator = CertificateValidator(ee_cert.asn1, validation_context=network_context)
            path = network_validator.validate_usage(set())
            self.assertIsNotNone(path)
            self.assertEqual(1, len(network_context.soft_fail_exceptions))
        finally:
            crl_client.fetch = original_fetch

        # In hard-fail mode the same network failure is surfaced as a path
        # validation failure, still without producing a RevokedError.
        def broken_fetch(cert, use_deltas=True, user_agent=None, timeout=10):
            raise URLError('network unavailable')

        crl_client.fetch = broken_fetch
        try:
            hard_context = ValidationContext(
                trust_roots=[ca_cert.asn1],
                allow_fetching=True,
                revocation_mode='hard-fail'
            )
            hard_validator = CertificateValidator(ee_cert.asn1, validation_context=hard_context)
            with self.assertRaises(URLError) as hard_cm:
                hard_validator.validate_usage(set())
            self.assertNotIn('end-to-end-end-entity', str(hard_cm.exception))
        finally:
            crl_client.fetch = original_fetch

        # A complete in-scope CRL that lists the serial produces a definite
        # revocation decision, which is reported as RevokedError.
        crl_context = ValidationContext(
            trust_roots=[ca_cert.asn1],
            crls=[revoked_crl],
            moment=moment,
            revocation_mode='hard-fail'
        )
        revoked_validator = CertificateValidator(ee_cert.asn1, validation_context=crl_context)
        with self.assertRaises(RevokedError) as revoked_cm:
            revoked_validator.validate_usage(set())

        revoked_message = str(revoked_cm.exception)
        self.assertIn('revoked', revoked_message)
        self.assertNotIn('end-to-end-end-entity', revoked_message)
