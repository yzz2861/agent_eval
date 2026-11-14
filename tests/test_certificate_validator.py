# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

from asn1crypto import pem, x509
from asn1crypto.util import timezone
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathBuildingError, PathValidationError
from certvalidator.path import ValidationPath
from certvalidator.validate import validate_path

from ._unittest_compat import patch

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


class PathBuildingValidatorTests(unittest.TestCase):

    def _load_cert(self, filename):
        with open(os.path.join(fixtures_dir, 'path_building', filename), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    def _context(self, trust_roots):
        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        return ValidationContext(trust_roots=trust_roots, moment=moment)

    def test_hierarchical_chain_validates(self):
        root_a = self._load_cert('root-a.pem')
        intermediate = self._load_cert('intermediate-a.pem')
        leaf = self._load_cert('leaf-a.pem')

        context = self._context([root_a])
        validator = CertificateValidator(leaf, [intermediate], context)
        path = validator.validate_usage(set(['digital_signature']))

        self.assertEqual(
            [root_a.sha256, intermediate.sha256, leaf.sha256],
            [cert.sha256 for cert in path]
        )

    def test_cross_signed_root_not_used_when_untrusted(self):
        root_a = self._load_cert('root-a.pem')
        root_b = self._load_cert('root-b.pem')
        cross_a_by_b = self._load_cert('root-a-cross-by-b.pem')
        leaf = self._load_cert('leaf-root-a.pem')

        # Only root A is trusted - root B and the cross certificate are
        # supplied as untrusted intermediates, so validation must remain
        # anchored at root A and never switch to root B's chain
        context = self._context([root_a])
        validator = CertificateValidator(leaf, [cross_a_by_b, root_b], context)
        path = validator.validate_usage(set(['digital_signature']))

        self.assertEqual(
            [root_a.sha256, leaf.sha256],
            [cert.sha256 for cert in path]
        )

    def test_cross_signed_root_validates_via_trusted_signer(self):
        root_b = self._load_cert('root-b.pem')
        cross_a_by_b = self._load_cert('root-a-cross-by-b.pem')
        leaf = self._load_cert('leaf-root-a.pem')

        # Only root B is trusted, so the cross-signed copy of root A must be
        # used as an intermediate
        context = self._context([root_b])
        validator = CertificateValidator(leaf, [cross_a_by_b], context)
        path = validator.validate_usage(set(['digital_signature']))

        self.assertEqual(
            [root_b.sha256, cross_a_by_b.sha256, leaf.sha256],
            [cert.sha256 for cert in path]
        )

    def test_cross_signed_roots_prefer_direct_anchor(self):
        root_a = self._load_cert('root-a.pem')
        root_b = self._load_cert('root-b.pem')
        cross_a_by_b = self._load_cert('root-a-cross-by-b.pem')
        leaf = self._load_cert('leaf-root-a.pem')

        context = self._context([root_a, root_b])
        validator = CertificateValidator(leaf, [cross_a_by_b], context)
        path = validator.validate_usage(set(['digital_signature']))

        self.assertEqual(root_a.sha256, path.first.sha256)
        self.assertEqual(2, len(path))

    def test_same_name_roots_aki_selects_correct_root(self):
        root_1 = self._load_cert('shared-root-1.pem')
        root_2 = self._load_cert('shared-root-2.pem')
        intermediate = self._load_cert('intermediate-shared.pem')
        leaf = self._load_cert('leaf-shared.pem')

        context = self._context([root_1, root_2])
        validator = CertificateValidator(leaf, [intermediate], context)
        path = validator.validate_usage(set(['digital_signature']))

        self.assertEqual(root_2.sha256, path.first.sha256)

    def test_same_name_roots_without_aki_backtracks(self):
        root_1 = self._load_cert('shared-noski-root-1.pem')
        root_2 = self._load_cert('shared-noski-root-2.pem')
        leaf = self._load_cert('leaf-shared-noski.pem')

        # Without AKI/SKI information, the path to root 1 is tried first and
        # fails the signature check, so validation must backtrack to root 2
        context = self._context([root_1, root_2])
        validator = CertificateValidator(leaf, [], context)
        path = validator.validate_usage(set(['digital_signature']))

        self.assertEqual(root_2.sha256, path.first.sha256)

    def test_missing_intermediate_fails(self):
        root_a = self._load_cert('root-a.pem')
        leaf = self._load_cert('leaf-a.pem')

        context = self._context([root_a])
        validator = CertificateValidator(leaf, [], context)

        with self.assertRaisesRegex(PathBuildingError, 'no issuer matching'):
            validator.validate_usage(set(['digital_signature']))

    def test_cross_signed_loop_fails(self):
        cross_a_by_b = self._load_cert('root-a-cross-by-b.pem')
        cross_b_by_a = self._load_cert('root-b-cross-by-a.pem')
        leaf = self._load_cert('leaf-root-a.pem')

        context = self._context([])
        validator = CertificateValidator(leaf, [cross_a_by_b, cross_b_by_a], context)

        with self.assertRaisesRegex(PathBuildingError, 'loop'):
            validator.validate_usage(set(['digital_signature']))

    def test_overlong_chain_fails(self):
        root = self._load_cert('long-root.pem')
        intermediates = [
            self._load_cert('long-int-%d.pem' % i) for i in range(1, 8)
        ]
        leaf = self._load_cert('long-leaf.pem')

        context = self._context([root])
        validator = CertificateValidator(leaf, intermediates, context)

        with self.assertRaisesRegex(PathBuildingError, 'maximum length'):
            validator.validate_usage(set(['digital_signature']))

    def test_max_length_boundary_chain_validates(self):
        root = self._load_cert('long-root.pem')
        intermediates = [
            self._load_cert('long-int-%d.pem' % i) for i in range(2, 8)
        ]
        leaf = self._load_cert('long-leaf-2.pem')

        context = self._context([root])
        validator = CertificateValidator(leaf, intermediates, context)
        path = validator.validate_usage(set(['digital_signature']))

        self.assertEqual(8, len(path))
        self.assertEqual(root.sha256, path.first.sha256)

    def test_validate_path_rejects_untrusted_anchor(self):
        root_a = self._load_cert('root-a.pem')
        intermediate = self._load_cert('intermediate-a.pem')
        leaf = self._load_cert('leaf-a.pem')

        context = self._context([root_a])

        # A path anchored at a certificate that is not one of the caller's
        # trust roots must not validate, even if every signature in it is
        # otherwise verifiable
        path = ValidationPath(leaf)
        path.prepend(intermediate)

        with self.assertRaisesRegex(PathValidationError, 'not one of the trusted root'):
            validate_path(context, path)
