# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

from asn1crypto import pem, x509
from asn1crypto.util import timezone
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.validate import validate_path
from certvalidator.errors import (
    PathValidationError,
    PathValidationIndeterminateError,
)

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

    def _validate_nc_path(self, end_entity_filename, intermediate_filenames):
        end_entity_cert = self._load_cert_object(
            'name_constraints', end_entity_filename
        )
        intermediate_certs = [
            self._load_cert_object('name_constraints', filename)
            for filename in intermediate_filenames
        ]
        trust_roots = [self._load_cert_object('name_constraints', 'nc_root.crt')]

        context = ValidationContext(
            trust_roots=trust_roots,
            other_certs=intermediate_certs,
            revocation_mode='soft-fail'
        )
        paths = context.certificate_registry.build_paths(end_entity_cert)
        self.assertEqual(1, len(paths))
        return validate_path(context, paths[0])

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

    def test_name_constraints_permitted_dns_san_accepted(self):
        cert = self._validate_nc_path('ee_dns_good.crt', ['nc_dns_ca.crt'])
        self.assertEqual('good.example.com', cert.subject_alt_name_value[0].native)

    def test_name_constraints_dns_san_violation_rejected(self):
        with self.assertRaisesRegex(PathValidationError, 'permitted subtrees'):
            self._validate_nc_path('ee_dns_evil.crt', ['nc_dns_ca.crt'])

    def test_name_constraints_common_name_checked_without_san(self):
        # The end-entity has no SAN extension, so the CN must still be
        # normalized and checked against the accumulated DNS constraints.
        cert = self._validate_nc_path('ee_cn_good.crt', ['nc_dns_ca.crt'])
        self.assertIsNone(cert.subject_alt_name_value)

    def test_name_constraints_idna_a_label_normalized(self):
        # An A-label SAN under a punycode permitted subtree is accepted.
        self._validate_nc_path('ee_idna_good.crt', ['nc_dns_ca.crt'])

    def test_name_constraints_idna_u_label_normalized(self):
        # The SAN stores a raw U-label while the constraint uses an A-label;
        # both sides must be IDNA-normalized before comparison instead of the
        # un-decodable name causing an indeterminate result.
        self._validate_nc_path('ee_idna_ulabel.crt', ['nc_idna_ca.crt'])

    def test_name_constraints_permitted_ip_san_accepted(self):
        self._validate_nc_path('ee_ip_good.crt', ['nc_ip_ca.crt'])

    def test_name_constraints_ip_san_violation_rejected(self):
        with self.assertRaisesRegex(PathValidationError, 'permitted subtrees'):
            self._validate_nc_path('ee_ip_bad.crt', ['nc_ip_ca.crt'])

    def test_name_constraints_excluded_dns_subtree_rejected(self):
        with self.assertRaisesRegex(PathValidationError, 'excluded subtree'):
            self._validate_nc_path('ee_excluded.crt', ['nc_excluded_dns_ca.crt'])

    def test_name_constraints_uri_san_normalized_and_accepted(self):
        # The URI constraint uses a leading-dot host subtree; only the host
        # component of the SAN URI is extracted, normalized and compared.
        cert = self._validate_nc_path('ee_uri_good.crt', ['nc_uri_ca.crt'])
        self.assertEqual(
            'uniform_resource_identifier',
            cert.subject_alt_name_value[0].name
        )

    def test_eku_intersection_conflict_rejected(self):
        # The CA only allows clientAuth/emailProtection while the end-entity
        # asserts serverAuth, so the accumulated EKU intersection is empty.
        with self.assertRaisesRegex(PathValidationError, 'extended key'):
            self._validate_nc_path('ee_eku_conflict.crt', ['nc_eku_ca.crt'])

    def test_missing_extension_is_not_universal_permission(self):
        # A certificate without a SAN must not bypass DNS name constraints:
        # an out-of-constraint CN is a violation, not an implicit allow.
        end_entity_cert = self._load_cert_object(
            'name_constraints', 'ee_dns_evil.crt'
        )
        intermediate_certs = [
            self._load_cert_object('name_constraints', 'nc_dns_ca.crt')
        ]
        context = ValidationContext(
            trust_roots=[self._load_cert_object('name_constraints', 'nc_root.crt')],
            other_certs=intermediate_certs,
            revocation_mode='soft-fail'
        )
        path = context.certificate_registry.build_paths(end_entity_cert)[0]
        with self.assertRaises(PathValidationError):
            validate_path(context, path)

    def test_indeterminate_name_constraint_is_distinct_from_violation(self):
        # An IP subtree whose encoded length is not 4, 8, 16 or 32 bytes can
        # not be evaluated, so validation reports an indeterminate result
        # rather than treating the constraint as allowed or as a violation.
        from certvalidator._name_constraints import (
            NameConstraintIndeterminate,
            NameConstraintViolation,
            _normalize_ip_constraint,
        )

        with self.assertRaises(NameConstraintIndeterminate):
            _normalize_ip_constraint(b'\x01\x02\x03')

        # The internal indeterminate signal is distinct from hard violations,
        # while the public error still participates in the validation error
        # hierarchy so callers can handle the outcome uniformly.
        self.assertFalse(issubclass(NameConstraintIndeterminate, NameConstraintViolation))
        self.assertTrue(issubclass(PathValidationIndeterminateError, PathValidationError))

    def test_indeterminate_result_raised_for_unevaluable_ip_constraint(self):
        # Replace the DNS CA's nameConstraints extension with one containing an
        # IP subtree whose encoded length is unsupported. The path can not be
        # judged allowed or in violation, so an indeterminate error is raised.
        trust_anchor = self._load_cert_object('name_constraints', 'nc_root.crt')
        malformed_subtree = x509.GeneralSubtree.load(
            b'\x30\x05\x87\x03\x01\x02\x03'
        )
        malformed_constraints = x509.NameConstraints()
        malformed_constraints['permitted_subtrees'] = [malformed_subtree]
        malformed_extension = x509.Extension({
            'extn_id': 'name_constraints',
            'critical': True,
            'extn_value': malformed_constraints,
        })

        tbs = trust_anchor['tbs_certificate']
        extensions = tbs['extensions'].copy()
        extensions.append(malformed_extension)
        tbs['extensions'] = extensions

        end_entity_cert = self._load_cert_object('name_constraints', 'ee_dns_good.crt')
        constrained_ca = self._load_cert_object('name_constraints', 'nc_dns_ca.crt')
        context = ValidationContext(
            trust_roots=[trust_anchor],
            other_certs=[constrained_ca],
            revocation_mode='soft-fail'
        )
        path = context.certificate_registry.build_paths(end_entity_cert)[0]
        with self.assertRaises(PathValidationIndeterminateError):
            validate_path(context, path)
