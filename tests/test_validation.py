# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest

from asn1crypto import algos, core, csr, keys, pem, x509
from asn1crypto import _validation as validation
from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')
keys_dir = os.path.join(fixtures_dir, 'keys')


def _load(path):
    with open(path, 'rb') as f:
        data = f.read()
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return data


class ErrorHierarchyTests(unittest.TestCase):

    def test_all_errors_share_base(self):
        for cls in (
            validation.UnknownAlgorithmError,
            validation.MissingParametersError,
            validation.DuplicateParametersError,
            validation.ParameterConflictError,
            validation.InvalidParametersError,
            validation.KeySizeError,
            validation.KeyUsageMismatchError,
        ):
            self.assertTrue(issubclass(cls, validation.AlgorithmValidationError))
            self.assertTrue(issubclass(cls, ValueError))


class EcBindingTests(unittest.TestCase):

    def setUp(self):
        self.public_key_info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-ec-named-der.key'))
        )

    def test_named_curve_validates(self):
        # secp256r1 is an RFC 5480 named curve with an uncompressed point.
        self.assertIs(
            self.public_key_info,
            validation.validate_public_key(self.public_key_info)
        )
        self.assertIs(self.public_key_info, self.public_key_info.validate())

    def test_secp256k1_rejected(self):
        self.public_key_info['algorithm']['parameters'] = core.ObjectIdentifier('1.3.132.0.10')
        with self.assertRaises(validation.InvalidParametersError) as cm:
            validation.validate_public_key(self.public_key_info)
        self.assertEqual('1.3.132.0.10', cm.exception.oid)
        # The message must name the offending curve OID, not any key material.
        self.assertIn('1.3.132.0.10', str(cm.exception))

    def test_unknown_curve_oid_classified(self):
        self.public_key_info['algorithm']['parameters'] = core.ObjectIdentifier('1.2.3.4.5.6.7.8.9')
        with self.assertRaises(validation.UnknownAlgorithmError) as cm:
            validation.validate_public_key(self.public_key_info)
        self.assertEqual('1.2.3.4.5.6.7.8.9', cm.exception.oid)

    def test_missing_curve_rejected(self):
        # A missing curve must never cause a backend to assume a default.
        del self.public_key_info['algorithm']['parameters']
        with self.assertRaises(validation.MissingParametersError) as cm:
            validation.validate_public_key(self.public_key_info)
        self.assertEqual('1.2.840.10045.2.1', cm.exception.oid)
        self.assertEqual('Void', cm.exception.parameter_type)

    def test_implicit_ca_curve_rejected(self):
        domain = keys.ECDomainParameters(name='implicit_ca', value=core.Null())
        self.public_key_info['algorithm']['parameters'] = domain
        with self.assertRaises(validation.MissingParametersError):
            validation.validate_public_key(self.public_key_info)

    def test_wrong_length_point_rejected(self):
        point = self.public_key_info['public_key']
        self.public_key_info['public_key'] = keys.ECPointBitString(point.native[:-1])
        with self.assertRaises(validation.InvalidParametersError) as cm:
            validation.validate_public_key(self.public_key_info)
        self.assertNotIn(str(point.native), str(cm.exception))

    def test_compressed_point_rejected(self):
        point = self.public_key_info['public_key']
        compressed = b'\x02' + point.native[1:33]
        self.public_key_info['public_key'] = keys.ECPointBitString(compressed)
        with self.assertRaises(validation.InvalidParametersError):
            validation.validate_public_key(self.public_key_info)

    def test_explicit_domain_params_strict_only(self):
        explicit = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-ec-der.key'))
        )
        # Explicit parameters remain acceptable outside strict mode.
        validation.validate_public_key(explicit, strict=False)
        with self.assertRaises(validation.InvalidParametersError):
            validation.validate_public_key(explicit, strict=True)


class RsaBindingTests(unittest.TestCase):

    def setUp(self):
        self.public_key_info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-der.key'))
        )

    def test_valid_rsa_key(self):
        validation.validate_public_key(self.public_key_info, strict=False)
        validation.validate_public_key(self.public_key_info, strict=True)

    def test_short_rsa_strict_only(self):
        short_key = keys.RSAPublicKey({
            'modulus': 2 ** 512 - 1,
            'public_exponent': 65537,
        })
        info = keys.PublicKeyInfo.wrap(short_key, 'rsa')
        # Legacy-sized keys still validate with default settings.
        validation.validate_public_key(info, strict=False)
        with self.assertRaises(validation.KeySizeError) as cm:
            validation.validate_public_key(info, strict=True)
        self.assertEqual('1.2.840.113549.1.1.1', cm.exception.oid)
        self.assertIn('512', str(cm.exception))

    def test_invalid_exponent_rejected(self):
        bad_key = keys.RSAPublicKey({
            'modulus': 2 ** 2048 - 1,
            'public_exponent': 2,
        })
        info = keys.PublicKeyInfo.wrap(bad_key, 'rsa')
        with self.assertRaises(validation.InvalidParametersError):
            validation.validate_public_key(info)

    def test_pss_key_with_params(self):
        pss_info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-rsapss-der.key'))
        )
        # The fixture omits explicit parameters, which is allowed by default
        # but rejected in strict mode.
        validation.validate_public_key(pss_info, strict=False)
        with self.assertRaises(validation.MissingParametersError):
            validation.validate_public_key(pss_info, strict=True)

    def test_pss_key_with_explicit_params_validates(self):
        params = algos.RSASSAPSSParams({
            'hash_algorithm': {'algorithm': 'sha256'},
            'mask_gen_algorithm': {
                'algorithm': 'mgf1',
                'parameters': {'algorithm': 'sha256'},
            },
            'salt_length': 32,
            'trailer_field': 1,
        })
        info = keys.PublicKeyInfo()
        info['algorithm'] = keys.PublicKeyAlgorithm({'algorithm': 'rsassa_pss'})
        info['algorithm']['parameters'] = params
        info['public_key'] = self.public_key_info['public_key']
        validation.validate_public_key(info, strict=False)
        validation.validate_public_key(info, strict=True)


class DsaBindingTests(unittest.TestCase):

    def test_complete_dsa_params_validate(self):
        info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-dsa-der.key'))
        )
        validation.validate_public_key(info, strict=False)
        validation.validate_public_key(info, strict=True)

    def test_inherited_dsa_params_strict_only(self):
        cert = x509.Certificate.load(
            _load(os.path.join(fixtures_dir, 'DSAParametersInheritedCACert.crt'))
        )
        info = cert.public_key
        # Inherited parameters are accepted for default verification parsing.
        validation.validate_public_key(info, strict=False)
        with self.assertRaises(validation.MissingParametersError):
            validation.validate_public_key(info, strict=True)

    def test_incomplete_dsa_params_rejected(self):
        info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-dsa-der.key'))
        )
        info['algorithm']['parameters']['q'] = core.Integer(0)
        with self.assertRaises(validation.InvalidParametersError):
            validation.validate_public_key(info)


class EddsaBindingTests(unittest.TestCase):

    def setUp(self):
        cert = x509.Certificate.load(_load(os.path.join(keys_dir, 'test-ed25519.crt')))
        self.public_key_info = cert.public_key

    def test_ed25519_without_params_validates(self):
        validation.validate_public_key(self.public_key_info)

    def test_ed25519_with_null_params_rejected(self):
        self.public_key_info['algorithm']['parameters'] = core.Null()
        with self.assertRaises(validation.ParameterConflictError) as cm:
            validation.validate_public_key(self.public_key_info)
        self.assertEqual('1.3.101.112', cm.exception.oid)
        self.assertEqual('Null', cm.exception.parameter_type)

    def test_ed25519_with_typed_params_rejected(self):
        self.public_key_info['algorithm']['parameters'] = core.OctetString(b'\x01')
        with self.assertRaises(validation.ParameterConflictError) as cm:
            validation.validate_public_key(self.public_key_info)
        self.assertEqual('OctetString', cm.exception.parameter_type)

    def test_ed25519_signature_algorithm_with_params_rejected(self):
        signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'ed25519'})
        validation.validate_signed_digest_algorithm(signature_algorithm)
        signature_algorithm['parameters'] = core.OctetString(b'\x02')
        with self.assertRaises(validation.ParameterConflictError):
            validation.validate_signed_digest_algorithm(signature_algorithm)


class AlgorithmIdentifierTests(unittest.TestCase):

    def test_unknown_oid_parses_but_verification_rejects(self):
        signature_algorithm = algos.SignedDigestAlgorithm()
        signature_algorithm['algorithm'] = algos.SignedDigestAlgorithmId('1.2.3.4.5.6.7.8.9')
        encoded = signature_algorithm.dump()
        # Default parsing must still round-trip unknown algorithms.
        parsed = algos.SignedDigestAlgorithm.load(encoded)
        self.assertEqual(encoded, parsed.dump())
        self.assertEqual('1.2.3.4.5.6.7.8.9', parsed['algorithm'].dotted)
        with self.assertRaises(validation.UnknownAlgorithmError) as cm:
            validation.validate_signed_digest_algorithm(signature_algorithm)
        self.assertEqual('1.2.3.4.5.6.7.8.9', cm.exception.oid)

    def test_non_null_params_on_null_only_oid(self):
        # The typed parser enforces the NULL tag at parse time, so a wrong
        # parameter type on a NULL-only OID is rejected while still parsing
        # the OID itself. The validation layer reports the policy conflict for
        # any value that does reach it with a non-NULL Any parameter.
        generic = algos.AlgorithmIdentifier()
        generic['algorithm'] = algos.DigestAlgorithmId('sha256')
        generic['parameters'] = core.OctetString(b'\x01')
        # Parsing is lazy; the tag conflict is raised when the parameter is
        # materialized against the OID's required NULL spec.
        parsed = algos.DigestAlgorithm.load(generic.dump())
        with self.assertRaises(ValueError):
            parsed['parameters'].native

    def test_missing_null_params_strict_only(self):
        raw = algos.SignedDigestAlgorithm.load(
            algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}).dump()
        )
        del raw['parameters']
        validation.validate_signed_digest_algorithm(raw, strict=False)
        with self.assertRaises(validation.MissingParametersError) as cm:
            validation.validate_signed_digest_algorithm(raw, strict=True)
        self.assertEqual('1.2.840.113549.1.1.11', cm.exception.oid)
        self.assertEqual('Void', cm.exception.parameter_type)

    def test_pss_null_parameters_strict_only(self):
        # An RSASSA-PSS OID with no explicit parameters is accepted by default
        # but rejected in strict mode since the parameters must be explicit.
        signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pss'})
        validation.validate_signed_digest_algorithm(signature_algorithm, strict=False)
        with self.assertRaises(validation.MissingParametersError):
            validation.validate_signed_digest_algorithm(signature_algorithm, strict=True)

    def test_pss_with_full_params_validates(self):
        params = algos.RSASSAPSSParams({
            'hash_algorithm': {'algorithm': 'sha256'},
            'mask_gen_algorithm': {
                'algorithm': 'mgf1',
                'parameters': {'algorithm': 'sha256'},
            },
            'salt_length': 32,
            'trailer_field': 1,
        })
        signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pss'})
        signature_algorithm['parameters'] = params
        self.assertIs(
            signature_algorithm,
            signature_algorithm.validate(strict=True)
        )

    def test_validate_method_entry_point(self):
        signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
        self.assertIs(signature_algorithm, signature_algorithm.validate())
        signature_algorithm['algorithm'] = algos.SignedDigestAlgorithmId('1.2.3.4.5.6.7.8.9')
        with self.assertRaises(validation.UnknownAlgorithmError):
            signature_algorithm.validate()

    def test_ber_encoded_null_parameter_accepted(self):
        # Real-world certificates sometimes encode NULL parameters through an
        # unparsed Any value; these must be recognized as NULL.
        certificate = x509.Certificate.load(
            _load(os.path.join(fixtures_dir, 'chromium/ndn.ca.crt'))
        )
        validation.validate_signed_digest_algorithm(
            certificate['signature_algorithm']
        )


class DuplicateParametersTests(unittest.TestCase):

    def _pss_algorithm(self, hash_name, mgf_name):
        params = algos.RSASSAPSSParams({
            'hash_algorithm': {'algorithm': hash_name},
            'mask_gen_algorithm': {
                'algorithm': 'mgf1',
                'parameters': {'algorithm': mgf_name},
            },
            'salt_length': 32,
            'trailer_field': 1,
        })
        signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pss'})
        signature_algorithm['parameters'] = params
        return signature_algorithm

    def test_consistent_digests_validate(self):
        signature_algorithm = self._pss_algorithm('sha256', 'sha256')
        validation.validate_signed_digest_algorithm(
            signature_algorithm, strict=True
        )

    def test_conflicting_digests_classified_as_duplicate(self):
        signature_algorithm = self._pss_algorithm('sha256', 'sha1')
        with self.assertRaises(validation.DuplicateParametersError) as cm:
            validation.validate_signed_digest_algorithm(
                signature_algorithm, strict=True
            )
        self.assertEqual('1.2.840.113549.1.1.10', cm.exception.oid)
        self.assertEqual('RSASSAPSSParams', cm.exception.parameter_type)


class KeyUsageTests(unittest.TestCase):

    def setUp(self):
        self.certificate = x509.Certificate.load(
            _load(os.path.join(fixtures_dir, 'admin.ch.crt'))
        )

    def test_permitted_usage(self):
        validation.validate_certificate(self.certificate, usage='sign')

    def test_mismatched_usage(self):
        with self.assertRaises(validation.KeyUsageMismatchError) as cm:
            validation.validate_certificate(self.certificate, usage='cert_sign')
        self.assertEqual('KeyUsage', cm.exception.parameter_type)
        self.assertNotIn('BEGIN', str(cm.exception))

    def test_missing_key_usage_allows_operation(self):
        certificate = x509.Certificate.load(
            _load(os.path.join(keys_dir, 'test-der.crt'))
        )
        self.assertIsNone(certificate.key_usage_value)
        validation.validate_certificate(certificate, usage='cert_sign')

    def test_native_set_accepted(self):
        validation.validate_key_usage(set(['key_cert_sign']), 'cert_sign')
        with self.assertRaises(validation.KeyUsageMismatchError):
            validation.validate_key_usage(set(['crl_sign']), 'cert_sign')

    def test_unknown_operation_raises_value_error(self):
        with self.assertRaises(ValueError):
            validation.validate_key_usage(None, 'not_a_real_operation')


class CertificateAndCsrTests(unittest.TestCase):

    def test_real_certificates_validate_non_strict(self):
        relative_paths = [
            'admin.ch.crt',
            'rfc3739.crt',
            'sender_dummycorp.com.crt',
            'chromium/ndn.ca.crt',
            'keys/test-der.crt',
            'keys/test-ec-named-der.crt',
            'keys/test-ed25519.crt',
            'keys/test-ed448.crt',
            'keys/test-rsapss.crt',
        ]
        for relative_path in relative_paths:
            certificate = x509.Certificate.load(
                _load(os.path.join(fixtures_dir, relative_path))
            )
            self.assertIs(certificate, certificate.validate())

    def test_certificate_validate_returns_certificate(self):
        certificate = x509.Certificate.load(
            _load(os.path.join(keys_dir, 'test-der.crt'))
        )
        self.assertIs(certificate, validation.validate_certificate(certificate))
        self.assertIs(certificate, certificate.validate(strict=True))

    def test_csr_validate(self):
        request = csr.CertificationRequest.load(
            _load(os.path.join(fixtures_dir, 'test-inter-der.csr'))
        )
        self.assertIs(request, request.validate())
        self.assertIs(request, validation.validate_csr(request))

    def test_errors_do_not_leak_key_material(self):
        info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-ec-named-der.key'))
        )
        point_bytes = info['public_key'].native
        info['algorithm']['parameters'] = core.ObjectIdentifier('1.3.132.0.10')
        with self.assertRaises(validation.AlgorithmValidationError) as cm:
            validation.validate_public_key(info)
        self.assertNotIn(repr(point_bytes), str(cm.exception))
        self.assertNotIn(str(point_bytes), str(cm.exception))


class PrivateKeyInfoTests(unittest.TestCase):

    def test_private_key_variants_validate(self):
        relative_paths = [
            'test-pkcs8-der.key',
            'test-pkcs8-dsa-der.key',
            'test-pkcs8-ec-named-der.key',
            'test-rsapss-der.key',
        ]
        for relative_path in relative_paths:
            info = keys.PrivateKeyInfo.load(
                _load(os.path.join(keys_dir, relative_path))
            )
            self.assertIs(info, validation.validate_private_key(info))
            self.assertIs(info, info.validate())

    def test_ed25519_private_key_validates(self):
        info = keys.PrivateKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-ed25519.key'))
        )
        validation.validate_private_key(info)

    def test_ed25519_private_key_with_params_rejected(self):
        info = keys.PrivateKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-ed25519.key'))
        )
        info['private_key_algorithm']['parameters'] = core.Null()
        with self.assertRaises(validation.ParameterConflictError) as cm:
            validation.validate_private_key(info)
        self.assertEqual('1.3.101.112', cm.exception.oid)

    def test_ec_explicit_params_private_key_strict_only(self):
        info = keys.PrivateKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-pkcs8-ec-der.key'))
        )
        validation.validate_private_key(info, strict=False)
        with self.assertRaises(validation.InvalidParametersError):
            validation.validate_private_key(info, strict=True)


class DefaultParsingUnchangedTests(unittest.TestCase):

    def test_unknown_algorithm_round_trip(self):
        original = algos.SignedDigestAlgorithm()
        original['algorithm'] = algos.SignedDigestAlgorithmId('1.2.3.4.5.6.7.8.9')
        parsed = algos.SignedDigestAlgorithm.load(original.dump())
        self.assertEqual(original.dump(), parsed.dump())

    def test_explicit_ec_curve_still_parses(self):
        info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-ec-der.key'))
        )
        self.assertEqual('specified', info['algorithm']['parameters'].name)

    def test_rsa_pss_fixture_mapping_unchanged(self):
        info = keys.PublicKeyInfo.load(
            _load(os.path.join(keys_dir, 'test-public-rsapss-der.key'))
        )
        self.assertEqual('rsassa_pss', info.algorithm)
        self.assertIsNone(info['algorithm']['parameters'].native)
