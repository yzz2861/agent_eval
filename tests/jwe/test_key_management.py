import warnings
from unittest import TestCase

from joserfc import jwe
from joserfc.errors import (
    InvalidKeyCurveError,
    InvalidKeyLengthError,
    InvalidKeyTypeError,
)
from joserfc.jwe import GeneralJSONEncryption
from joserfc.jwk import ECKey, OctKey, OKPKey, RSAKey


class TestJWEKeyManagementValidation(TestCase):
    def setUp(self):
        self.rsa_key = RSAKey.generate_key()
        self.ec_key = ECKey.generate_key("P-256")
        self.ed25519_key = OKPKey.generate_key("Ed25519")
        self.x25519_key = OKPKey.generate_key("X25519")
        self.oct_128 = OctKey.generate_key(128)
        self.oct_256 = OctKey.generate_key(256)

    def assert_key_error(self, error, alg, key, enc="A128GCM"):
        protected = {"alg": alg, "enc": enc}
        with self.assertRaises(error):
            jwe.encrypt_compact(protected, b"hello", key, algorithms=[alg, enc])

    def test_direct_mode_rejects_non_oct_key(self):
        # "dir" only works with symmetric keys; an RSA key must be rejected
        self.assert_key_error(InvalidKeyTypeError, "dir", self.rsa_key)
        self.assert_key_error(InvalidKeyTypeError, "dir", self.ec_key)

    def test_direct_mode_checks_enc_key_length(self):
        # A128GCM requires a 128-bit CEK, the shared key length MUST match "enc"
        self.assert_key_error(InvalidKeyLengthError, "dir", self.oct_256, enc="A128GCM")
        # a matching key still round-trips instead of falling back to a default
        value = jwe.encrypt_compact({"alg": "dir", "enc": "A128GCM"}, b"hello", self.oct_128)
        obj = jwe.decrypt_compact(value, self.oct_128)
        self.assertEqual(obj.plaintext, b"hello")

    def test_rsa15_rejects_non_rsa_key(self):
        for key in (self.oct_128, self.ec_key, self.ed25519_key):
            self.assert_key_error(InvalidKeyTypeError, "RSA1_5", key)

    def test_rsa15_rejects_short_rsa_key(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            short_key = RSAKey.generate_key(1024)
        self.assert_key_error(InvalidKeyLengthError, "RSA1_5", short_key)

    def test_ecdh_es_rejects_non_ec_key(self):
        self.assert_key_error(InvalidKeyTypeError, "ECDH-ES", self.oct_128)
        self.assert_key_error(InvalidKeyTypeError, "ECDH-ES", self.rsa_key)

    def test_ecdh_es_rejects_signature_only_curve(self):
        # Ed25519 is an OKP key but can not perform ECDH key agreement
        self.assert_key_error(InvalidKeyCurveError, "ECDH-ES", self.ed25519_key)
        self.assert_key_error(InvalidKeyCurveError, "ECDH-ES+A128KW", self.ed25519_key)

    def test_ecdh_es_accepts_key_agreement_curves(self):
        for key in (self.ec_key, self.x25519_key):
            value = jwe.encrypt_compact({"alg": "ECDH-ES", "enc": "A128GCM"}, b"hello", key)
            obj = jwe.decrypt_compact(value, key)
            self.assertEqual(obj.plaintext, b"hello")

    def test_a128kw_rejects_oct_key_with_wrong_length(self):
        self.assert_key_error(InvalidKeyTypeError, "A128KW", self.rsa_key)
        self.assert_key_error(InvalidKeyTypeError, "A128KW", self.ec_key)
        self.assert_key_error(InvalidKeyLengthError, "A128KW", self.oct_256)

        value = jwe.encrypt_compact({"alg": "A128KW", "enc": "A128GCM"}, b"hello", self.oct_128)
        obj = jwe.decrypt_compact(value, self.oct_128)
        self.assertEqual(obj.plaintext, b"hello")

    def test_decrypt_validates_key_management_mode(self):
        # a valid "dir" token can not be decrypted with an RSA key
        dir_value = jwe.encrypt_compact({"alg": "dir", "enc": "A128GCM"}, b"hello", self.oct_128)
        with self.assertRaises(InvalidKeyTypeError):
            jwe.decrypt_compact(dir_value, self.rsa_key)

        # A128KW rejects a wrapping key whose length does not match the alg
        kw_value = jwe.encrypt_compact({"alg": "A128KW", "enc": "A128GCM"}, b"hello", self.oct_128)
        with self.assertRaises(InvalidKeyLengthError):
            jwe.decrypt_compact(kw_value, self.oct_256)

        # ECDH-ES rejects a signature-only OKP curve on the decrypt side
        ecdh_value = jwe.encrypt_compact({"alg": "ECDH-ES", "enc": "A128GCM"}, b"hello", self.ec_key)
        with self.assertRaises(InvalidKeyCurveError):
            jwe.decrypt_compact(ecdh_value, self.ed25519_key)

    def test_json_serialization_validates_each_recipient(self):
        obj = GeneralJSONEncryption({"enc": "A128GCM"}, b"hello")
        obj.add_recipient({"alg": "RSA-OAEP"}, self.rsa_key)
        obj.add_recipient({"alg": "ECDH-ES+A128KW"}, self.ec_key)
        value = jwe.encrypt_json(obj, None)

        # the RSA key does not match the ECDH-ES recipient; strict verification fails
        with self.assertRaises(InvalidKeyTypeError):
            jwe.decrypt_json(value, self.rsa_key)

        # with verify_all_recipients disabled, the matching recipient still decrypts
        registry = jwe.JWERegistry(verify_all_recipients=False)
        decrypted = jwe.decrypt_json(value, self.rsa_key, registry=registry)
        self.assertEqual(decrypted.plaintext, b"hello")
