#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Tests for explicit, sanitized private-key loading."""

import os
import stat
import tempfile
import unittest
import warnings

from pyasn1.codec.der import decoder, encoder

import rsa.key
import rsa.pem


TEST_DIR = os.path.dirname(__file__)
PASSPHRASE = "pw"


def _fixture(name):
    with open(os.path.join(TEST_DIR, name), "rb") as fixture:
        return fixture.read()


def _tamper_pkcs8_crt(pem_data):
    der = rsa.pem.load_pem(pem_data, "PRIVATE KEY")
    key_info, _ = decoder.decode(der)
    private_key, _ = decoder.decode(bytes(key_info[2]))
    private_key[7] = int(private_key[7]) + 1
    key_info[2] = encoder.encode(private_key)
    return rsa.pem.save_pem(encoder.encode(key_info), "PRIVATE KEY")


class PrivateKeyLoadingTest(unittest.TestCase):
    def setUp(self):
        self.plain_pkcs8 = _fixture("private_pkcs8.pem")
        self.encrypted_pkcs8 = _fixture("private_pkcs8_encrypted.pem")
        self.empty_passphrase_pkcs8 = _fixture("private_pkcs8_encrypted_empty.pem")
        self.encrypted_pkcs1 = _fixture("private_pkcs1_encrypted.pem")
        self.expected = rsa.PrivateKey.load_pkcs1(self.plain_pkcs8)

    def test_load_pkcs8_plain(self):
        key = rsa.PrivateKey.load_pkcs1(self.plain_pkcs8)
        self.assertEqual(self.expected, key)

    def test_load_encrypted_pkcs8_with_str_and_bytes(self):
        from_str = rsa.PrivateKey.load_pkcs1(self.encrypted_pkcs8, passphrase=PASSPHRASE)
        from_bytes = rsa.PrivateKey.load_pkcs1(
            self.encrypted_pkcs8,
            passphrase=PASSPHRASE.encode("utf-8"),
        )
        self.assertEqual(self.expected, from_str)
        self.assertEqual(self.expected, from_bytes)

    def test_load_traditional_encrypted_pkcs1(self):
        key = rsa.PrivateKey.load_pkcs1(self.encrypted_pkcs1, passphrase=PASSPHRASE)
        self.assertEqual(self.expected, key)

    def test_empty_passphrase_is_still_a_passphrase(self):
        key = rsa.PrivateKey.load_pkcs1(self.empty_passphrase_pkcs8, passphrase=b"")
        self.assertEqual(self.expected, key)

    def test_missing_passphrase_is_classified(self):
        with self.assertRaises(rsa.key.PassphraseRequiredError):
            rsa.PrivateKey.load_pkcs1(self.encrypted_pkcs8)
        with self.assertRaises(rsa.key.MissingPassphraseError):
            rsa.PrivateKey.load_pkcs1(self.encrypted_pkcs1)

    def test_wrong_passphrase_is_classified_and_sanitized(self):
        secret = "never-print-this-passphrase"
        with self.assertRaises(rsa.key.IncorrectPassphraseError) as caught:
            rsa.PrivateKey.load_pkcs1(self.encrypted_pkcs8, passphrase=secret)

        message = str(caught.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn(str(self.expected.p), message)
        self.assertNotIn(str(self.expected.d), message)
        self.assertNotIn("BEGIN ENCRYPTED PRIVATE KEY", message)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", message)

    def test_wrong_passphrase_traditional_is_classified(self):
        with self.assertRaises(rsa.key.WrongPassphraseError):
            rsa.PrivateKey.load_pkcs1(self.encrypted_pkcs1, passphrase="wrong")

    def test_passphrase_type_and_size_limits(self):
        with self.assertRaises(rsa.key.PassphraseTypeError):
            rsa.PrivateKey.load_pkcs1(
                self.encrypted_pkcs8,
                passphrase=1234,  # type: ignore[arg-type]
            )
        with self.assertRaises(rsa.key.PassphraseTooLongError):
            rsa.PrivateKey.load_pkcs1(
                self.encrypted_pkcs8,
                passphrase=PASSPHRASE,
                max_passphrase_size=1,
            )

    def test_bad_base64_is_classified(self):
        malformed = (
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"definitely-not-base64!\n"
            b"-----END RSA PRIVATE KEY-----\n"
        )
        with self.assertRaises(rsa.key.PEMBase64Error):
            rsa.PrivateKey.load_pkcs1(malformed)

    def test_wrong_pem_label_is_classified(self):
        wrong_label = self.plain_pkcs8.replace(b"PRIVATE KEY", b"PUBLIC KEY")
        with self.assertRaises(rsa.key.PEMLabelError):
            rsa.PrivateKey.load_pkcs1(wrong_label)

    def test_crt_inconsistency_is_rejected(self):
        damaged = _tamper_pkcs8_crt(self.plain_pkcs8)
        with self.assertRaises(rsa.key.CRTConsistencyError):
            rsa.PrivateKey.load_pkcs1(damaged)

    def test_permissions_warning_does_not_modify_file(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "private.pem")
            with open(filename, "wb") as private_key:
                private_key.write(self.plain_pkcs8)
            os.chmod(filename, 0o644)
            mode_before = stat.S_IMODE(os.stat(filename).st_mode)

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                key = rsa.PrivateKey.load_pkcs1_file(
                    filename,
                    check_file_permissions=True,
                )

            self.assertEqual(self.expected, key)
            self.assertEqual(mode_before, stat.S_IMODE(os.stat(filename).st_mode))
            self.assertTrue(
                any(
                    issubclass(warning.category, rsa.key.PrivateKeyPermissionWarning)
                    for warning in caught
                )
            )

    def test_source_path_checks_permissions_without_reading_it(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "permissions-only.pem")
            with open(filename, "wb") as unrelated_file:
                unrelated_file.write(b"not a private key")
            os.chmod(filename, 0o644)

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                key = rsa.PrivateKey.load_pkcs1(
                    self.plain_pkcs8,
                    check_file_permissions=True,
                    source_path=filename,
                )

            self.assertEqual(self.expected, key)
            self.assertTrue(
                any(
                    issubclass(warning.category, rsa.key.PrivateKeyPermissionWarning)
                    for warning in caught
                )
            )

    def test_policy_repr_redacts_passphrase(self):
        secret = "policy-secret-value"
        policy = rsa.key.PrivateKeyLoadPolicy(passphrase=secret, check_permissions=True)
        self.assertNotIn(secret, repr(policy))
        self.assertIn("<redacted>", repr(policy))

    def test_policy_object_route(self):
        policy = rsa.key.PrivateKeyLoadPolicy(
            passphrase=PASSPHRASE,
            max_passphrase_length=64,
        )
        key = rsa.PrivateKey.load_pkcs1(self.encrypted_pkcs8, policy=policy)
        self.assertEqual(self.expected, key)


if __name__ == "__main__":
    unittest.main()
