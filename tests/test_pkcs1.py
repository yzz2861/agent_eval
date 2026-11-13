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

"""Tests string operations."""

import struct
import sys
import typing
import unittest

import rsa
from rsa import asn1, pkcs1


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    content: typing.List[int] = []
    while length:
        content.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(content)]) + bytes(content)


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _digest_info(algorithm_contents: bytes, digest: bytes) -> bytes:
    digest_algorithm = _der_tlv(asn1.TAG_SEQUENCE, algorithm_contents)
    octet_string = _der_tlv(asn1.TAG_OCTET_STRING, digest)
    return _der_tlv(asn1.TAG_SEQUENCE, digest_algorithm + octet_string)


def _algorithm_contents(oid_der: bytes, parameters: bytes = b"\x05\x00") -> bytes:
    return _der_tlv(asn1.TAG_OBJECT_IDENTIFIER, oid_der) + parameters


# OBJECT IDENTIFIER content bytes (without the 0x06 tag and length) for hashes.
OID_MD5_DER = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05])
OID_SHA1_DER = bytes([0x2B, 0x0E, 0x03, 0x02, 0x1A])
OID_SHA256_DER = bytes(
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
)


def _raw_sign(
    priv: rsa.PrivateKey,
    digest_info: bytes,
    padding_length: typing.Optional[int] = None,
) -> bytes:
    """Builds a PKCS#1 v1.5 signature over arbitrary DigestInfo bytes."""

    keylength = rsa.common.byte_size(priv.n)
    if padding_length is None:
        padding_length = keylength - len(digest_info) - 3
    if padding_length < 0:
        raise ValueError("DigestInfo does not fit inside the key")
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    if len(encoded) != keylength:
        raise ValueError("encoded message does not match the key length")
    payload = rsa.transform.bytes2int(encoded)
    encrypted = priv.blinded_decrypt(payload)
    return rsa.transform.int2bytes(encrypted, keylength)


class BinaryTest(unittest.TestCase):
    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(256)

    def test_enc_dec(self):
        message = struct.pack(">IIII", 0, 0, 0, 1)
        print("\n\tMessage:   %r" % message)

        encrypted = pkcs1.encrypt(message, self.pub)
        print("\tEncrypted: %r" % encrypted)

        decrypted = pkcs1.decrypt(encrypted, self.priv)
        print("\tDecrypted: %r" % decrypted)

        self.assertEqual(message, decrypted)

    def test_decoding_failure(self):
        message = struct.pack(">IIII", 0, 0, 0, 1)
        encrypted = pkcs1.encrypt(message, self.pub)

        # Alter the encrypted stream
        a = encrypted[5]
        self.assertIsInstance(a, int)

        altered_a = (a + 1) % 256
        encrypted = encrypted[:5] + bytes([altered_a]) + encrypted[6:]

        self.assertRaises(pkcs1.DecryptionError, pkcs1.decrypt, encrypted, self.priv)

    def test_randomness(self):
        """Encrypting the same message twice should result in different
        cryptos.
        """

        message = struct.pack(">IIII", 0, 0, 0, 1)
        encrypted1 = pkcs1.encrypt(message, self.pub)
        encrypted2 = pkcs1.encrypt(message, self.pub)

        self.assertNotEqual(encrypted1, encrypted2)


class MultiprimeBinaryTest(unittest.TestCase):
    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(256, nprimes=3)

    def test_multiprime_enc_dec(self):
        message = struct.pack(">IIII", 0, 0, 0, 1)
        print("\n\tMessage:   %r" % message)

        encrypted = pkcs1.encrypt(message, self.pub)
        print("\tEncrypted: %r" % encrypted)

        decrypted = pkcs1.decrypt(encrypted, self.priv)
        print("\tDecrypted: %r" % decrypted)

        self.assertEqual(message, decrypted)


class ExtraZeroesTest(unittest.TestCase):
    def setUp(self):
        # Key, cyphertext, and plaintext taken from https://github.com/sybrenstuvel/python-rsa/issues/146
        self.private_key = rsa.PrivateKey.load_pkcs1(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAs1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi/fGHG4CLw98+Yo\n0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv+6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM\n/ZfSCKvrjXybzgu+sBmobdtYm+sppbdL+GEHXGd8gdQw8DDCZSR6+dPJFAzLZTCd\nB+Ctwe/RXPF+ewVdfaOGjkZIzDoYDw7n+OHnsYCYozkbTOcWHpjVevipR+IBpGPi\n1rvKgFnlcG6d/tj0hWRl/6cS7RqhjoiNEtxqoJzpXs/Kg8xbCxXbCchkf11STA8u\ndiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQIDAQABAoIBABpQLQ7qbHtp4h1Y\nORAfcFRW7Q74UvtH/iEHH1TF8zyM6wZsYtcn4y0mxYE3Mp+J0xlTJbeVJkwZXYVH\nL3UH29CWHSlR+TWiazTwrCTRVJDhEoqbcTiRW8fb+o/jljVxMcVDrpyYUHNo2c6w\njBxhmKPtp66hhaDpds1Cwi0A8APZ8Z2W6kya/L/hRBzMgCz7Bon1nYBMak5PQEwV\nF0dF7Wy4vIjvCzO6DSqA415DvJDzUAUucgFudbANNXo4HJwNRnBpymYIh8mHdmNJ\n/MQ0YLSqUWvOB57dh7oWQwe3UsJ37ZUorTugvxh3NJ7Tt5ZqbCQBEECb9ND63gxo\n/a3YR/0CgYEA7BJc834xCi/0YmO5suBinWOQAF7IiRPU+3G9TdhWEkSYquupg9e6\nK9lC5k0iP+t6I69NYF7+6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ/+F\ndkYlwuGSNttMQBzjCiVy0+y0+Wm3rRnFIsAtd0RlZ24aN3bFTWJINIsCgYEAwnQq\nvNmJe9SwtnH5c/yCqPhKv1cF/4jdQZSGI6/p3KYNxlQzkHZ/6uvrU5V27ov6YbX8\nvKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZz3s4Xd\nhiJBShgy+fKURvBQwtWmQHZJ3EGrcOI7PcwiyYcCgYEAlql5jSUCY0ALtidzQogW\nJ+B87N+RGHsBuJ/0cxQYinwg+ySAAVbSyF1WZujfbO/5+YBN362A/1dn3lbswCnH\nK/bHF9+fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT+uwQ0misgR8SQE4W25dDG\nkdEYsz+BgCsyrCcu8J5C+tUCgYAFVPQbC4f2ikVyKzvgz0qx4WUDTBqRACq48p6e\n+eLatv7nskVbr7QgN+nS9+Uz80ihR0Ev1yCAvnwmM/XYAskcOea87OPmdeWZlQM8\nVXNwINrZ6LMNBLgorfuTBK1UoRo1pPUHCYdqxbEYI2unak18mikd2WB7Fp3h0YI4\nVpGZnwKBgBxkAYnZv+jGI4MyEKdsQgxvROXXYOJZkWzsKuKxVkVpYP2V4nR2YMOJ\nViJQ8FUEnPq35cMDlUk4SnoqrrHIJNOvcJSCqM+bWHAioAsfByLbUPM8sm3CDdIk\nXVJl32HuKYPJOMIWfc7hIfxLRHnCN+coz2M6tgqMDs0E/OfjuqVZ\n-----END RSA PRIVATE KEY-----",
            format="PEM",
        )
        self.cyphertext = bytes.fromhex(
            "4501b4d669e01b9ef2dc800aa1b06d49196f5a09fe8fbcd037323c60eaf027bfb98432be4e4a26c567ffec718bcbea977dd26812fa071c33808b4d5ebb742d9879806094b6fbeea63d25ea3141733b60e31c6912106e1b758a7fe0014f075193faa8b4622bfd5d3013f0a32190a95de61a3604711bc62945f95a6522bd4dfed0a994ef185b28c281f7b5e4c8ed41176d12d9fc1b837e6a0111d0132d08a6d6f0580de0c9eed8ed105531799482d1e466c68c23b0c222af7fc12ac279bc4ff57e7b4586d209371b38c4c1035edd418dc5f960441cb21ea2bedbfea86de0d7861e81021b650a1de51002c315f1e7c12debe4dcebf790caaa54a2f26b149cf9e77d"
        )
        self.plaintext = bytes.fromhex("54657374")

    def test_unmodified(self):
        message = rsa.decrypt(self.cyphertext, self.private_key)
        self.assertEqual(message, self.plaintext)

    def test_prepend_zeroes(self):
        cyphertext = bytes.fromhex("0000") + self.cyphertext
        with self.assertRaises(rsa.DecryptionError):
            rsa.decrypt(cyphertext, self.private_key)

    def test_append_zeroes(self):
        cyphertext = self.cyphertext + bytes.fromhex("0000")
        with self.assertRaises(rsa.DecryptionError):
            rsa.decrypt(cyphertext, self.private_key)


class SignatureTest(unittest.TestCase):
    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(512)

    def test_sign_verify(self):
        """Test happy flow of sign and verify"""

        message = b"je moeder"
        signature = pkcs1.sign(message, self.priv, "SHA-256")
        self.assertEqual("SHA-256", pkcs1.verify(message, signature, self.pub))

    def test_sign_verify_sha3(self):
        """Test happy flow of sign and verify with SHA3-256"""

        message = b"je moeder"
        signature = pkcs1.sign(message, self.priv, "SHA3-256")
        self.assertEqual("SHA3-256", pkcs1.verify(message, signature, self.pub))

    def test_find_signature_hash(self):
        """Test happy flow of sign and find_signature_hash"""

        message = b"je moeder"
        signature = pkcs1.sign(message, self.priv, "SHA-256")

        self.assertEqual("SHA-256", pkcs1.find_signature_hash(signature, self.pub))

    def test_alter_message(self):
        """Altering the message should let the verification fail."""

        signature = pkcs1.sign(b"je moeder", self.priv, "SHA-256")
        self.assertRaises(
            pkcs1.VerificationError, pkcs1.verify, b"mijn moeder", signature, self.pub
        )

    def test_sign_different_key(self):
        """Signing with another key should let the verification fail."""

        (otherpub, _) = rsa.newkeys(512)

        message = b"je moeder"
        signature = pkcs1.sign(message, self.priv, "SHA-256")
        self.assertRaises(pkcs1.VerificationError, pkcs1.verify, message, signature, otherpub)

    def test_multiple_signings(self):
        """Signing the same message twice should return the same signatures."""

        message = struct.pack(">IIII", 0, 0, 0, 1)
        signature1 = pkcs1.sign(message, self.priv, "SHA-1")
        signature2 = pkcs1.sign(message, self.priv, "SHA-1")

        self.assertEqual(signature1, signature2)

    def test_split_hash_sign(self):
        """Hashing and then signing should match with directly signing the message."""

        message = b"je moeder"
        msg_hash = pkcs1.compute_hash(message, "SHA-256")
        signature1 = pkcs1.sign_hash(msg_hash, self.priv, "SHA-256")

        # Calculate the signature using the unified method
        signature2 = pkcs1.sign(message, self.priv, "SHA-256")

        self.assertEqual(signature1, signature2)

    def test_hash_sign_verify(self):
        """Test happy flow of hash, sign, and verify"""

        message = b"je moeder"
        msg_hash = pkcs1.compute_hash(message, "SHA-224")
        signature = pkcs1.sign_hash(msg_hash, self.priv, "SHA-224")

        self.assertTrue(pkcs1.verify(message, signature, self.pub))

    def test_prepend_zeroes(self):
        """Prepending the signature with zeroes should be detected."""

        message = b"je moeder"
        signature = pkcs1.sign(message, self.priv, "SHA-256")
        signature = bytes.fromhex("0000") + signature
        with self.assertRaises(rsa.VerificationError):
            pkcs1.verify(message, signature, self.pub)

    def test_apppend_zeroes(self):
        """Apppending the signature with zeroes should be detected."""

        message = b"je moeder"
        signature = pkcs1.sign(message, self.priv, "SHA-256")
        signature = signature + bytes.fromhex("0000")
        with self.assertRaises(rsa.VerificationError):
            pkcs1.verify(message, signature, self.pub)


class MultiprimeSignatureTest(unittest.TestCase):
    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(512, nprimes=3)

    def test_multiprime_sign_verify(self):
        """Test happy flow of sign and verify"""

        message = b"je moeder"
        signature = pkcs1.sign(message, self.priv, "SHA-256")
        self.assertEqual("SHA-256", pkcs1.verify(message, signature, self.pub))


class PaddingSizeTest(unittest.TestCase):
    def test_too_little_padding(self):
        """Padding less than 8 bytes should be rejected."""

        # Construct key that will be small enough to need only 7 bytes of padding.
        # This key is 168 bit long, and was generated with rsa.newkeys(nbits=168).
        self.private_key = rsa.PrivateKey.load_pkcs1(
            b"""
-----BEGIN RSA PRIVATE KEY-----
MHkCAQACFgCIGbbNSkIRLtprxka9NgOf5UxgxCMCAwEAAQIVQqymO0gHubdEVS68
CdCiWmOJxVfRAgwBQM+e1JJwMKmxSF0CCmya6CFxO8Evdn8CDACMM3AlVC4FhlN8
3QIKC9cjoam/swMirwIMAR7Br9tdouoH7jAE
-----END RSA PRIVATE KEY-----
        """
        )
        self.public_key = rsa.PublicKey(n=self.private_key.n, e=self.private_key.e)

        cyphertext = self.encrypt_with_short_padding(b"op je hoofd")
        with self.assertRaises(rsa.DecryptionError):
            rsa.decrypt(cyphertext, self.private_key)

    def encrypt_with_short_padding(self, message: bytes) -> bytes:
        # This is a copy of rsa.pkcs1.encrypt() adjusted to use the wrong padding length.
        keylength = rsa.common.byte_size(self.public_key.n)

        # The word 'padding' has 7 letters, so is one byte short of a valid padding length.
        padded = b"\x00\x02padding\x00" + message

        payload = rsa.transform.bytes2int(padded)
        encrypted_value = rsa.core.encrypt_int(payload, self.public_key.e, self.public_key.n)
        cyphertext = rsa.transform.int2bytes(encrypted_value, keylength)

        return cyphertext


class Asn1ParserTest(unittest.TestCase):
    def test_parse_standard_digest_info(self):
        digest = b"\x22" * 32
        encoded = _digest_info(_algorithm_contents(OID_SHA256_DER), digest)
        oid, parsed_digest = asn1.parse_digest_info(encoded)
        self.assertEqual("2.16.840.1.101.3.4.2.1", oid)
        self.assertEqual(digest, parsed_digest)

    def test_trailing_data_rejected(self):
        digest = b"\x33" * 20
        encoded = _digest_info(_algorithm_contents(OID_SHA1_DER), digest)
        self.assertRaises(asn1.Asn1Error, asn1.parse_digest_info, encoded + b"\x00")

    def test_missing_null_parameters_rejected(self):
        digest = b"\x44" * 16
        encoded = _digest_info(_algorithm_contents(OID_MD5_DER, b""), digest)
        self.assertRaises(asn1.Asn1Error, asn1.parse_digest_info, encoded)

    def test_non_minimal_length_rejected(self):
        digest = b"\x55" * 32
        algorithm = _der_tlv(asn1.TAG_SEQUENCE, _algorithm_contents(OID_SHA256_DER))
        octet_string = _der_tlv(asn1.TAG_OCTET_STRING, digest)
        contents = algorithm + octet_string
        encoded = bytes([asn1.TAG_SEQUENCE, 0x81, len(contents)]) + contents
        self.assertRaises(asn1.Asn1Error, asn1.parse_digest_info, encoded)

    def test_non_minimal_oid_rejected(self):
        # Arc 128 encoded as 80 81 00 instead of the minimal 81 00.
        bad_oid_content = bytes([0x2A, 0x80, 0x81, 0x00])
        digest = b"\x66" * 32
        algorithm = _der_tlv(
            asn1.TAG_SEQUENCE,
            _der_tlv(asn1.TAG_OBJECT_IDENTIFIER, bad_oid_content) + b"\x05\x00",
        )
        encoded = _der_tlv(
            asn1.TAG_SEQUENCE,
            algorithm + _der_tlv(asn1.TAG_OCTET_STRING, digest),
        )
        self.assertRaises(asn1.Asn1Error, asn1.parse_digest_info, encoded)

    def test_truncated_oid_rejected(self):
        # The final base-128 group keeps its continuation bit set.
        digest = b"\x77" * 32
        algorithm = _der_tlv(
            asn1.TAG_SEQUENCE,
            bytes([asn1.TAG_OBJECT_IDENTIFIER, 0x02, 0x2A, 0x86])
            + b"\x05\x00",
        )
        encoded = _der_tlv(
            asn1.TAG_SEQUENCE,
            algorithm + _der_tlv(asn1.TAG_OCTET_STRING, digest),
        )
        self.assertRaises(asn1.Asn1Error, asn1.parse_digest_info, encoded)


class StrictVerificationTest(unittest.TestCase):
    def setUp(self):
        # 1024 bits fits every supported DigestInfo, including SHA-512.
        (self.pub, self.priv) = rsa.newkeys(1024)
        self.message = b"strict verification message"

    def _assert_rejected(self, signature: bytes) -> None:
        with self.assertRaises(pkcs1.VerificationError) as context:
            pkcs1.verify(self.message, signature, self.pub)
        # The external message must stay generic and never echo signature bytes.
        self.assertEqual("Verification failed", str(context.exception))
        self.assertNotIn(b"\xff", str(context.exception).encode())

    def test_legal_signatures_for_every_hash(self):
        for hash_name in ("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"):
            with self.subTest(hash_name=hash_name):
                signature = pkcs1.sign(self.message, self.priv, hash_name)
                self.assertEqual(
                    hash_name, pkcs1.verify(self.message, signature, self.pub)
                )

    def test_legal_signature_with_declared_hash(self):
        signature = pkcs1.sign(self.message, self.priv, "SHA-256")
        self.assertEqual(
            "SHA-256",
            pkcs1.verify(self.message, signature, self.pub, "SHA-256"),
        )

    def test_declared_hash_mismatch_is_rejected(self):
        signature = pkcs1.sign(self.message, self.priv, "SHA-256")
        self.assertRaises(
            pkcs1.VerificationError,
            pkcs1.verify,
            self.message,
            signature,
            self.pub,
            "SHA-512",
        )

    def test_wrong_oid_is_rejected(self):
        # OID claims SHA-256, while the digest is only 20 bytes (SHA-1 length).
        digest = pkcs1.compute_hash(self.message, "SHA-1")
        digest_info = _digest_info(_algorithm_contents(OID_SHA256_DER), digest)
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_wrong_hash_length_is_rejected(self):
        digest = pkcs1.compute_hash(self.message, "SHA-1")[:19]
        digest_info = _digest_info(_algorithm_contents(OID_SHA1_DER), digest)
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_null_parameters_accepted(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = _digest_info(
            _algorithm_contents(OID_SHA256_DER, b"\x05\x00"), digest
        )
        signature = _raw_sign(self.priv, digest_info)
        self.assertEqual("SHA-256", pkcs1.verify(self.message, signature, self.pub))

    def test_missing_parameters_are_rejected(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = _digest_info(
            _algorithm_contents(OID_SHA256_DER, b""), digest
        )
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_non_null_parameters_are_rejected(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = _digest_info(
            _algorithm_contents(OID_SHA256_DER, b"\x05\x01\x00"), digest
        )
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_extra_field_in_digest_info_is_rejected(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_algorithm = _der_tlv(
            asn1.TAG_SEQUENCE, _algorithm_contents(OID_SHA256_DER)
        )
        octet_string = _der_tlv(asn1.TAG_OCTET_STRING, digest)
        extra_integer = _der_tlv(asn1.TAG_INTEGER, b"\x01")
        digest_info = _der_tlv(
            asn1.TAG_SEQUENCE, digest_algorithm + octet_string + extra_integer
        )
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_non_minimal_der_length_is_rejected(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_algorithm = _der_tlv(
            asn1.TAG_SEQUENCE, _algorithm_contents(OID_SHA256_DER)
        )
        octet_string = _der_tlv(asn1.TAG_OCTET_STRING, digest)
        contents = digest_algorithm + octet_string
        # The outer SEQUENCE length uses the long form although it fits one byte.
        digest_info = bytes([asn1.TAG_SEQUENCE, 0x81, len(contents)]) + contents
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_short_padding_is_rejected(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = _digest_info(_algorithm_contents(OID_SHA256_DER), digest)
        keylength = rsa.common.byte_size(self.priv.n)
        padding_length = 7
        encoded = (
            b"\x00\x01"
            + b"\xff" * padding_length
            + b"\x00"
            + digest_info
            + b"\x00" * (keylength - len(digest_info) - padding_length - 3)
        )
        payload = rsa.transform.bytes2int(encoded)
        signature = rsa.transform.int2bytes(
            self.priv.blinded_decrypt(payload), keylength
        )
        self._assert_rejected(signature)

    def test_bad_padding_bytes_are_rejected(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = _digest_info(_algorithm_contents(OID_SHA256_DER), digest)
        keylength = rsa.common.byte_size(self.priv.n)
        padding_length = keylength - len(digest_info) - 3
        encoded = (
            b"\x00\x01"
            + b"\xff" * (padding_length - 1)
            + b"\x00"
            + b"\x00"
            + digest_info
        )
        payload = rsa.transform.bytes2int(encoded)
        signature = rsa.transform.int2bytes(
            self.priv.blinded_decrypt(payload), keylength
        )
        self._assert_rejected(signature)

    def test_trailing_bytes_after_signature_are_rejected(self):
        signature = pkcs1.sign(self.message, self.priv, "SHA-256")
        self._assert_rejected(signature + b"\x00\x00")

    def test_prefix_only_forgery_is_rejected(self):
        # A block whose DigestInfo starts with the exact expected prefix, but
        # whose structure is not a valid DigestInfo.
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = pkcs1.HASH_ASN1["SHA-256"] + digest + b"\x00\x01\x02"
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_tail_only_forgery_is_rejected(self):
        # The correct hash sits at the end, but the header carries another OID
        # and extra trailing bytes before it.
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        inner = (
            _digest_info(_algorithm_contents(OID_MD5_DER), b"\x00" * 16) + digest
        )
        self._assert_rejected(_raw_sign(self.priv, inner))

    def test_unknown_oid_is_rejected(self):
        # OID 1.1.1, which is not one of the supported hash OIDs.
        unknown_oid = bytes([0x29, 0x01, 0x01])
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = _digest_info(_algorithm_contents(unknown_oid), digest)
        self._assert_rejected(_raw_sign(self.priv, digest_info))

    def test_find_signature_hash_rejects_malformed_block(self):
        digest = pkcs1.compute_hash(self.message, "SHA-256")
        digest_info = _digest_info(
            _algorithm_contents(OID_SHA256_DER, b""), digest
        )
        self.assertRaises(
            pkcs1.VerificationError,
            pkcs1.find_signature_hash,
            _raw_sign(self.priv, digest_info),
            self.pub,
        )

    def test_find_signature_hash_accepts_legal_block(self):
        signature = pkcs1.sign(self.message, self.priv, "SHA-384")
        self.assertEqual("SHA-384", pkcs1.find_signature_hash(signature, self.pub))
