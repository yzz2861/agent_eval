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

"""Tests PKCS #1 version 2 functionality.

Most of the mocked values come from the test vectors found at:
http://www.itomorrowmag.com/emc-plus/rsa-labs/standards-initiatives/pkcs-rsa-cryptography-standard.htm

The PSS vectors were generated independently with OpenSSL 4.1 using a
2048-bit key and SHA-256 for both the message digest and MGF1.
"""

import base64
import unittest

import rsa
from rsa import key, pkcs1, pkcs1_v2

# OpenSSL-generated public key (n, e = 65537).
_PSS_N = int(
    "B8C9AFD283658E49785FCFB493CFE5A080DE3E6619883139FA51CD481D953B54"
    "BC7AEB4133ABFEECD4F0FDF93E4E68DA4569BBBE27C22F4D21ACD1DFDBAB5F"
    "C61CD564DEFA8772089AC1C36DDC795DF4C166CD3139272A9B4C06AF075D40"
    "B20C3E10891201E0CA52BF1EFC06BDABFDF4641BEBFF900769E9D68C7F8544"
    "0C4A3CA9C317A4EA621381E139947B4314FE4B698BA7E6D4FC4804108FB22E"
    "DA13349E30E96D5D7274DBB6B4F1FE3252A19928B38CD5C752B06DC7F6404C"
    "CA7CE16DD54AC98EB1244DE24E9A1F074A8A52C4633E81C54E1F51146CD090"
    "3A179F396ABB2BB52798331DA36AEFF226D2BE65376744A2508BD3666076BB"
    "AE6CFD028E0DBB",
    16,
)

_PSS_PUB = key.PublicKey(_PSS_N, 65537)

_PSS_VECTORS = {
    "hash": (
        b"payments-pss-hash-salt-2026",
        b"dKjG06/YaV5vEwotlIGKaw8wiozXZ7dqi7bsGAvE9uhNZg3XnG0iRwNdW22eoRPu"
        b"9ngQL6E7o64+ScJMJGE7hUau31hSmGCAgy3Xon+yhsgPi/Nqq5o59NxiEV3CnUp"
        b"2JMMf6yILAlHm7s+mIptEB1Rq8G6mbM9Zhjtfpr9/BDzew3Vy2/K2M25/1R943"
        b"v80bb1xTjZcXlSPpwrEl90Gp2Sy8Yvx8H7JcgKau5kxE56xlZiVSZ/REJBLNzTI"
        b"/c4SuQNur2sDME9cdbaJpvViUgrkBCZfkJxoAiUn8itHqCUQFah8NgQQFtN5bp"
        b"BYAxY2l9Gqs2xodQJnMNmcxfVDtw==",
    ),
    "max": (
        b"payments-pss-max-salt-2026",
        b"rQ+uYa90QMxKN+WG3kgeWtXuIUYbmjUjNS5ucLtUuBhXRhFFcqogwI129509lMu"
        b"KkFku+SKR75kiwt/Ie4E6gB4mNISP4o+9f0Xz8rTKSg3ld/heyVPnJD6991fnb7"
        b"6ZkTzKk5FNNgGNc/OerBaLlmOLHlx2C0WPNBEO1Kh+YR4PItdrzSp9DLnVETg4"
        b"aKPQzWZ2dET5ISXV5NDuEA7RkUSAAMWId1Lkr+iPepqm4qCCnXGVbgcpB7jLV9R"
        b"nItxeLcTT7K6ho7F1h8EAlUCi51h14xoJfLV+XRLNezBdO21YPau+hIKZ2H4H/o"
        b"3Y5L5rCFLYl8ou8/3Ciu96VJm9gQ==",
    ),
    "fixed32": (
        b"payments-pss-fixed-32-2026",
        b"cLj09JgyRgDJFxyJDY4LxxS/palGbDBBGdV9M0kOHfLBXk1+hoIcvbSe5i4883"
        b"/1u0eFEEcpJWLY8QShtdau/2yORcAzKMhtadIIclhB0MLX1nCsRbepddjj/AREP"
        b"EpBHEgSnKmY0jl1NSQtSmqC7NYHxPnKw3JLBE9Kr/5QHb3yl0FRQZVJFKz35QtX"
        b"QXYNMROGTiNx23hY+ECo1hEVd53hmgzVTWE4Y6k0TWi1Cq6sDl6rZPn4SPQTIM+"
        b"w7vHTdN0G8xsA+LBudnsGfohJS+AQjtIBiPp+A2IfuNR0UQdCvnKLgXvF3tVlk"
        b"Ftfbg2lUJ2Q1Tw+EuK/q2aPONpqjg==",
    ),
    "empty": (
        b"payments-pss-empty-salt-2026",
        b"OwSbgDp+lrWV9gndAXkwa1bpYWRYWPArsB8kL5Klr4a7UzUsl052q9mlDnSwtc"
        b"bxJwvS320x1A89QyyBfuwrxoY/TCGR58vbDb8gW8gXwWHpT4of4c7+aEN6OgbbF"
        b"RAXv+sh1DbK+uM05tdRCssh3c5oPeWjXaa6iwzxPJbu65SfksGPqBEB+TWBQ5Z5"
        b"1VHGOQrLkuZFTjSKLyc7q2lRRZjZo8gZG9c1IEsraV0Wb2ki7ji6LhTBghg71r"
        b"BjH0Aeu0+Zw6hg0hQrHEuXqUiSw1Y+dhHjxfQi3MhpGnGiBEYemgo73rUMFZZn1"
        b"S3ddtYQ5zJJEcWM1QPqYim10nZ/ag==",
    ),
    "mgf1_sha1": (
        b"payments-pss-hash-salt-2026",
        b"sF3/g4yZSycBpLZXx6RSCEI8+uV73cP+eGURej4jAJrCQJVkv1freck9/t7a31M"
        b"+9gb7J7n0TvmkhvrXnKtUrW45lw850Q67gMnrdNPrlRs8cgTqppc8dR6dnIn1P4o"
        b"cRQyAuWGhWIsPzYo5xWect/NLDHUAwaC9OjeoIaG7pdu9dzZ/i9XntvHsrg74iQ"
        b"/4XNqGSE+bmO6pVxl2I10t0I9yCyCIN8mmyIB5huClWfQytGPA+OirmWvCl3K/Y"
        b"G9SaTixA4qalF6wRn2RMpJbu/FS0MLZevRJivFUdICgz2m6Y5YlflVUBnIfeJv"
        b"9bETWhpRY2Qqq8DQN+eJBhla9Bw==",
    ),
    "v15": (
        b"payments-pss-hash-salt-2026",
        b"MNUqg5PepSIKkkUBjKGv1NtbzJ7ZEk3t0NRtrzLXI6PJAcLSPugVTMlzWiXkc"
        b"XHY6B0HdfKgTwTa4eiaPN5xeF2WMoHfQC7AnQ+fMiVLgIdNcWIa0DuDc7ZC7gpY"
        b"uptKkgBIL/rF7y0SLb8Ye9DUIAwgoqXI5kDU8QKejeJeeVOcyXKCsGTBmKUSKw"
        b"sfTmgsvIJluqGl2pEZlY0WQxk1ivUL/1KPx8WtypP/jHcx5zihOU4yxrdrVLMNx"
        b"MQEq9JpyH7bdvgqZrEFRPxaP3wv3168N8tCd9vBzpFyyiwoGQektica+aiYZ49MA"
        b"A4xetWiNT5Wb710XWC5e+35qd/I4w==",
    ),
}


def _vector(name):
    message, signature = _PSS_VECTORS[name]
    return message, base64.b64decode(signature)


# A 521-bit modulus exercises emLen == keyLen - 1 (521 mod 8 == 1).
_PSS_521_N = int(
    "1AB18C0FC66BDABA8CF73EB84BE39021AD5C0D3BA9E0BB1175E2D1CE5418B9F"
    "9B2275B6324FE89F8AAA6443A318CED03F4389B40A5DA9DC64A7A34F921B27"
    "1C197D",
    16,
)
_PSS_521_PUB = key.PublicKey(_PSS_521_N, 65537)
_PSS_521_MESSAGE = base64.b64decode(b"NTIxLWJpdCBib3VuZGFyeSB2ZWN0b3I=")
_PSS_521_SIGNATURE = base64.b64decode(
    b"ATifjiEYHGYbN+2BHDeoyaLYFkQbk74GMG6aIwVWnjVUtwj/WbFZ7jVxbAUPx/dnwDcX"
    b"cjS7suY5i6GC3fLCmSpi"
)


class MGFTest(unittest.TestCase):
    def test_oaep_int_db_mask(self):
        seed = (
            b"\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2" b"\xf0\x6c\xb5\x8f"
        )
        db = (
            b"\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90"
            b"\xaf\xd8\x07\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd4\x36\xe9\x95\x69"
            b"\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49"
        )
        masked_db = (
            b"\xdc\xd8\x7d\x5c\x68\xf1\xee\xa8\xf5\x52\x67\xc3\x1b\x2e\x8b\xb4"
            b"\x25\x1f\x84\xd7\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25"
            b"\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4"
            b"\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5"
            b"\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0"
            b"\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4f\x7b\xc2\x75\x19\x52"
            b"\x81\xce\x32\xd2\xf1\xb7\x6d\x4d\x35\x3e\x2d"
        )

        # dbMask = MGF(seed, length(DB))
        db_mask = pkcs1_v2.mgf1(seed, length=len(db))
        expected_db_mask = (
            b"\x06\xe1\xde\xb2\x36\x9a\xa5\xa5\xc7\x07\xd8\x2c\x8e\x4e\x93\x24"
            b"\x8a\xc7\x83\xde\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25"
            b"\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4"
            b"\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5"
            b"\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0"
            b"\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4e\xaf\xf4\x9c\x8c\x3b"
            b"\x7c\xfc\x95\x1a\x51\xec\xd1\xdd\xe6\x12\x64"
        )

        self.assertEqual(db_mask, expected_db_mask)

        # seedMask = MGF(maskedDB, length(seed))
        seed_mask = pkcs1_v2.mgf1(masked_db, length=len(seed))
        expected_seed_mask = (
            b"\x41\x87\x0b\x5a\xb0\x29\xe6\x57\xd9\x57\x50\xb5\x4c\x28\x3c\x08" b"\x72\x5d\xbe\xa9"
        )

        self.assertEqual(seed_mask, expected_seed_mask)

    def test_invalid_hasher(self):
        """Tests an invalid hasher generates an exception"""
        with self.assertRaises(ValueError):
            pkcs1_v2.mgf1(b"\x06\xe1\xde\xb2", length=8, hasher="SHA2")

    def test_invalid_length(self):
        with self.assertRaises(OverflowError):
            pkcs1_v2.mgf1(b"\x06\xe1\xde\xb2", length=2 ** 50)


class PSSOpenSSLVectorTest(unittest.TestCase):
    """Verification against independently generated OpenSSL PSS signatures."""

    def assert_pss_failure(self, message, signature, **kwargs):
        with self.assertRaises(pkcs1.VerificationError) as caught:
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, **kwargs)
        self.assertEqual(str(caught.exception), "Verification failed")

    def test_hash_length_salt(self):
        message, signature = _vector("hash")
        self.assertTrue(
            pkcs1_v2.verify_pss(
                message,
                signature,
                _PSS_PUB,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length="hash",
            )
        )

    def test_maximum_salt(self):
        message, signature = _vector("max")
        self.assertTrue(
            pkcs1_v2.verify_pss(
                message,
                signature,
                _PSS_PUB,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length="max",
            )
        )

    def test_fixed_32_byte_salt(self):
        message, signature = _vector("fixed32")
        self.assertTrue(
            pkcs1_v2.verify_pss(
                message,
                signature,
                _PSS_PUB,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length=32,
            )
        )

    def test_empty_salt(self):
        message, signature = _vector("empty")
        self.assertTrue(
            pkcs1_v2.verify_pss(
                message,
                signature,
                _PSS_PUB,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length=0,
            )
        )

    def test_separate_mgf1_hash(self):
        message, signature = _vector("mgf1_sha1")
        self.assertTrue(
            pkcs1_v2.verify_pss(
                message,
                signature,
                _PSS_PUB,
                hash_method="SHA-256",
                mgf1_hash="SHA-1",
                salt_length="hash",
            )
        )

    def test_modulus_with_extra_signature_octet(self):
        # OpenSSL-generated 521-bit key, maximum 31-byte salt.  The signature
        # is 66 octets while the EMSA-PSS encoded message is only 65.
        self.assertTrue(
            pkcs1_v2.verify_pss(
                _PSS_521_MESSAGE,
                _PSS_521_SIGNATURE,
                _PSS_521_PUB,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length="max",
            )
        )
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(
                _PSS_521_MESSAGE,
                _PSS_521_SIGNATURE,
                _PSS_521_PUB,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length=32,
            )

    def test_wrong_message_hash(self):
        message, signature = _vector("hash")
        self.assert_pss_failure(
            message,
            signature,
            hash_method="SHA-384",
            mgf1_hash="SHA-256",
            salt_length=32,
        )

    def test_wrong_mgf1_hash(self):
        message, signature = _vector("hash")
        self.assert_pss_failure(
            message,
            signature,
            hash_method="SHA-256",
            mgf1_hash="SHA-1",
            salt_length="hash",
        )

    def test_wrong_salt_length(self):
        max_message, max_signature = _vector("max")
        self.assert_pss_failure(
            max_message,
            max_signature,
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length=32,
        )

        empty_message, empty_signature = _vector("empty")
        self.assert_pss_failure(
            empty_message,
            empty_signature,
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length="hash",
        )

    def test_tampered_message(self):
        message, signature = _vector("hash")
        self.assert_pss_failure(
            message + b"!",
            signature,
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length="hash",
        )

    def test_tampered_signature(self):
        message, signature = _vector("hash")
        for index in (0, len(signature) // 2, len(signature) - 1):
            tampered = bytearray(signature)
            tampered[index] ^= 0x01
            self.assert_pss_failure(
                message,
                bytes(tampered),
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length="hash",
            )

    def test_truncated_signature(self):
        message, signature = _vector("hash")
        self.assert_pss_failure(
            message,
            signature[:-1],
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length="hash",
        )
        self.assert_pss_failure(
            message,
            signature[: len(signature) // 2],
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length="hash",
        )

    def test_v15_cross_does_not_verify_as_pss(self):
        message, v15_signature = _vector("v15")
        self.assertEqual(pkcs1.verify(message, v15_signature, _PSS_PUB), "SHA-256")
        self.assert_pss_failure(
            message,
            v15_signature,
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length="hash",
        )

    def test_pss_does_not_verify_as_v15(self):
        message, signature = _vector("hash")
        with self.assertRaises(pkcs1.VerificationError):
            pkcs1.verify(message, signature, _PSS_PUB)


class PSSParameterTest(unittest.TestCase):
    def test_invalid_hash_method(self):
        message, signature = _vector("hash")
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, hash_method="SHA-999")

    def test_invalid_mgf1_hash(self):
        message, signature = _vector("hash")
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, mgf1_hash="SHA-999")

    def test_invalid_salt_policy(self):
        message, signature = _vector("hash")
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, salt_length="random")

    def test_negative_salt_length(self):
        message, signature = _vector("hash")
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, salt_length=-1)

    def test_salt_length_larger_than_modulus(self):
        message, signature = _vector("hash")
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, salt_length=223)

    def test_wrong_argument_types(self):
        message, signature = _vector("hash")
        with self.assertRaises(TypeError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, salt_length=True)
        with self.assertRaises(TypeError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, hash_method=256)
        with self.assertRaises(TypeError):
            pkcs1_v2.verify_pss(message, signature, _PSS_PUB, salt_length=1.5)
        with self.assertRaises(TypeError):
            pkcs1_v2.verify_pss(message, "not bytes", _PSS_PUB)

    def test_modulus_too_small(self):
        small_pub, _ = rsa.newkeys(512)
        message = b"small modulus"
        signature = b"\x00" * rsa.common.byte_size(small_pub.n)
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(
                message,
                signature,
                small_pub,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length="hash",
            )


class PSSRoundTripTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key, cls.private_key = rsa.newkeys(1024)

    def test_salt_policies(self):
        message = b"round-trip PSS salt policies"
        for salt_length in (0, "hash", 31, 32, "max"):
            with self.subTest(salt_length=salt_length):
                signature = pkcs1_v2.pss_sign(
                    message,
                    self.private_key,
                    hash_method="SHA-256",
                    mgf1_hash="SHA-256",
                    salt_length=salt_length,
                )
                self.assertTrue(
                    pkcs1_v2.pss_verify(
                        message,
                        signature,
                        self.public_key,
                        hash_method="SHA-256",
                        mgf1_hash="SHA-256",
                        salt_length=salt_length,
                    )
                )

    def test_fixed_salt_is_distinct_from_hash_length(self):
        message = b"fixed salt differs from SHA-384 digest length"
        signature = pkcs1_v2.sign_pss(
            message,
            self.private_key,
            hash_method="SHA-384",
            mgf1_hash="SHA-384",
            salt_length=32,
        )
        self.assertTrue(
            pkcs1_v2.verify_pss(
                message,
                signature,
                self.public_key,
                hash_method="SHA-384",
                mgf1_hash="SHA-384",
                salt_length=32,
            )
        )
        with self.assertRaises(pkcs1.VerificationError):
            pkcs1_v2.verify_pss(
                message,
                signature,
                self.public_key,
                hash_method="SHA-384",
                mgf1_hash="SHA-384",
                salt_length="hash",
            )

    def test_exact_minimum_modulus_for_fixed_salt(self):
        small_pub, small_priv = rsa.newkeys(528)
        message = b"exact modulus boundary"
        signature = pkcs1_v2.pss_sign(
            message,
            small_priv,
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length=32,
        )
        self.assertTrue(
            pkcs1_v2.verify_pss(
                message,
                signature,
                small_pub,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length=32,
            )
        )
        with self.assertRaises(ValueError):
            pkcs1_v2.verify_pss(
                message,
                signature,
                small_pub,
                hash_method="SHA-256",
                mgf1_hash="SHA-256",
                salt_length=33,
            )

    def test_emsa_pss_encode_shape(self):
        message_hash = pkcs1.compute_hash(b"shape", "SHA-256")
        salt = b"\x01" * 32
        encoded = pkcs1_v2.emsa_pss_encode(
            message_hash,
            1023,
            hash_method="SHA-256",
            mgf1_hash="SHA-256",
            salt_length=32,
            salt=salt,
        )
        self.assertEqual(len(encoded), 128)
        self.assertEqual(encoded[-1:], b"\xbc")
        self.assertEqual(encoded[0] & 0x80, 0)
