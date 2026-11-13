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

"""Functions for PKCS#1 version 2 encryption and signing

This module implements certain functionality from PKCS#1 version 2. Main
documentation is RFC 8017: https://tools.ietf.org/html/rfc8017

The PSS implementation below is intentionally explicit: callers have to select
the message hash, the MGF1 hash and the salt-length policy.  In particular, a
PKCS#1 v1.5 signature is never accepted as a PSS signature, and verification
never falls back to a different padding scheme.
"""

import os
import typing
from hmac import compare_digest

from rsa import (
    common,
    core,
    pkcs1,
    transform,
)

PSS_SALT_LENGTH_HASH = "hash"
PSS_SALT_LENGTH_MAX = "max"

SALT_LENGTH_HASH = PSS_SALT_LENGTH_HASH
SALT_LENGTH_MAX = PSS_SALT_LENGTH_MAX

_VERIFICATION_FAILED = "Verification failed"

VerificationError = pkcs1.VerificationError

_HASH_ALIASES = {
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA-1": "SHA-1",
    "SHA224": "SHA-224",
    "SHA-224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA-256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA-384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA-512": "SHA-512",
    "SHA3-256": "SHA3-256",
    "SHA3-384": "SHA3-384",
    "SHA3-512": "SHA3-512",
}

_SALT_HASH_NAMES = {
    "HASH",
    "HASH-LENGTH",
    "HASH-LEN",
    "DIGEST",
    "DIGEST-LENGTH",
    "DIGEST-LEN",
}

_SALT_MAX_NAMES = {
    "MAX",
    "MAXIMUM",
    "MAX-LENGTH",
    "MAX-LEN",
    "MAXIMUM-LENGTH",
    "MAXIMUM-LEN",
}


def _normalize_hash_name(hash_method: str) -> str:
    """Return the canonical rsa hash name, or raise ValueError."""

    if not isinstance(hash_method, str):
        raise TypeError("hash method must be a string")

    normalized = hash_method.strip().upper().replace("_", "-")
    canonical = _HASH_ALIASES.get(normalized)
    if canonical is None:
        canonical = _HASH_ALIASES.get(normalized.replace("-", ""))
    if canonical is None or canonical not in pkcs1.HASH_METHODS:
        raise ValueError("Invalid hash method: %s" % hash_method)
    return canonical


def _hash_length(hash_method: str) -> int:
    return pkcs1.HASH_METHODS[hash_method]().digest_size


def _resolve_salt_length(salt_length: typing.Union[int, str, None], em_len: int, h_len: int) -> int:
    """Resolve a salt-length policy to a concrete number of octets.

    ``"hash"`` selects the hash output length, ``"max"`` the largest salt that
    fits in the encoded message, and an integer selects a fixed length.  Zero
    is a valid fixed length.
    """

    if salt_length is None:
        salt_length = PSS_SALT_LENGTH_HASH

    if isinstance(salt_length, bool):
        raise TypeError("salt length must be an integer or a salt-length policy")

    if isinstance(salt_length, int):
        resolved = salt_length
        if resolved < 0:
            raise ValueError("salt length must not be negative")
    elif isinstance(salt_length, str):
        policy = salt_length.strip().upper().replace("_", "-")
        if policy in _SALT_HASH_NAMES:
            resolved = h_len
        elif policy in _SALT_MAX_NAMES:
            resolved = em_len - h_len - 2
        else:
            raise ValueError("Invalid salt-length policy: %s" % salt_length)
    else:
        raise TypeError("salt length must be an integer or a salt-length policy")

    if resolved < 0 or resolved > em_len - h_len - 2:
        raise ValueError("Modulus is too small for the requested PSS salt length")

    return resolved


def _encoded_message_length(n: int) -> typing.Tuple[int, int]:
    """Return ``(em_bits, em_len)`` for an RSA modulus."""

    if not isinstance(n, int):
        raise TypeError("modulus must be an integer")
    if n <= 0:
        raise ValueError("modulus must be positive")

    em_bits = common.bit_size(n) - 1
    if em_bits < 1:
        raise ValueError("Modulus is too small for PSS")
    return em_bits, common.ceil_div(em_bits, 8)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def emsa_pss_encode(
    message_hash: bytes,
    em_bits: int,
    hash_method: str = "SHA-256",
    mgf1_hash: typing.Optional[str] = None,
    salt_length: typing.Union[int, str, None] = PSS_SALT_LENGTH_HASH,
    salt: typing.Optional[bytes] = None,
) -> bytes:
    """Encode a message hash using EMSA-PSS.

    :param message_hash: hash of the message, using ``hash_method``.
    :param em_bits: bit length of the encoded message, ``modBits - 1``.
    :param hash_method: message hash name.
    :param mgf1_hash: hash used by MGF1; defaults to ``hash_method``.
    :param salt_length: ``"hash"``, ``"max"`` or a fixed number of octets.
    :param salt: optional fixed salt.  Its length must match ``salt_length``.
    :return: the EMSA-PSS encoded message, ``ceil(em_bits / 8)`` octets long.
    """

    hash_method = _normalize_hash_name(hash_method)
    mgf1_hash = hash_method if mgf1_hash is None else _normalize_hash_name(mgf1_hash)

    if not isinstance(em_bits, int) or isinstance(em_bits, bool):
        raise TypeError("em_bits must be an integer")
    if em_bits < 1:
        raise ValueError("em_bits must be positive")

    h_len = _hash_length(hash_method)
    em_len = common.ceil_div(em_bits, 8)

    if not isinstance(message_hash, bytes):
        raise TypeError("message_hash must be a byte string")
    if len(message_hash) != h_len:
        raise ValueError("message hash length does not match hash method")

    s_len = _resolve_salt_length(salt_length, em_len, h_len)

    if salt is None:
        salt_bytes = os.urandom(s_len)
    else:
        if not isinstance(salt, bytes):
            raise TypeError("salt must be a byte string")
        if len(salt) != s_len:
            raise ValueError("salt length does not match salt-length policy")
        salt_bytes = salt

    m_prime = b"\x00" * 8 + message_hash + salt_bytes
    h_value = pkcs1.compute_hash(m_prime, hash_method)

    ps = b"\x00" * (em_len - s_len - h_len - 2)
    db = ps + b"\x01" + salt_bytes
    db_mask = mgf1(h_value, len(db), mgf1_hash)
    masked_db = bytearray(_xor(db, db_mask))

    unused_bits = 8 * em_len - em_bits
    if unused_bits:
        masked_db[0] &= 0xFF >> unused_bits

    return bytes(masked_db) + h_value + b"\xbc"


def _pss_verify_encoded(
    message_hash: bytes,
    encoded_message: bytes,
    em_bits: int,
    hash_method: str,
    mgf1_hash: str,
    salt_length: int,
) -> bool:
    """Verify an EMSA-PSS encoded message without leaking failure details."""

    h_len = _hash_length(hash_method)
    em_len = len(encoded_message)
    db_len = em_len - h_len - 1

    masked_db = encoded_message[:db_len]
    h_value = encoded_message[db_len : db_len + h_len]
    trailer = encoded_message[-1:]

    unused_bits = 8 * em_len - em_bits
    if unused_bits:
        forbidden_mask = (0xFF << (8 - unused_bits)) & 0xFF
        high_bits_ok = not (masked_db[0] & forbidden_mask)
    else:
        high_bits_ok = True

    db_mask = mgf1(h_value, db_len, mgf1_hash)
    db = bytearray(_xor(masked_db, db_mask))
    if unused_bits:
        db[0] &= 0xFF >> unused_bits

    ps_len = em_len - h_len - salt_length - 2
    ps_ok = compare_digest(bytes(db[:ps_len]), b"\x00" * ps_len)
    separator_ok = db[ps_len] == 0x01
    salt = bytes(db[ps_len + 1 :])

    m_prime = b"\x00" * 8 + message_hash + salt
    expected_h = pkcs1.compute_hash(m_prime, hash_method)

    ok = (
        compare_digest(trailer, b"\xbc")
        & ps_ok
        & separator_ok
        & high_bits_ok
        & compare_digest(h_value, expected_h)
    )
    return bool(ok)


def verify(
    message: typing.Union[bytes, typing.BinaryIO],
    signature: bytes,
    pub_key: typing.Any,
    hash_method: str = "SHA-256",
    mgf1_hash: typing.Optional[str] = None,
    salt_length: typing.Union[int, str, None] = PSS_SALT_LENGTH_HASH,
) -> bool:
    """Verify an RSASSA-PSS signature.

    The padding is always PSS; there is no fallback to PKCS#1 v1.5.

    :param message: signed message, or a binary file-like object.
    :param signature: RSASSA-PSS signature.
    :param pub_key: public key with ``n`` and ``e`` attributes.
    :param hash_method: message hash name.
    :param mgf1_hash: MGF1 hash name; defaults to ``hash_method``.
    :param salt_length: ``"hash"``, ``"max"`` or a fixed number of octets.
    :return: ``True`` when the signature is valid.
    :raises ValueError: for invalid parameters or a modulus too small to hold
        the requested PSS parameters.
    :raises TypeError: for arguments of the wrong type.
    :raises pkcs1.VerificationError: when the signature does not match.  The
        exception deliberately contains no information about which check
        failed.
    """

    hash_method = _normalize_hash_name(hash_method)
    mgf1_hash = hash_method if mgf1_hash is None else _normalize_hash_name(mgf1_hash)

    try:
        n = pub_key.n
        e = pub_key.e
    except AttributeError as ex:
        raise TypeError("pub_key must provide n and e") from ex

    if not isinstance(n, int) or not isinstance(e, int):
        raise TypeError("modulus and exponent must be integers")
    if n <= 0 or e <= 0:
        raise ValueError("modulus and exponent must be positive")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be a byte string")

    em_bits, em_len = _encoded_message_length(n)
    h_len = _hash_length(hash_method)
    s_len = _resolve_salt_length(salt_length, em_len, h_len)

    key_len = common.byte_size(n)
    if len(signature) != key_len:
        raise pkcs1.VerificationError(_VERIFICATION_FAILED)

    signature_int = transform.bytes2int(signature)
    if signature_int >= n:
        raise pkcs1.VerificationError(_VERIFICATION_FAILED)

    decoded = core.encrypt_int(signature_int, e, n)
    encoded = transform.int2bytes(decoded, key_len)

    if em_len < key_len:
        if not compare_digest(encoded[: key_len - em_len], b"\x00" * (key_len - em_len)):
            raise pkcs1.VerificationError(_VERIFICATION_FAILED)
        encoded = encoded[key_len - em_len :]

    message_hash = pkcs1.compute_hash(message, hash_method)
    if not _pss_verify_encoded(
        message_hash,
        encoded,
        em_bits,
        hash_method,
        mgf1_hash,
        s_len,
    ):
        raise pkcs1.VerificationError(_VERIFICATION_FAILED)

    return True


def sign(
    message: typing.Union[bytes, typing.BinaryIO],
    priv_key: typing.Any,
    hash_method: str = "SHA-256",
    mgf1_hash: typing.Optional[str] = None,
    salt_length: typing.Union[int, str, None] = PSS_SALT_LENGTH_HASH,
) -> bytes:
    """Create an RSASSA-PSS signature.

    This helper is primarily intended to make it easy to produce and exercise
    PSS signatures.  Verification never uses it as a fallback.
    """

    hash_method = _normalize_hash_name(hash_method)
    mgf1_hash = hash_method if mgf1_hash is None else _normalize_hash_name(mgf1_hash)

    try:
        n = priv_key.n
    except AttributeError as ex:
        raise TypeError("priv_key must provide n") from ex

    em_bits, em_len = _encoded_message_length(n)
    h_len = _hash_length(hash_method)
    s_len = _resolve_salt_length(salt_length, em_len, h_len)

    message_hash = pkcs1.compute_hash(message, hash_method)
    encoded = emsa_pss_encode(
        message_hash,
        em_bits,
        hash_method,
        mgf1_hash,
        s_len,
    )

    key_len = common.byte_size(n)
    payload = transform.bytes2int(encoded)
    encrypted = priv_key.blinded_decrypt(payload)
    return transform.int2bytes(encrypted, key_len)


pss_encode = emsa_pss_encode
encode_pss = emsa_pss_encode
pss_sign = sign
sign_pss = sign
pss_verify = verify
verify_pss = verify


def mgf1(seed: bytes, length: int, hasher: str = "SHA-1") -> bytes:
    """
    MGF1 is a Mask Generation Function based on a hash function.

    A mask generation function takes an octet string of variable length and a
    desired output length as input, and outputs an octet string of the desired
    length. The plaintext-awareness of RSAES-OAEP relies on the random nature of
    the output of the mask generation function, which in turn relies on the
    random nature of the underlying hash.

    :param bytes seed: seed from which mask is generated, an octet string
    :param int length: intended length in octets of the mask, at most 2^32(hLen)
    :param str hasher: hash function (hLen denotes the length in octets of the hash
        function output)

    :return: mask, an octet string of length `length`
    :rtype: bytes

    :raise OverflowError: when `length` is too large for the specified `hasher`
    :raise ValueError: when specified `hasher` is invalid
    """

    try:
        hash_length = pkcs1.HASH_METHODS[hasher]().digest_size
    except KeyError as ex:
        raise ValueError(
            "Invalid `hasher` specified. Please select one of: {hash_list}".format(
                hash_list=", ".join(sorted(pkcs1.HASH_METHODS.keys()))
            )
        ) from ex

    # If l > 2^32(hLen), output "mask too long" and stop.
    if length > (2 ** 32 * hash_length):
        raise OverflowError(
            "Desired length should be at most 2**32 times the hasher's output "
            "length ({hash_length} for {hasher} function)".format(
                hash_length=hash_length,
                hasher=hasher,
            )
        )

    # Looping `counter` from 0 to ceil(l / hLen)-1, build `output` based on the
    # hashes formed by (`seed` + C), being `C` an octet string of length 4
    # generated by converting `counter` with the primitive I2OSP
    output = b"".join(
        pkcs1.compute_hash(
            seed + transform.int2bytes(counter, fill_size=4),
            method_name=hasher,
        )
        for counter in range(common.ceil_div(length, hash_length) + 1)
    )

    # Output the leading `length` octets of `output` as the octet string mask.
    return output[:length]


__all__ = [
    "mgf1",
    "emsa_pss_encode",
    "encode_pss",
    "pss_encode",
    "sign",
    "sign_pss",
    "pss_sign",
    "verify",
    "verify_pss",
    "pss_verify",
    "PSS_SALT_LENGTH_HASH",
    "PSS_SALT_LENGTH_MAX",
    "SALT_LENGTH_HASH",
    "SALT_LENGTH_MAX",
    "VerificationError",
]

if __name__ == "__main__":
    print("Running doctests 1000x or until failure")
    import doctest

    for count in range(1000):
        (failures, tests) = doctest.testmod()
        if failures:
            break

        if count % 100 == 0 and count:
            print("%i times" % count)

    print("Doctests done")
