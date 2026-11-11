from __future__ import division

import hashlib

import pytest

from .keys import SigningKey, BadSignatureError
from .curves import NIST256p, Ed25519
from .util import (
    sigencode_string,
    sigencode_der,
    sigdecode_string,
    sigdecode_der,
    sigdecode_string_strict,
    sigdecode_der_strict,
    orderlen,
    number_to_string,
)
from .der import encode_sequence, encode_integer


example_data = b"some data to sign"


@pytest.fixture(scope="module")
def key():
    return SigningKey.generate(curve=NIST256p)


def _canonize(r, s, order):
    """Return the low-S form of the (r, s) pair."""
    if s > order // 2:
        s = order - s
    return r, s


@pytest.fixture(scope="module")
def low_s_sig(key):
    """A valid signature with s <= n/2, as (r, s) integers."""
    order = key.curve.order
    sig = key.sign(example_data, sigencode=sigencode_string)
    r, s = sigdecode_string(sig, order)
    return _canonize(r, s, order)


@pytest.fixture(scope="module")
def high_s_sig(low_s_sig, key):
    """The high-S counterpart of the valid signature."""
    r, s = low_s_sig
    return r, key.curve.order - s


def _raw(pair, order):
    return sigencode_string(pair[0], pair[1], order)


def _der(pair, order):
    return sigencode_der(pair[0], pair[1], order)


def test_valid_signature_accepted_in_both_modes_raw(key, low_s_sig):
    vk = key.verifying_key
    sig = _raw(low_s_sig, key.curve.order)
    assert vk.verify(sig, example_data)
    assert vk.verify(sig, example_data, strict=True)


def test_valid_signature_accepted_in_both_modes_der(key, low_s_sig):
    vk = key.verifying_key
    sig = _der(low_s_sig, key.curve.order)
    assert vk.verify(sig, example_data, sigdecode=sigdecode_der)
    assert vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)


def test_valid_signature_accepted_in_both_modes_verify_digest(key, low_s_sig):
    vk = key.verifying_key
    digest = hashlib.sha256(example_data).digest()
    sig = key.sign_digest(digest, sigencode=sigencode_string)
    r, s = sigdecode_string(sig, key.curve.order)
    r, s = _canonize(r, s, key.curve.order)
    sig = sigencode_string(r, s, key.curve.order)
    assert vk.verify_digest(sig, digest)
    assert vk.verify_digest(sig, digest, strict=True)


def test_high_s_accepted_by_default_rejected_in_strict_raw(key, high_s_sig):
    vk = key.verifying_key
    sig = _raw(high_s_sig, key.curve.order)
    # default behaviour is unchanged: high-S verifies fine
    assert vk.verify(sig, example_data)
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, strict=True)
    assert "high-S" in str(exc_info.value)


def test_high_s_accepted_by_default_rejected_in_strict_der(key, high_s_sig):
    vk = key.verifying_key
    sig = _der(high_s_sig, key.curve.order)
    assert vk.verify(sig, example_data, sigdecode=sigdecode_der)
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)
    assert "high-S" in str(exc_info.value)


def test_r_zero_rejected_in_strict_raw(key, low_s_sig):
    vk = key.verifying_key
    order = key.curve.order
    sig = sigencode_string(0, low_s_sig[1], order)
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, strict=True)
    assert "r not in range" in str(exc_info.value)


def test_r_zero_rejected_in_strict_der(key, low_s_sig):
    vk = key.verifying_key
    order = key.curve.order
    sig = sigencode_der(0, low_s_sig[1], order)
    with pytest.raises(BadSignatureError):
        vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)


def test_s_zero_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    order = key.curve.order
    sig = sigencode_string(low_s_sig[0], 0, order)
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, strict=True)
    assert "s not in range" in str(exc_info.value)


def test_s_equal_n_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    order = key.curve.order
    sig = number_to_string(low_s_sig[0], order) + number_to_string(
        order, order
    )
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, strict=True)
    assert "s not in range" in str(exc_info.value)


def test_r_equal_n_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    order = key.curve.order
    sig = number_to_string(order, order) + number_to_string(
        low_s_sig[1], order
    )
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, strict=True)
    assert "r not in range" in str(exc_info.value)


def test_negative_integer_in_der_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    order = key.curve.order
    # hand-craft a DER signature with a negative r (0x80 as first byte
    # of the integer content means negative in two's complement)
    neg_r = b"\x02\x01\x80"
    s_enc = encode_integer(low_s_sig[1])
    sig = encode_sequence(neg_r + s_enc)
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)
    assert "Malformed formatting of signature" in str(exc_info.value)


def test_non_minimal_der_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    # hand-craft a DER signature where r has an unnecessary leading zero
    # byte (the value 0x7f doesn't need the 0x00 padding)
    padded_r = b"\x02\x02\x00\x7f"
    s_enc = encode_integer(low_s_sig[1])
    sig = encode_sequence(padded_r + s_enc)
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)
    assert "Malformed formatting of signature" in str(exc_info.value)


def test_trailing_bytes_after_der_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    sig = _der(low_s_sig, key.curve.order) + b"\x00"
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)
    assert "Malformed formatting of signature" in str(exc_info.value)


def test_raw_signature_one_byte_too_long_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    sig = _raw(low_s_sig, key.curve.order) + b"\x00"
    assert len(sig) == 2 * orderlen(key.curve.order) + 1
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, strict=True)
    assert "Malformed formatting of signature" in str(exc_info.value)


def test_raw_signature_one_byte_too_short_rejected_in_strict(key, low_s_sig):
    vk = key.verifying_key
    sig = _raw(low_s_sig, key.curve.order)[:-1]
    assert len(sig) == 2 * orderlen(key.curve.order) - 1
    with pytest.raises(BadSignatureError) as exc_info:
        vk.verify(sig, example_data, strict=True)
    assert "Malformed formatting of signature" in str(exc_info.value)


def test_der_signature_rejected_by_strict_raw_entry(key, low_s_sig):
    """The same signature in DER encoding must not pass the raw entry."""
    vk = key.verifying_key
    sig = _der(low_s_sig, key.curve.order)
    # sanity check: it verifies through the DER entry
    assert vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)
    with pytest.raises(BadSignatureError):
        vk.verify(sig, example_data, strict=True)


def test_raw_signature_rejected_by_strict_der_entry(key, low_s_sig):
    """The same signature in raw encoding must not pass the DER entry."""
    vk = key.verifying_key
    sig = _raw(low_s_sig, key.curve.order)
    # sanity check: it verifies through the raw entry
    assert vk.verify(sig, example_data, strict=True)
    with pytest.raises(BadSignatureError):
        vk.verify(sig, example_data, sigdecode=sigdecode_der, strict=True)


def test_strict_rejects_unknown_sigdecode(key, low_s_sig):
    vk = key.verifying_key
    sig = _raw(low_s_sig, key.curve.order)

    def custom_decoder(signature, order):
        return sigdecode_string(signature, order)

    with pytest.raises(ValueError):
        vk.verify(sig, example_data, sigdecode=custom_decoder, strict=True)


def test_strict_decoders_are_public_and_functional(key, low_s_sig):
    order = key.curve.order
    raw = _raw(low_s_sig, order)
    assert sigdecode_string_strict(raw, order) == low_s_sig
    der_sig = _der(low_s_sig, order)
    assert sigdecode_der_strict(der_sig, order) == low_s_sig


def test_eddsa_unaffected_by_strict_flag():
    sk = SigningKey.generate(curve=Ed25519)
    vk = sk.verifying_key
    sig = sk.sign(example_data)
    assert vk.verify(sig, example_data)
    # the strict flag must not change the EdDSA code path
    assert vk.verify(sig, example_data, strict=True)
    with pytest.raises(BadSignatureError):
        vk.verify(sig, b"other data", strict=True)
