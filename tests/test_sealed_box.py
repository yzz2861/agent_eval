# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import annotations

import binascii

import pytest

from nacl.encoding import HexEncoder
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

from .utils import check_type_error, read_crypto_test_vectors


def sealbox_vectors() -> list[tuple[bytes, bytes, bytes, bytes]]:
    # Fmt: <recipient sk><tab><recipient pk><tab><pt_len>:<plaintext>
    # <tab><cr_len>:<ciphertext>[<tab> ...]

    def splitlen(x: bytes) -> bytes:
        ln, dta = x.split(b":")
        assert len(dta) == 2 * int(ln)
        return dta

    DATA = "sealed_box_ref.txt"
    return [
        (x[0], x[1], splitlen(x[2]), splitlen(x[3]))
        for x in read_crypto_test_vectors(DATA, maxels=4, delimiter=b"\t")
    ]


def test_generate_private_key():
    PrivateKey.generate()


def test_sealed_box_creation():
    pub = PublicKey(
        b"ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    priv = PrivateKey(
        b"5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    SealedBox(priv)
    SealedBox(pub)


@pytest.mark.parametrize(
    ("privalice", "pubalice", "plaintext", "_encrypted"), sealbox_vectors()
)
def test_sealed_box_encryption(
    privalice: bytes, pubalice: bytes, plaintext: bytes, _encrypted: bytes
):
    pubalice_decoded = PublicKey(pubalice, encoder=HexEncoder)
    privalice_decoded = PrivateKey(privalice, encoder=HexEncoder)

    box = SealedBox(pubalice_decoded)
    encrypted = box.encrypt(
        binascii.unhexlify(plaintext),
        encoder=HexEncoder,
    )

    assert encrypted != _encrypted
    # since SealedBox.encrypt uses an ephemeral sender's keypair

    box2 = SealedBox(privalice_decoded)
    decrypted = box2.decrypt(
        encrypted,
        encoder=HexEncoder,
    )
    assert binascii.hexlify(decrypted) == plaintext
    assert bytes(box) == bytes(box2)


@pytest.mark.parametrize(
    ("privalice", "_pubalice", "plaintext", "encrypted"), sealbox_vectors()
)
def test_sealed_box_decryption(
    privalice: bytes, _pubalice: bytes, plaintext: bytes, encrypted: bytes
):
    privalice_decoded = PrivateKey(privalice, encoder=HexEncoder)

    box = SealedBox(privalice_decoded)
    decrypted = box.decrypt(
        encrypted,
        encoder=HexEncoder,
    )
    assert binascii.hexlify(decrypted) == plaintext


def test_wrong_types():
    priv = PrivateKey.generate()

    check_type_error(
        ("SealedBox must be created from a PublicKey or a PrivateKey"),
        SealedBox,
        priv.encode(),
    )
    check_type_error(
        ("SealedBox must be created from a PublicKey or a PrivateKey"),
        SealedBox,
        priv.public_key.encode(),
    )
    with pytest.raises(TypeError):
        # Type safety: we want to check this error is detected at runtime.
        SealedBox(priv, priv.public_key)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("_privalice", "pubalice", "_plaintext", "encrypted"), sealbox_vectors()
)
def test_sealed_box_public_key_cannot_decrypt(
    _privalice: bytes, pubalice: bytes, _plaintext: bytes, encrypted: bytes
):
    pubalice_decoded = PublicKey(pubalice, encoder=HexEncoder)

    box = SealedBox(pubalice_decoded)
    with pytest.raises(TypeError):
        # Type safety: mypy spots that you can't decrypt with a public key, but we
        # want to detect this at runtime too.
        box.decrypt(  # type: ignore[misc]
            encrypted,
            encoder=HexEncoder,
        )


def test_sealed_box_zero_length_plaintext():
    empty_plaintext = b""
    k = PrivateKey.generate()
    enc_box = SealedBox(k.public_key)
    dec_box = SealedBox(k)

    msg = enc_box.encrypt(empty_plaintext)
    decoded = dec_box.decrypt(msg)

    assert decoded == empty_plaintext


def test_sealed_box_too_short_msg():
    empty_plaintext = b""
    k = PrivateKey.generate()
    enc_box = SealedBox(k.public_key)
    dec_box = SealedBox(k)

    msg = enc_box.encrypt(empty_plaintext)
    with pytest.raises(CryptoError):
        dec_box.decrypt(msg[:-1])

def test_sealed_box_truncated_ciphertext_raises_crypto_error():
    k = PrivateKey.generate()
    enc_box = SealedBox(k.public_key)
    dec_box = SealedBox(k)

    message = enc_box.encrypt(b"a non-empty sealed message")

    # Every prefix shorter than the SEALBYTES overhead is a truncated box
    # and must be rejected with the same CryptoError, never accepted as an
    # empty plaintext.
    for length in range(0, len(message)):
        with pytest.raises(CryptoError):
            dec_box.decrypt(message[:length])


def test_sealed_box_minimum_length_is_sealbytes():
    import nacl.bindings as bindings

    k = PrivateKey.generate()
    pk = bytes(k.public_key)
    sk = bytes(k)

    # A ciphertext shorter than SEALBYTES cannot hold even the embedded
    # ephemeral public key and MAC, so it must be rejected outright.
    for length in range(0, bindings.crypto_box_SEALBYTES):
        with pytest.raises(CryptoError):
            bindings.crypto_box_seal_open(b"\x00" * length, pk, sk)


def test_sealed_box_does_not_decrypt_truncated_input(monkeypatch):
    import nacl.bindings as crypto_box_module
    from nacl import _sodium

    k = PrivateKey.generate()
    pk = bytes(k.public_key)
    sk = bytes(k)

    calls = 0
    original = _sodium.lib.crypto_box_seal_open

    def _boom(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("native seal_open must not be invoked")

    monkeypatch.setattr(_sodium.lib, "crypto_box_seal_open", _boom)
    assert hasattr(crypto_box_module, "crypto_box_seal_open")
    for length in (0, 1, 16, 31, 47):
        with pytest.raises(CryptoError):
            crypto_box_module.crypto_box_seal_open(
                b"\x00" * length, pk, sk
            )
    assert calls == 0
    monkeypatch.setattr(_sodium.lib, "crypto_box_seal_open", original)


def test_sealed_box_wrong_key_rejects_without_leaking():
    recipient = PrivateKey.generate()
    other = PrivateKey.generate()
    enc_box = SealedBox(recipient.public_key)
    wrong_box = SealedBox(other)

    ciphertext = enc_box.encrypt(b"secret payload")

    with pytest.raises(CryptoError):
        wrong_box.decrypt(ciphertext)


def test_sealed_box_padding_is_not_accepted_as_plaintext():
    k = PrivateKey.generate()
    enc_box = SealedBox(k.public_key)
    dec_box = SealedBox(k)

    ciphertext = enc_box.encrypt(b"padded message")

    # Appending zero bytes changes the authenticated ciphertext length and
    # therefore fails the MAC check instead of being silently stripped.
    for padding in (1, 2, 16):
        with pytest.raises(CryptoError):
            dec_box.decrypt(ciphertext + b"\x00" * padding)


def test_sealed_box_legitimate_empty_message_still_roundtrips():
    k = PrivateKey.generate()
    enc_box = SealedBox(k.public_key)
    dec_box = SealedBox(k)

    ciphertext = enc_box.encrypt(b"")
    assert len(ciphertext) == 48
    assert dec_box.decrypt(ciphertext) == b""

    # A genuine SEALBYTES-long box that is corrupted is still rejected.
    damaged = bytearray(ciphertext)
    damaged[-1] ^= 1
    with pytest.raises(CryptoError):
        dec_box.decrypt(bytes(damaged))


def test_sealed_box_cross_language_reference_vectors_still_compatible():
    # The published libsodium cross-language reference vectors exercise the
    # exact wire format; they must continue to decrypt after hardening.
    for privalice, _pubalice, plaintext, encrypted in sealbox_vectors():
        priv = PrivateKey(privalice, encoder=HexEncoder)
        box = SealedBox(priv)
        decoded = box.decrypt(encrypted, encoder=HexEncoder)
        assert binascii.hexlify(decoded) == plaintext

