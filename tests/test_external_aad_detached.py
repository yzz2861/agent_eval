"""
Tests for explicit external AAD and detached payload handling on Enc0Message.
Sign1Message coverage lives in tests/test_sign1message.py.
"""
import cbor2
import pytest
from cryptography.exceptions import InvalidTag

from pycose import headers
from pycose.exceptions import CoseException, CoseIllegalExternalAad
from pycose.keys.keyops import EncryptOp, DecryptOp
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.enc0message import Enc0Message


IV = b'0123456789ab'
PLAINTEXT = b'secret plaintext value'
EXTERNAL_AAD = b'some critical external data'


def _make_key():
    key = SymmetricKey.generate_key(key_len=16, optional_params={'ALG': 'A128GCM'})
    key.key_ops = [EncryptOp, DecryptOp]
    return key


def _make_message(key):
    return Enc0Message(phdr={'ALG': 'A128GCM'}, uhdr={headers.IV: IV}, key=key)


def test_explicit_external_aad_round_trip():
    key = _make_key()
    msg = _make_message(key)
    msg.payload = PLAINTEXT

    encoded = msg.encode(external_aad=EXTERNAL_AAD)
    assert msg.external_aad == b''

    decoded = Enc0Message.decode(encoded)
    decoded.key = key
    assert decoded.decrypt(external_aad=EXTERNAL_AAD) == PLAINTEXT
    assert decoded.external_aad == b''


def test_truncated_external_aad_fails_authentication():
    key = _make_key()
    msg = _make_message(key)
    msg.payload = PLAINTEXT
    encoded = msg.encode(external_aad=EXTERNAL_AAD)

    decoded = Enc0Message.decode(encoded)
    decoded.key = key

    with pytest.raises(InvalidTag):
        decoded.decrypt(external_aad=EXTERNAL_AAD[:-1])


def test_empty_external_aad_round_trip():
    key = _make_key()
    msg = _make_message(key)
    msg.payload = PLAINTEXT

    encoded = msg.encode(external_aad=b'')

    decoded = Enc0Message.decode(encoded)
    decoded.key = key
    assert decoded.decrypt(external_aad=b'') == PLAINTEXT


def test_empty_aad_does_not_decrypt_non_empty_aad_message():
    key = _make_key()
    msg = _make_message(key)
    msg.payload = PLAINTEXT
    encoded = msg.encode(external_aad=EXTERNAL_AAD)

    decoded = Enc0Message.decode(encoded)
    decoded.key = key

    with pytest.raises(InvalidTag):
        decoded.decrypt(external_aad=b'')


def test_external_aad_length_limit_is_configurable():
    key = _make_key()
    msg = _make_message(key)
    msg.payload = PLAINTEXT
    msg.MAX_EXTERNAL_AAD_LENGTH = 4

    with pytest.raises(CoseIllegalExternalAad, match='exceeds the maximum allowed length'):
        msg.encode(external_aad=b'12345')

    assert msg.external_aad == b''
    encoded = msg.encode(external_aad=b'1234')
    decoded = Enc0Message.decode(encoded)
    decoded.key = key
    decoded.MAX_EXTERNAL_AAD_LENGTH = 4
    assert decoded.decrypt(external_aad=b'1234') == PLAINTEXT


def test_detached_payload_encrypt_and_decrypt():
    key = _make_key()
    msg = _make_message(key)

    encoded, detached_ciphertext = msg.encode(detached_payload=PLAINTEXT, external_aad=EXTERNAL_AAD)

    assert cbor2.loads(encoded).value[2] is None
    assert isinstance(detached_ciphertext, bytes) and len(detached_ciphertext) > 0

    decoded = Enc0Message.decode(encoded)
    decoded.key = key
    assert decoded.payload is None
    assert decoded.decrypt(detached_payload=detached_ciphertext, external_aad=EXTERNAL_AAD) == PLAINTEXT


def test_detached_payload_missing_on_decrypt():
    key = _make_key()
    msg = _make_message(key)
    encoded, detached_ciphertext = msg.encode(detached_payload=PLAINTEXT, external_aad=EXTERNAL_AAD)

    decoded = Enc0Message.decode(encoded)
    decoded.key = key

    with pytest.raises(CoseException, match='Missing payload and no detached payload provided'):
        decoded.decrypt(external_aad=EXTERNAL_AAD)


def test_detached_and_attached_payload_are_mutually_exclusive():
    key = _make_key()
    msg = _make_message(key)
    msg.payload = PLAINTEXT

    with pytest.raises(CoseException, match='Detached payload must be None when payload is set'):
        msg.encrypt(detached_payload=b'other plaintext')


def test_detached_payload_with_truncated_aad_fails():
    key = _make_key()
    msg = _make_message(key)
    encoded, detached_ciphertext = msg.encode(detached_payload=PLAINTEXT, external_aad=EXTERNAL_AAD)

    decoded = Enc0Message.decode(encoded)
    decoded.key = key

    with pytest.raises(InvalidTag):
        decoded.decrypt(detached_payload=detached_ciphertext, external_aad=EXTERNAL_AAD[:-1])


def test_detached_payload_with_empty_aad_round_trip():
    key = _make_key()
    msg = _make_message(key)
    encoded, detached_ciphertext = msg.encode(detached_payload=PLAINTEXT, external_aad=b'')

    decoded = Enc0Message.decode(encoded)
    decoded.key = key
    assert decoded.decrypt(detached_payload=detached_ciphertext, external_aad=b'') == PLAINTEXT
