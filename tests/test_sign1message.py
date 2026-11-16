import cbor2
import pytest

from pycose.exceptions import CoseException, CoseIllegalAlgorithm, CoseIllegalKeyOps, CoseIllegalExternalAad
from pycose.keys import OKPKey, EC2Key
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.messages.sign1message import Sign1Message


def test_sign1_encoding(test_sign1):
    test_input = test_sign1['input']
    test_output = test_sign1['output']

    msg = Sign1Message(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        external_aad=test_input['external_aad'])

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._create_sig_structure() == test_output['structure']

    key = CoseKey.from_dict(test_sign1["cek"])
    key.key_ops = [SignOp, VerifyOp]
    msg.key = key

    assert msg.compute_signature() == test_output['signature']
    assert cbor2.loads(msg.encode(tag=test_sign1['cbor_tag'])) == test_output['result']


def test_sign1_decoding(test_sign1):
    if not test_sign1['cbor_tag']:
        pytest.skip("Missing CBOR tag")

    test_input = test_sign1['input']
    test_output = test_sign1['output']

    msg = Sign1Message.decode(cbor2.dumps(test_output['result']))
    msg.external_aad = test_input['external_aad']

    key = CoseKey.from_dict(test_sign1["cek"])
    key.key_ops = [VerifyOp]
    msg.key = key

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    assert msg.verify_signature()


def test_detached_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key

    encoded = msg.encode(detached_payload=payload)

    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key

    assert msg.payload is None

    assert msg.verify_signature(detached_payload=payload)


def test_attach_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    # Sign with detached payload
    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key
    encoded = msg.encode(detached_payload=payload)

    # Decode, attach payload, and re-encode
    msg = Sign1Message.decode(encoded)
    msg.payload = payload
    sig = msg.signature
    encoded = msg.encode(sign=False)

    # Decode and verify
    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key
    assert msg.verify_signature()

    # Make sure re-encoding didn't change the signature
    assert msg.signature == sig


def test_detach_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    # Sign with attached payload
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=payload)
    msg.key = ec2_key
    encoded = msg.encode()

    # Decode, detach payload, and re-encode
    msg = Sign1Message.decode(encoded)
    msg.payload = None
    sig = msg.signature
    encoded = msg.encode(sign=False)

    # Decode and verify
    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key
    assert msg.verify_signature(detached_payload=payload)

    # Make sure re-encoding didn't change the signature
    assert msg.signature == sig


def test_fail_on_missing_payload_signing():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key

    with pytest.raises(CoseException, match="Missing payload"):
        msg.encode()


def test_fail_on_missing_payload_verification():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key
    encoded = msg.encode(detached_payload=payload)

    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key

    with pytest.raises(CoseException, match="Missing payload"):
        msg.verify_signature()


@pytest.mark.parametrize('alg', ['ES384', 'ES512'])
def test_fail_on_non_matching_algorithms_phdr(alg):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': alg})
    msg.key = ec2_key

    with pytest.raises(CoseIllegalAlgorithm) as excinfo:
        msg.encode()

    assert "Conflicting algorithms" in str(excinfo.value)


@pytest.mark.parametrize('ops',
                         ['VERIFY', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP',
                          'DERIVE_KEY', 'DERIVE_BITS', 'MAC_CREATE', 'MAC_VERIFY'])
def test_fail_on_illegal_keyops_signing(ops):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'KEY_OPS': [ops]})
    msg.key = ec2_key

    with pytest.raises(CoseIllegalKeyOps) as excinfo:
        msg.encode()

    assert "Illegal key operations specified." in str(excinfo.value)


@pytest.mark.parametrize('ops',
                         ['SIGN', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP',
                          'DERIVE_KEY', 'DERIVE_BITS', 'MAC_CREATE', 'MAC_VERIFY'])
def test_fail_on_illegal_keyops_verifying(ops):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256')
    msg.key = ec2_key

    msg = msg.encode()

    msg = Sign1Message.decode(msg)
    # set an illegal key op
    if ops in {'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP', 'MAC_CREATE', 'MAC_VERIFY'}:
        with pytest.raises(CoseIllegalKeyOps) as excinfo:
            ec2_key.key_ops = [ops]

        assert "Invalid COSE key operation" in str(excinfo.value)
        return
    else:
        ec2_key.key_ops = [ops]

    msg.key = ec2_key

    with pytest.raises(CoseIllegalKeyOps) as excinfo:
        msg.verify_signature()

    assert "Illegal key operations specified." in str(excinfo.value)


# ---------------------------------------------------------------------------
# Explicit external AAD handling
# ---------------------------------------------------------------------------


def test_external_aad_is_covered_byte_for_byte():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    payload = b'signed message'
    external_aad = b'some critical external data'

    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=payload)
    msg.key = ec2_key
    encoded = msg.encode(external_aad=external_aad)

    # The explicitly supplied AAD must not leak onto the message object.
    assert msg.external_aad == b''

    decoded = Sign1Message.decode(encoded)
    decoded.key = ec2_key

    # The exact AAD participates in the signature and verification succeeds.
    assert decoded.verify_signature(external_aad=external_aad)
    assert decoded.external_aad == b''

    # A truncated AAD changes the authenticated structure and fails verification.
    assert not decoded.verify_signature(external_aad=external_aad[:-1])


def test_empty_external_aad_round_trip():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    payload = b'signed message'

    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=payload)
    msg.key = ec2_key

    # An explicit empty AAD is accepted both at signing and at verification.
    encoded = msg.encode(external_aad=b'')
    decoded = Sign1Message.decode(encoded)
    decoded.key = ec2_key
    assert decoded.verify_signature(external_aad=b'')


def test_empty_aad_does_not_verify_non_empty_aad_message():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    payload = b'signed message'
    external_aad = b'authenticated-side-data'

    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=payload, external_aad=external_aad)
    msg.key = ec2_key
    encoded = msg.encode()

    decoded = Sign1Message.decode(encoded)
    decoded.key = ec2_key

    # Verifying with an empty AAD must fail because the original AAD was non-empty.
    assert not decoded.verify_signature(external_aad=b'')
    # The original AAD still verifies.
    assert decoded.verify_signature(external_aad=external_aad)


def test_external_aad_length_limit_is_configurable():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    payload = b'signed message'

    class LimitedSign1Message(Sign1Message):
        MAX_EXTERNAL_AAD_LENGTH = 4

    msg = LimitedSign1Message(phdr={'ALG': 'ES256'}, payload=payload)
    msg.key = ec2_key

    # An AAD exceeding the configured limit is rejected.
    with pytest.raises(CoseIllegalExternalAad, match='exceeds the maximum allowed length'):
        msg.encode(external_aad=b'12345')

    # The failed override must not mutate the message state.
    assert msg.external_aad == b''

    # An AAD exactly at the limit is accepted.
    assert msg.encode(external_aad=b'1234')


def test_external_aad_length_limit_instance_override():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=b'signed message')
    msg.key = ec2_key
    msg.MAX_EXTERNAL_AAD_LENGTH = 3

    with pytest.raises(CoseIllegalExternalAad, match='exceeds the maximum allowed length'):
        msg.external_aad = b'1234'

    msg.external_aad = b'123'
    assert msg.external_aad == b'123'


def test_external_aad_must_be_bytes():
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=b'signed message')
    with pytest.raises(TypeError, match='external_aad must be of type'):
        msg.external_aad = 'not-bytes'


def test_detached_payload_with_explicit_aad():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    payload = b'signed message'
    external_aad = b'detached-aad'

    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key
    encoded = msg.encode(detached_payload=payload, external_aad=external_aad)

    decoded = Sign1Message.decode(encoded)
    decoded.key = ec2_key
    assert decoded.payload is None

    # Both the detached payload and the AAD must be supplied for verification.
    assert decoded.verify_signature(detached_payload=payload, external_aad=external_aad)

    # The wrong AAD breaks verification even with the correct detached payload.
    assert not decoded.verify_signature(detached_payload=payload, external_aad=external_aad[:-1])

    # A detached payload is mutually exclusive with an attached payload.
    decoded.payload = b'other content'
    with pytest.raises(CoseException, match='Detached payload must be None'):
        decoded.verify_signature(detached_payload=payload, external_aad=external_aad)
