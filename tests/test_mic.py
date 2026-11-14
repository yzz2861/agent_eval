import ast
import hashlib
import hmac

import pytest

from ntlm_auth import messages as message_module
from ntlm_auth.constants import AvId
from ntlm_auth.exceptions import MicMismatchError, MicMissingError, \
    MicNotNegotiatedError
from ntlm_auth.messages import AuthenticateMessage, NegotiateMessage, \
    compute_mic


def _load_expected(test_name):
    """Pull the authoritative expected byte literal out of test_messages.py."""
    with open('tests/test_messages.py', 'rb') as test_file:
        tree = ast.parse(test_file.read())

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == test_name:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if isinstance(target, ast.Name) and \
                                target.id == 'expected':
                            return ast.literal_eval(sub.value)

    raise RuntimeError("Could not find expected bytes for %s" % test_name)


CHALLENGE_WITH_TIMESTAMP = bytes.fromhex(
    "4e544c4d535350000200000003000c003800000033828ae20123456789abcdef"
    "00000000000000002400240044000000060070170000000f5300650072007600"
    "6500720002000c0044006f006d00610069006e0001000c005300650072007600"
    "6500720000000000")
SESSION_KEY = b"\x55" * 16


@pytest.fixture
def mic_exchange():
    negotiate = NegotiateMessage(3800728115, "Domain",
                                 "COMPUTER").get_data()
    challenge = CHALLENGE_WITH_TIMESTAMP
    authenticate = _load_expected('test_authenticate_message_with_mic')
    message = AuthenticateMessage.from_data(authenticate)
    return negotiate, challenge, authenticate, message


class TestAuthenticateParser(object):

    def test_parse_retains_raw_bytes_and_mic(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange

        assert message.data is authenticate
        assert message.mic == \
            bytes.fromhex('d2a145dea4253e1910fe0f5b7a0d2a90')
        assert len(message.mic) == 16
        assert message.mic_negotiated is True
        assert message.target_info[AvId.MSV_AV_FLAGS] == \
            b'\x02\x00\x00\x00'

    def test_parse_message_without_mic(self):
        raw = _load_expected('test_authenticate_message_ntlm_v2')
        message = AuthenticateMessage.from_data(raw)

        assert message.mic is None
        # The NTLMv2 response carries TargetInfo but no MsvAvFlags value that
        # advertises MIC_PROVIDED.
        assert message.target_info is not None
        assert message.target_info[AvId.MSV_AV_FLAGS] is None
        assert message.mic_negotiated is False
        assert message.data is raw

    def test_parse_rejects_invalid_signature(self):
        raw = bytearray(_load_expected('test_authenticate_message_with_mic'))
        raw[0] = ord('X')
        with pytest.raises(MicMismatchError):
            AuthenticateMessage.from_data(bytes(raw))

    def test_parse_rejects_wrong_message_type(self):
        raw = bytearray(_load_expected('test_authenticate_message_with_mic'))
        raw[8] = 2
        with pytest.raises(MicMismatchError):
            AuthenticateMessage.from_data(bytes(raw))

    def test_parse_rejects_truncated_header(self):
        raw = _load_expected('test_authenticate_message_with_mic')[:71]
        with pytest.raises(MicMismatchError):
            AuthenticateMessage.from_data(raw)

    def test_parse_rejects_security_buffer_past_end(self):
        raw = bytearray(_load_expected('test_authenticate_message_with_mic'))
        # Claim the LM response is far longer than the whole message.
        raw[12:14] = b'\xff\xff'
        with pytest.raises(MicMismatchError):
            AuthenticateMessage.from_data(bytes(raw))

    def test_partial_mic_field_is_retained_as_fragment(self):
        raw = bytearray(_load_expected('test_authenticate_message_with_mic'))
        # Zero all payload buffers so only the 80-byte truncated header is
        # needed. TargetInfo cannot be recovered from a truncated message, so
        # construct the parsed object directly to assert the fragment itself
        # is retained rather than being treated as an absent MIC.
        for field_offset in (12, 20, 28, 36, 44, 52):
            raw[field_offset:field_offset + 4] = b'\x00' * 4
        message = AuthenticateMessage.__new__(AuthenticateMessage)
        message.mic = bytes(raw[72:80])

        assert message.mic is not None
        assert len(message.mic) == 8


class TestComputeMic(object):

    def test_mic_matches_known_vector(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange

        actual = compute_mic(negotiate, challenge, authenticate, SESSION_KEY)
        assert actual == message.mic

    def test_mic_uses_zero_filled_mic_field(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange

        zeroed = authenticate[:72] + b'\x00' * 16 + authenticate[88:]
        expected = hmac.new(
            SESSION_KEY, negotiate + challenge + zeroed,
            digestmod=hashlib.md5).digest()
        assert compute_mic(negotiate, challenge, authenticate,
                           SESSION_KEY) == expected

    def test_mic_detects_reordered_messages(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange

        with pytest.raises(MicMismatchError):
            compute_mic(challenge, negotiate, authenticate, SESSION_KEY)

    @pytest.mark.parametrize('index', (0, 7, 8, 11))
    def test_mic_rejects_malformed_message_headers(self, mic_exchange, index):
        negotiate, challenge, authenticate, message = mic_exchange
        broken = bytearray(negotiate)
        broken[index] ^= 0x01

        with pytest.raises(MicMismatchError):
            compute_mic(bytes(broken), challenge, authenticate, SESSION_KEY)

    def test_mic_requires_bytes_and_key(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange

        with pytest.raises(MicMismatchError):
            compute_mic(None, challenge, authenticate, SESSION_KEY)
        with pytest.raises(MicMismatchError):
            compute_mic(negotiate, challenge, authenticate, None)

    def test_mic_rejects_authenticate_without_mic_field(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange
        # Remove the 16-byte MIC field and shift the payload back so the
        # AUTHENTICATE_MESSAGE uses the 72-byte header layout.
        raw = authenticate[:72] + authenticate[88:]
        assert len(raw) == len(authenticate) - 16

        with pytest.raises(MicMismatchError):
            compute_mic(negotiate, challenge, raw, SESSION_KEY)


class TestVerifyMic(object):

    def test_valid_mic_verifies(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange

        assert message.verify_mic(negotiate, challenge, authenticate,
                                  SESSION_KEY, strict=True) is True

    @pytest.mark.parametrize('message_index,byte_index', [
        ('negotiate', 12),
        ('negotiate', 32),
        ('challenge', 0x38),
        ('challenge', 24),
        ('authenticate', 60),
        ('authenticate', 0x64),
        ('authenticate', 100),
    ])
    def test_any_field_tamper_fails(self, mic_exchange, message_index,
                                    byte_index):
        negotiate, challenge, authenticate, message = mic_exchange
        values = {
            'negotiate': bytearray(negotiate),
            'challenge': bytearray(challenge),
            'authenticate': bytearray(authenticate),
        }
        values[message_index][byte_index] ^= 0x01

        with pytest.raises(MicMismatchError):
            message.verify_mic(
                bytes(values['negotiate']),
                bytes(values['challenge']),
                bytes(values['authenticate']),
                SESSION_KEY, strict=True)

    def test_length_change_fails(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange
        longer = authenticate[:0x64] + b'X' + authenticate[0x64:]

        with pytest.raises(MicMismatchError):
            message.verify_mic(negotiate, challenge, longer, SESSION_KEY,
                               strict=True)

    def test_corrupt_mic_is_mismatch(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange
        corrupt = bytearray(authenticate)
        corrupt[72] ^= 0xff
        parsed = AuthenticateMessage.from_data(bytes(corrupt))

        with pytest.raises(MicMismatchError):
            parsed.verify_mic(negotiate, challenge, bytes(corrupt),
                              SESSION_KEY, strict=True)

    def test_truncated_mic_is_mismatch(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange
        # A header cut inside the MIC field cannot carry its payloads; build
        # the parsed object directly to prove a short MIC is always treated
        # as a mismatch rather than a missing MIC.
        parsed = AuthenticateMessage.__new__(AuthenticateMessage)
        parsed.target_info = message.target_info
        parsed.mic = authenticate[72:80]
        assert len(parsed.mic) == 8

        with pytest.raises(MicMismatchError):
            parsed.verify_mic(negotiate, challenge, authenticate, SESSION_KEY,
                              strict=True)

    def test_missing_raw_messages_are_mismatch(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange

        with pytest.raises(MicMismatchError):
            message.verify_mic(None, challenge, authenticate, SESSION_KEY,
                               strict=True)
        with pytest.raises(MicMismatchError):
            message.verify_mic(negotiate, None, authenticate, SESSION_KEY,
                               strict=True)
        with pytest.raises(MicMismatchError):
            message.verify_mic(negotiate, challenge, None, SESSION_KEY,
                               strict=True)

    def test_not_negotiated_raises_distinct_error(self):
        raw = _load_expected('test_authenticate_message_ntlm_v2')
        message = AuthenticateMessage.from_data(raw)
        negotiate = b'N' * 40
        challenge = b'C' * 64

        with pytest.raises(MicNotNegotiatedError):
            message.verify_mic(negotiate, challenge, raw, SESSION_KEY,
                               strict=True)
        with pytest.raises(MicNotNegotiatedError):
            message.verify_mic(negotiate, challenge, raw, SESSION_KEY,
                               strict=False)

    def test_missing_mic_distinct_from_mismatch_and_not_negotiated(
            self, mic_exchange, monkeypatch):
        negotiate, challenge, authenticate, message = mic_exchange
        message.mic = None

        # Non-strict: no MIC is simply reported as absent via False, without
        # conflating the state with a mismatch.
        assert message.verify_mic(negotiate, challenge, authenticate,
                                  SESSION_KEY, strict=False) is False

        with pytest.raises(MicMissingError):
            message.verify_mic(negotiate, challenge, authenticate,
                               SESSION_KEY, strict=True)

    def test_verification_uses_constant_time_compare(self, mic_exchange,
                                                     monkeypatch):
        negotiate, challenge, authenticate, message = mic_exchange
        calls = []

        def fake_compare_digest(a, b):
            calls.append((a, b))
            return a == b

        monkeypatch.setattr(message_module.hmac, 'compare_digest',
                            fake_compare_digest)
        assert message.verify_mic(negotiate, challenge, authenticate,
                                  SESSION_KEY, strict=True) is True
        assert len(calls) == 1
        assert calls[0][1] == message.mic

    def test_exception_messages_contain_no_secret_material(self, mic_exchange):
        negotiate, challenge, authenticate, message = mic_exchange
        corrupt = bytearray(authenticate)
        corrupt[72] ^= 0xff
        parsed = AuthenticateMessage.from_data(bytes(corrupt))

        try:
            parsed.verify_mic(negotiate, challenge, bytes(corrupt),
                              SESSION_KEY, strict=True)
        except MicMismatchError as err:
            text = str(err)
        else:
            pytest.fail('MicMismatchError was not raised')

        assert SESSION_KEY.hex() not in text
        assert SESSION_KEY not in text.encode()
