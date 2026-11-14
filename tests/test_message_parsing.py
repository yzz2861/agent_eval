import struct

import pytest

from ntlm_auth.constants import AvId, MessageTypes, NegotiateFlags, \
    NTLM_SIGNATURE
from ntlm_auth.exceptions import MalformedMessageError
from ntlm_auth.messages import ChallengeMessage, TargetInfo


REQUEST_TARGET = NegotiateFlags.NTLMSSP_REQUEST_TARGET
TARGET_INFO = NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO
VERSION = NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION
EXTENDED = NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY


def build_challenge(flags=0, target_name=(0, 0, 56), target_info=(0, 0, 56),
                    total=48, version=None, payload=b""):
    """Builds a raw CHALLENGE_MESSAGE with explicit security buffer fields."""
    msg = NTLM_SIGNATURE
    msg += struct.pack("<I", MessageTypes.NTLM_CHALLENGE)
    msg += struct.pack("<HHI", *target_name)
    msg += struct.pack("<I", flags)
    msg += b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    msg += b"\x00" * 8
    msg += struct.pack("<HHI", *target_info)
    if version is not None:
        msg += version
    msg += payload
    if len(msg) < total:
        msg += b"\x00" * (total - len(msg))
    return msg


def target_info_bytes():
    info = TargetInfo()
    info[AvId.MSV_AV_NB_DOMAIN_NAME] = b"do"
    info[AvId.MSV_AV_NB_COMPUTER_NAME] = b"pc"
    return info.pack()


class TestBoundedChallengeParsing(object):

    def test_rejects_truncated_fixed_header_exhaustively(self):
        valid = build_challenge()
        for size in range(0, 48):
            with pytest.raises(MalformedMessageError) as exc:
                ChallengeMessage(valid[:size])
            assert "type 2" in str(exc.value)
            assert "fixed_header" in str(exc.value)

    def test_rejects_bad_signature_without_echoing_bytes(self):
        msg = bytearray(build_challenge())
        msg[0] = ord("X")
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(bytes(msg))
        assert "signature" in str(exc.value)
        # The reason must not echo any raw bytes from the bad signature.
        assert "does not match the NTLMSSP signature" in str(exc.value)

    def test_rejects_wrong_message_type(self):
        msg = bytearray(build_challenge())
        msg[8:12] = struct.pack("<I", MessageTypes.NTLM_AUTHENTICATE)
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(bytes(msg))
        assert "message_type" in str(exc.value)
        assert "expected 2 but got 3" in str(exc.value)

    @pytest.mark.parametrize("length,offset", [
        (1, 47),       # single byte overshoot
        (2, 47),       # multi byte overshoot
        (0xffff, 0),   # maximum uint16 length
        (0xffff, 8),   # large length, small offset
        (0xff, 48),    # length reaches past the message
        (1, 0xffffffff),
    ])
    def test_target_name_out_of_bounds(self, length, offset):
        msg = build_challenge(
            flags=REQUEST_TARGET,
            target_name=(length, length, offset), total=48)
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg)
        assert "target_name" in str(exc.value)

    @pytest.mark.parametrize("length,offset", [
        (0x20, 0xfffffff0),
        (1, 0xffffffff),
        (0xffff, 0xffff0002),
    ])
    def test_target_name_offset_length_wrap(self, length, offset):
        msg = build_challenge(
            flags=REQUEST_TARGET,
            target_name=(length, length, offset), total=48)
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg)
        assert "wraps past the 32-bit limit" in str(exc.value)
        assert "target_name" in str(exc.value)

    @pytest.mark.parametrize("length,offset", [
        (0x10, 0xfffffff8),
        (0xffff, 0xffff0002),
    ])
    def test_target_info_offset_length_wrap(self, length, offset):
        msg = build_challenge(
            flags=TARGET_INFO,
            target_info=(length, length, offset), total=48)
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg)
        assert "target_info" in str(exc.value)
        assert "wraps past the 32-bit limit" in str(exc.value)

    def test_payload_inside_fixed_header_is_always_rejected(self):
        msg = build_challenge(
            flags=REQUEST_TARGET, target_name=(4, 4, 20), total=56)
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg)
        assert "overlaps the fixed header" in str(exc.value)

    def test_zero_length_field_accepts_any_offset(self):
        msg = build_challenge(
            flags=REQUEST_TARGET, target_name=(0, 0, 0xffffffff), total=48)
        for strict in (False, True):
            parsed = ChallengeMessage(msg, strict=strict)
            assert parsed.target_name == b""

    def test_zero_length_field_at_end_of_message(self):
        msg = build_challenge(
            flags=REQUEST_TARGET, target_name=(0, 0, 48), total=48)
        parsed = ChallengeMessage(msg, strict=True)
        assert parsed.target_name == b""

    def test_overlapping_payloads_lenient_but_strict_rejection(self):
        info = target_info_bytes()
        # The target_info is a valid AV_PAIR sequence starting at 48 while the
        # target name claims 50:58, so the ranges overlap while each slice is
        # still individually parseable.
        payload = info + b"A" * 8
        msg = build_challenge(
            flags=REQUEST_TARGET | TARGET_INFO,
            target_name=(8, 8, 50),
            target_info=(len(info), len(info), 48),
            total=48 + len(payload),
            payload=payload)
        lenient = ChallengeMessage(msg, strict=False)
        assert lenient.target_name == payload[2:10]

        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg, strict=True)
        assert "overlaps another field" in str(exc.value)
        assert "target_info" in str(exc.value)

    def test_adjacent_payloads_are_disjoint(self):
        info = target_info_bytes()
        name = b"srv"
        payload = name + info
        msg = build_challenge(
            flags=REQUEST_TARGET | TARGET_INFO,
            target_name=(len(name), len(name), 48),
            target_info=(len(info), len(info), 48 + len(name)),
            total=48 + len(payload), payload=payload)
        parsed = ChallengeMessage(msg, strict=True)
        assert parsed.target_name == name
        assert parsed.target_info.pack() == info

    def test_trailing_bytes_lenient_but_strict_rejection(self):
        msg = build_challenge(
            flags=REQUEST_TARGET, target_name=(4, 4, 48),
            total=56, payload=b"name")
        assert ChallengeMessage(msg, strict=False).target_name == b"name"

        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg + b"tail", strict=True)
        assert "trailing byte" in str(exc.value)

    def test_strict_rejects_maximum_length_smaller_than_length(self):
        msg = build_challenge(
            flags=REQUEST_TARGET, target_name=(4, 2, 48),
            total=56, payload=b"name")
        # Lenient parsing keeps the historical behaviour.
        assert ChallengeMessage(msg, strict=False).target_name == b"name"
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg, strict=True)
        assert "maximum_length" in str(exc.value)

    def test_valid_message_fields_are_byte_identical(self):
        info = target_info_bytes()
        name = "Server".encode("utf-16-le")
        version = b"\x06\x00\x70\x17\x00\x00\x00\x0f"
        payload = name + info
        msg = build_challenge(
            flags=REQUEST_TARGET | TARGET_INFO | VERSION | EXTENDED,
            target_name=(len(name), len(name), 56),
            target_info=(len(info), len(info), 56 + len(name)),
            total=56 + len(payload), payload=payload, version=version)
        parsed = ChallengeMessage(msg, strict=True)
        assert parsed.signature == NTLM_SIGNATURE
        assert parsed.message_type == MessageTypes.NTLM_CHALLENGE
        assert parsed.server_challenge == \
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        assert parsed.target_name == name
        assert parsed.target_info.pack() == info
        assert parsed.version == struct.unpack("<q", version)[0]
        assert parsed.get_data() == msg

    def test_error_messages_never_contain_sensitive_payload(self):
        secret_name = b"SENSITIVE-DOMAIN"
        msg = build_challenge(
            flags=REQUEST_TARGET,
            target_name=(len(secret_name), len(secret_name), 48),
            total=48)
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg)
        assert secret_name not in str(exc.value).encode()

    def test_error_messages_never_contain_challenge_bytes(self):
        secret_challenge = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
        msg = NTLM_SIGNATURE
        msg += struct.pack("<I", MessageTypes.NTLM_CHALLENGE)
        msg += struct.pack("<HHI", 0xffff, 0xffff, 0)
        msg += struct.pack("<I", REQUEST_TARGET)
        msg += secret_challenge
        msg += b"\x00" * 8
        msg += struct.pack("<HHI", 0, 0, 0)
        with pytest.raises(MalformedMessageError) as exc:
            ChallengeMessage(msg)
        assert secret_challenge not in str(exc.value).encode("latin-1")
        assert "type 2" in str(exc.value)
        assert "target_name" in str(exc.value)

    def test_flag_declared_field_with_zero_length_is_complete(self):
        # A declared but empty target info is structurally complete.
        msg = build_challenge(flags=TARGET_INFO, target_info=(0, 0, 0))
        parsed = ChallengeMessage(msg, strict=True)
        assert parsed.target_info is not None
        assert parsed.target_info.pack() == struct.pack("<HH", 0, 0)


class TestBoundedTargetInfoParsing(object):

    def test_valid_round_trip(self):
        raw = target_info_bytes()
        info = TargetInfo()
        info.unpack(raw, strict=True)
        assert info.pack() == raw

    @pytest.mark.parametrize("truncate_at", [1, 2, 3])
    def test_truncated_av_header(self, truncate_at):
        raw = struct.pack("<HH", AvId.MSV_AV_NB_DOMAIN_NAME, 4)[:truncate_at]
        with pytest.raises(MalformedMessageError) as exc:
            TargetInfo().unpack(raw)
        assert "target_info" in str(exc.value)

    def test_declared_av_value_runs_past_buffer(self):
        raw = struct.pack("<HH", AvId.MSV_AV_NB_DOMAIN_NAME, 10) + b"ab"
        with pytest.raises(MalformedMessageError) as exc:
            TargetInfo().unpack(raw)
        assert "av_value" in str(exc.value)

    def test_missing_eol_pair_is_rejected(self):
        raw = struct.pack("<HH", AvId.MSV_AV_NB_DOMAIN_NAME, 2) + b"ab"
        with pytest.raises(MalformedMessageError):
            TargetInfo().unpack(raw, strict=True)
        # Lenient mode still needs the bounded parse to terminate safely.
        with pytest.raises(MalformedMessageError):
            TargetInfo().unpack(raw, strict=False)

    def test_strict_rejects_trailing_av_bytes(self):
        raw = target_info_bytes()
        with pytest.raises(MalformedMessageError) as exc:
            TargetInfo().unpack(raw + b"x", strict=True)
        assert "trailing byte" in str(exc.value)

    def test_lenient_allows_trailing_av_bytes(self):
        raw = target_info_bytes()
        info = TargetInfo()
        info.unpack(raw + b"x", strict=False)
        assert info[AvId.MSV_AV_NB_DOMAIN_NAME] == b"do"

    def test_empty_buffer_is_an_empty_sequence(self):
        info = TargetInfo()
        info.unpack(b"", strict=True)
        assert info.fields == {}


class TestParsingResourceBounds(object):

    def test_large_declared_length_does_not_allocate_or_loop(self):
        # A 64 KiB declared length over a tiny message must fail immediately
        # without allocating the declared amount or iterating over it.
        msg = build_challenge(
            flags=REQUEST_TARGET, target_name=(0xffff, 0xffff, 0), total=48)
        for strict in (False, True):
            with pytest.raises(MalformedMessageError):
                ChallengeMessage(msg, strict=strict)

    def test_many_disjoint_payloads_share_one_budget(self):
        info = target_info_bytes()
        msg = build_challenge(
            flags=REQUEST_TARGET | TARGET_INFO,
            target_name=(1, 1, 48),
            target_info=(len(info), len(info), 49),
            total=49 + len(info), payload=b"x" + info)
        parsed = ChallengeMessage(msg, strict=True)
        assert parsed.target_name == b"x"
        assert parsed.target_info.pack() == info
