"""diagnostic error-path tests for truncated/spliced/tampered PGP data"""
import pytest

from pgpy import PGPMessage
from pgpy.errors import PGPArmorCRCError
from pgpy.errors import PGPArmorError
from pgpy.errors import PGPArmorHeaderError
from pgpy.errors import PGPError
from pgpy.errors import PGPPacketError
from pgpy.errors import PGPParseError
from pgpy.types import Armorable


@pytest.fixture(scope="module")
def armored_message():
    return PGPMessage.from_file("tests/testdata/blocks/message.onepass.asc")


@pytest.fixture(scope="module")
def armor_text(armored_message):
    return str(armored_message)


@pytest.fixture(scope="module")
def packet_blob(armored_message):
    return bytes(armored_message)


def _line_offset(text, line_index):
    return sum(len(line) + 1 for line in text.splitlines()[:line_index])


class TestErrorHierarchy(object):
    def test_types(self):
        assert issubclass(PGPParseError, PGPError)
        assert issubclass(PGPArmorError, PGPParseError)
        assert issubclass(PGPArmorHeaderError, PGPArmorError)
        assert issubclass(PGPArmorCRCError, PGPArmorError)
        assert issubclass(PGPPacketError, PGPParseError)
        # backwards compatibility: armor failures used to surface as ValueError
        assert issubclass(PGPArmorError, ValueError)


class TestArmorDiagnostics(object):
    def test_truncated_armor_missing_tail(self, armor_text):
        end_offset = armor_text.index("-----END")
        truncated = armor_text[:end_offset]
        with pytest.raises(PGPArmorHeaderError) as exc_info:
            Armorable.ascii_unarmor(truncated)
        err = exc_info.value
        assert err.offset == end_offset
        assert isinstance(err, PGPError)

    def test_truncated_armor_missing_crc_line(self, armor_text):
        crc_index = next(i for i, line in enumerate(armor_text.splitlines())
                         if line.startswith("="))
        truncated = "\n".join(armor_text.splitlines()[:crc_index]) + "\n"
        expected_offset = _line_offset(armor_text, crc_index)
        with pytest.raises(PGPArmorError) as exc_info:
            Armorable.ascii_unarmor(truncated)
        assert exc_info.value.offset == expected_offset

    def test_truncated_armor_missing_begin(self):
        with pytest.raises(PGPArmorError) as exc_info:
            Armorable.ascii_unarmor("not an armor block at all\n")
        assert exc_info.value.offset == 0

    def test_truncated_armor_cut_in_header(self, armor_text):
        # cut the block off in the middle of the BEGIN line
        truncated = armor_text[:12]
        with pytest.raises(PGPArmorError) as exc_info:
            Armorable.ascii_unarmor(truncated)
        assert exc_info.value.offset == 0

    def test_mismatched_armor_tail(self, armor_text):
        lines = armor_text.splitlines()
        end_index = next(i for i, line in enumerate(lines) if line.startswith("-----END"))
        lines[end_index] = "-----END PGP SIGANTURE-----"
        tampered = "\n".join(lines) + "\n"
        with pytest.raises(PGPArmorHeaderError) as exc_info:
            Armorable.ascii_unarmor(tampered)
        assert exc_info.value.offset == _line_offset(armor_text, end_index)

    def test_bad_crc24_points_at_crc_line(self, armor_text):
        lines = armor_text.splitlines()
        crc_index = next(i for i, line in enumerate(lines) if line.startswith("="))
        lines[crc_index] = "=abcd"
        tampered = "\n".join(lines) + "\n"
        with pytest.raises(PGPArmorCRCError) as exc_info:
            Armorable.ascii_unarmor(tampered)
        err = exc_info.value
        assert err.offset == _line_offset(armor_text, crc_index)
        assert err.expected != err.actual
        assert err.actual == Armorable.crc24(Armorable.ascii_unarmor(armor_text)["body"])

    def test_bad_crc24_through_message_parse_keeps_partial(self, armor_text):
        lines = armor_text.splitlines()
        crc_index = next(i for i, line in enumerate(lines) if line.startswith("="))
        lines[crc_index] = "=abcd"
        msg = PGPMessage()
        with pytest.raises(PGPArmorCRCError) as exc_info:
            msg.parse("\n".join(lines) + "\n")
        assert exc_info.value.partial is msg

    def test_malformed_body_character_offset(self, armor_text):
        lines = armor_text.splitlines()
        body_index = next(i for i, line in enumerate(lines)
                          if line and line[0] not in "-=" and not line.endswith(":") and ": " not in line)
        lines[body_index] = lines[body_index][:-1] + "!"
        tampered = "\n".join(lines) + "\n"
        with pytest.raises(PGPArmorError) as exc_info:
            Armorable.ascii_unarmor(tampered)
        assert exc_info.value.offset == _line_offset(armor_text, body_index)


class TestPacketDiagnostics(object):
    def test_cross_packet_truncation_first_packet(self, packet_blob):
        # first packet (OnePassSignature, 15 bytes) is cut short
        for cut in (1, 2, 5, 10):
            msg = PGPMessage()
            with pytest.raises(PGPPacketError) as exc_info:
                msg.parse(bytearray(packet_blob[:cut]))
            err = exc_info.value
            assert err.offset == 0
            assert err.partial is msg

    def test_cross_packet_truncation_second_packet(self, packet_blob):
        # first packet parses fine; the LiteralData packet starting at offset 15 is truncated
        msg = PGPMessage()
        with pytest.raises(PGPPacketError) as exc_info:
            msg.parse(bytearray(packet_blob[:30]))
        err = exc_info.value
        assert err.offset == 15
        assert err.tag == 11
        assert "Truncated packet" in str(err)
        # nothing was consumed past the corruption point
        assert msg._message is None

    def test_truncation_inside_final_packet(self, packet_blob):
        # the trailing Signature packet starts at offset 55; shave bytes off the end
        msg = PGPMessage()
        with pytest.raises(PGPPacketError) as exc_info:
            msg.parse(bytearray(packet_blob[:-1]))
        err = exc_info.value
        assert err.offset == 55
        assert err.tag == 2
        # earlier packets were fully parsed and retained on the partial message
        assert msg._message is not None
        assert len(msg._signatures) == 0

    def test_invalid_header_byte_offset(self):
        # 0x20 lacks the mandatory high bit of a packet header
        msg = PGPMessage()
        with pytest.raises(PGPPacketError) as exc_info:
            msg.parse(bytearray(b"\x20\x03"))
        assert exc_info.value.offset == 0

    def test_unknown_packet_tag_offset(self):
        # new-format header (0x80 | 0x40) with reserved tag 15, followed by a length byte
        data = bytearray(b"\xcf\x05abc")
        msg = PGPMessage()
        with pytest.raises(PGPPacketError) as exc_info:
            msg.parse(data)
        err = exc_info.value
        assert err.offset == 0
        assert err.tag == 15
        assert "Unknown or reserved packet tag" in str(err)

    def test_malformed_field_wraps_bare_exception(self, packet_blob):
        # flip the version byte of the signature packet to trigger a field-level failure
        # inside packet parsing, which must be wrapped with the absolute offset
        tampered = bytearray(packet_blob)
        sig_offset = 55
        tampered[sig_offset + 2] = 0x7f
        msg = PGPMessage()
        with pytest.raises(PGPPacketError) as exc_info:
            msg.parse(tampered)
        assert exc_info.value.offset == sig_offset
        assert isinstance(exc_info.value, PGPError)

    def test_all_good_data_still_parses(self, packet_blob):
        msg = PGPMessage()
        msg.parse(bytearray(packet_blob))
        assert len(msg._signatures) == 1
        assert msg._message is not None
