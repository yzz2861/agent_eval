import pytest

from hpack import Decoder, HPACKDecodingError
from hpack.hpack import decode_integer, encode_integer
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
from hpack.huffman_table import decode_huffman

from hypothesis import given, example
from hypothesis.strategies import binary


class TestHuffman:

    def test_request_huffman_decoder(self):
        assert (
            decode_huffman(b'\xf1\xe3\xc2\xe5\xf2:k\xa0\xab\x90\xf4\xff') ==
            b"www.example.com"
        )
        assert decode_huffman(b'\xa8\xeb\x10d\x9c\xbf') == b"no-cache"
        assert decode_huffman(b'%\xa8I\xe9[\xa9}\x7f') == b"custom-key"
        assert (
            decode_huffman(b'%\xa8I\xe9[\xb8\xe8\xb4\xbf') == b"custom-value"
        )

    def test_request_huffman_encode(self):
        encoder = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
        assert (
            encoder.encode(b"www.example.com") ==
            b'\xf1\xe3\xc2\xe5\xf2:k\xa0\xab\x90\xf4\xff'
        )
        assert encoder.encode(b"no-cache") == b'\xa8\xeb\x10d\x9c\xbf'
        assert encoder.encode(b"custom-key") == b'%\xa8I\xe9[\xa9}\x7f'
        assert (
            encoder.encode(b"custom-value") == b'%\xa8I\xe9[\xb8\xe8\xb4\xbf'
        )


class TestHuffmanDecoder:
    @given(data=binary())
    @example(b'\xff')
    @example(b'\x5f\xff\xff\xff\xff')
    @example(b'\x00\x3f\xff\xff\xff')
    def test_huffman_decoder_properly_handles_all_bytestrings(self, data):
        """
        When given random bytestrings, either we get HPACKDecodingError or we
        get a bytestring back.
        """
        # The examples aren't special, they're just known to hit specific error
        # paths through the state machine. Basically, they are strings that are
        # definitely invalid.
        try:
            result = decode_huffman(data)
        except HPACKDecodingError:
            result = b''

        assert isinstance(result, bytes)


class TestHuffmanDecodingStrictness:
    """
    RFC 7541 Section 5.2 requires strict validation of Huffman-coded strings:
    the EOS symbol must not appear, and padding must be an EOS prefix, i.e.
    at most 7 bits, all set to 1.
    """

    def test_eos_symbol_rejected(self):
        # Four 0xff bytes contain the 30-bit EOS symbol (30 one-bits).
        with pytest.raises(HPACKDecodingError, match="EOS"):
            decode_huffman(b'\xff\xff\xff\xff')

    def test_eos_symbol_after_valid_data_rejected(self):
        # b'\x1f' decodes to b'a'; the following 30 one-bits are EOS.
        with pytest.raises(HPACKDecodingError, match="EOS"):
            decode_huffman(b'\x1f\xff\xff\xff\xff')

    def test_eos_error_reports_input_offset(self):
        # The EOS symbol completes within the byte at offset 3.
        with pytest.raises(HPACKDecodingError, match="offset 3"):
            decode_huffman(b'\xff\xff\xff\xff')

    def test_large_input_with_eos_rejected(self):
        # A 64kB input of one-bits hits the EOS symbol almost immediately.
        with pytest.raises(HPACKDecodingError, match="EOS"):
            decode_huffman(b'\xff' * 65536)

    def test_padding_must_be_all_ones(self):
        # b'a' is the 5-bit code 00011; padding it with zero bits is invalid.
        with pytest.raises(HPACKDecodingError, match="padding"):
            decode_huffman(b'\x18')

    def test_padding_must_not_exceed_seven_bits(self):
        # b'a' followed by 11 one-bits: more than 7 padding bits is invalid.
        with pytest.raises(HPACKDecodingError, match="padding"):
            decode_huffman(b'\x1f\xff')

    def test_truncated_code_rejected(self):
        # A zero byte starts a code but never finishes it.
        with pytest.raises(HPACKDecodingError, match="Incomplete"):
            decode_huffman(b'\x00')

    def test_maximal_seven_bit_padding_accepted(self):
        # b'a' (5 bits), b'b' and b'd' (6 bits each) total 17 bits, so the
        # encoder appends exactly 7 one-bits of padding.
        encoder = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
        encoded = encoder.encode(b'abd')
        assert len(encoded) == 3
        assert decode_huffman(encoded) == b'abd'

    def test_all_valid_bytes_round_trip(self):
        # Every legal symbol in the table must keep decoding identically.
        encoder = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
        for byte in range(256):
            data = bytes([byte])
            assert decode_huffman(encoder.encode(data)) == data


class TestBoundedIntegerDecoding:
    """
    Integer representations that exceed implementation limits in octet length
    must be treated as decoding errors (RFC 7541 Section 5.1).
    """

    def test_maximum_length_integer_accepted(self):
        # The largest encodable value within the 5-continuation-octet limit.
        value = 2 ** 35 + 30
        encoded = bytes(encode_integer(value, 5))
        assert len(encoded) == 6
        assert decode_integer(encoded, 5) == (value, 6)

    def test_too_many_octets_rejected(self):
        # The first value that needs a sixth continuation octet.
        value = 2 ** 35 + 31
        encoded = bytes(encode_integer(value, 5))
        assert len(encoded) == 7
        with pytest.raises(HPACKDecodingError, match="too long"):
            decode_integer(encoded, 5)

    def test_oversized_integer_error_reports_input_offset(self):
        encoded = bytes(encode_integer(2 ** 35 + 31, 5))
        with pytest.raises(HPACKDecodingError, match="offset 5"):
            decode_integer(encoded, 5)

    def test_unbounded_continuation_octets_rejected(self):
        with pytest.raises(HPACKDecodingError, match="too long"):
            decode_integer(b'\xff' + b'\x80' * 64 + b'\x01', 5)

    def test_truncated_integer_rejected(self):
        with pytest.raises(HPACKDecodingError, match="truncated"):
            decode_integer(b'\x1f', 5)

    def test_truncated_integer_error_reports_input_offset(self):
        with pytest.raises(HPACKDecodingError, match="offset 2"):
            decode_integer(b'\x1f\x9a', 5)

    def test_empty_input_rejected(self):
        with pytest.raises(HPACKDecodingError):
            decode_integer(b'', 5)


class TestDecoderFailureAtomicity:
    """
    A decoding failure anywhere in a header block must abort the whole
    block: no partially decoded header list may be returned, and the error
    must point at the offset in the input where decoding failed.
    """

    def test_valid_header_followed_by_truncated_literal(self):
        decoder = Decoder()
        # b'\x82' is the indexed :method: GET; b'\x00' starts a literal
        # header whose name length octet is missing.
        with pytest.raises(HPACKDecodingError, match="offset 1"):
            decoder.decode(b'\x82\x00')

    def test_valid_header_followed_by_huffman_eos(self):
        decoder = Decoder()
        # A literal header whose Huffman-encoded name contains the EOS
        # symbol must fail the whole block.
        data = b'\x82' + b'\x00\x84\xff\xff\xff\xff' + b'\x00'
        with pytest.raises(HPACKDecodingError, match="EOS"):
            decoder.decode(data)

    def test_valid_header_followed_by_oversized_integer(self):
        decoder = Decoder()
        # A literal header whose name length is encoded with an unbounded
        # variable-length integer must fail the whole block.
        data = b'\x82' + b'\x00\x7f' + b'\x80' * 8 + b'\x01'
        with pytest.raises(HPACKDecodingError, match="too long"):
            decoder.decode(data)

    def test_no_partial_header_list_on_failure(self):
        decoder = Decoder()
        # Two valid indexed headers followed by a truncated literal: the
        # decode must raise rather than return the first two headers.
        data = b'\x82\x87' + b'\x00\x85\xf2\xb2\x4a'
        with pytest.raises(HPACKDecodingError):
            decoder.decode(data)
