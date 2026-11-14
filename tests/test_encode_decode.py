"""
Test for the integer encoding/decoding functionality in the HPACK library.
"""
import pytest

from hypothesis import given
from hypothesis.strategies import integers, binary, one_of

from hpack import (
    Decoder,
    Encoder,
    HPACKDecodingError,
    NeverIndexedHeaderTuple,
    OversizedHeaderListError,
)
from hpack.hpack import encode_integer, decode_integer
from hpack.table import table_entry_size


class TestIntegerEncoding:
    # These tests are stolen from the HPACK spec.
    def test_encoding_10_with_5_bit_prefix(self):
        val = encode_integer(10, 5)
        assert len(val) == 1
        assert val == bytearray(b'\x0a')

    def test_encoding_1337_with_5_bit_prefix(self):
        val = encode_integer(1337, 5)
        assert len(val) == 3
        assert val == bytearray(b'\x1f\x9a\x0a')

    def test_encoding_42_with_8_bit_prefix(self):
        val = encode_integer(42, 8)
        assert len(val) == 1
        assert val == bytearray(b'\x2a')


class TestIntegerDecoding:
    # These tests are stolen from the HPACK spec.
    def test_decoding_10_with_5_bit_prefix(self):
        val = decode_integer(b'\x0a', 5)
        assert val == (10, 1)

    def test_encoding_1337_with_5_bit_prefix(self):
        val = decode_integer(b'\x1f\x9a\x0a', 5)
        assert val == (1337, 3)

    def test_encoding_42_with_8_bit_prefix(self):
        val = decode_integer(b'\x2a', 8)
        assert val == (42, 1)

    def test_decode_empty_string_fails(self):
        with pytest.raises(HPACKDecodingError):
            decode_integer(b'', 8)

    def test_decode_insufficient_data_fails(self):
        with pytest.raises(HPACKDecodingError):
            decode_integer(b'\x1f', 5)


class TestEncodingProperties:
    """
    Property-based tests for our integer encoder and decoder.
    """
    @given(
        integer=integers(min_value=0),
        prefix_bits=integers(min_value=1, max_value=8)
    )
    def test_encode_positive_integer_always_valid(self, integer, prefix_bits):
        """
        So long as the prefix bits are between 1 and 8, any positive integer
        can be represented.
        """
        result = encode_integer(integer, prefix_bits)
        assert isinstance(result, bytearray)
        assert len(result) > 0

    @given(
        integer=integers(max_value=-1),
        prefix_bits=integers(min_value=1, max_value=8)
    )
    def test_encode_fails_for_negative_integers(self, integer, prefix_bits):
        """
        If the integer to encode is negative, the encoder fails.
        """
        with pytest.raises(ValueError):
            encode_integer(integer, prefix_bits)

    @given(
        integer=integers(min_value=0),
        prefix_bits=one_of(
            integers(max_value=0),
            integers(min_value=9)
        )
    )
    def test_encode_fails_for_invalid_prefixes(self, integer, prefix_bits):
        """
        If the prefix is out of the range [1,8], the encoder fails.
        """
        with pytest.raises(ValueError):
            encode_integer(integer, prefix_bits)

    @given(
        prefix_bits=one_of(
            integers(max_value=0),
            integers(min_value=9)
        )
    )
    def test_decode_fails_for_invalid_prefixes(self, prefix_bits):
        """
        If the prefix is out of the range [1,8], the encoder fails.
        """
        with pytest.raises(ValueError):
            decode_integer(b'\x00', prefix_bits)

    @given(
        data=binary(),
        prefix_bits=integers(min_value=1, max_value=8)
    )
    def test_decode_either_succeeds_or_raises_error(self, data, prefix_bits):
        """
        Attempting to decode data either returns a positive integer or throws a
        HPACKDecodingError.
        """
        try:
            result, consumed = decode_integer(data, prefix_bits)
        except HPACKDecodingError:
            pass
        else:
            assert isinstance(result, int)
            assert result >= 0
            assert consumed > 0

    @given(
        integer=integers(min_value=0, max_value=2**32),
        prefix_bits=integers(min_value=1, max_value=8)
    )
    def test_encode_decode_round_trips(self, integer, prefix_bits):
        """
        Given valid data, the encoder and decoder can round trip.
        """
        encoded_result = encode_integer(integer, prefix_bits)
        decoded_integer, consumed = decode_integer(
            bytes(encoded_result), prefix_bits
        )
        assert integer == decoded_integer
        assert consumed > 0

    def test_decode_too_long_fails(self):
        """
        If the variable integer representation is too long, the decoder fails.
        """
        with pytest.raises(HPACKDecodingError):
            decode_integer(b'\xff\xff\xff\xff\xff\xff', 5)


class TestDecoderHeaderListSizeAccounting:
    """
    Tests for the header list size accounting in the unified decoder path.

    Per RFC 7541 Section 4.1, each entry counts as the length of its name
    plus the length of its value plus 32 bytes of overhead, accumulated
    across the entire header block (however many HEADERS/CONTINUATION
    fragments it was reassembled from). Decoding must stop before the limit
    is exceeded, without committing the oversized entry, and the decoder
    must remain usable for subsequent, independent header blocks.
    """

    def test_entry_size_includes_fixed_overhead(self):
        """
        A header whose name and value alone fit under the limit is still
        rejected once the 32-byte per-entry overhead is accounted for.
        """
        headers = [(b'a', b'x' * 10)]
        assert len(headers[0][0]) + len(headers[0][1]) < 40

        e = Encoder()
        d = Decoder(max_header_list_size=40)

        with pytest.raises(OversizedHeaderListError):
            d.decode(e.encode(headers, huffman=False))

    def test_header_list_exactly_at_limit_is_accepted(self):
        headers = [(b'hello', b'world')]
        limit = table_entry_size(*headers[0])

        e = Encoder()
        d = Decoder(max_header_list_size=limit)

        assert d.decode(e.encode(headers, huffman=False)) == [
            ('hello', 'world'),
        ]

    def test_header_list_one_byte_over_limit_is_rejected(self):
        headers = [(b'hello', b'world')]
        limit = table_entry_size(*headers[0]) - 1

        e = Encoder()
        d = Decoder(max_header_list_size=limit)

        with pytest.raises(OversizedHeaderListError):
            d.decode(e.encode(headers, huffman=False))

    def test_size_accumulates_across_entries_in_block(self):
        headers = [(b'a', b'1'), (b'b', b'2'), (b'c', b'3')]
        each = table_entry_size(b'a', b'1')
        assert each == table_entry_size(b'b', b'2') == table_entry_size(b'c', b'3')

        e = Encoder()
        block = e.encode(headers, huffman=False)

        # Exactly at the cumulative limit: accepted.
        Decoder(max_header_list_size=each * 3).decode(block)

        # One byte short of the cumulative limit: rejected.
        with pytest.raises(OversizedHeaderListError):
            Decoder(max_header_list_size=each * 3 - 1).decode(block)

    def test_highly_compressed_block_cannot_bypass_limit(self):
        """
        A block that is tiny on the wire (one literal plus many indexed
        references to it) still inflates beyond the limit and is rejected.
        """
        headers = [(b'x-long-header-name', b'v' * 200)] * 8
        inflated = sum(table_entry_size(n, v) for n, v in headers)

        e = Encoder()
        block = e.encode(headers, huffman=True)
        assert len(block) < inflated // 4

        d = Decoder(max_header_list_size=inflated - 1)
        with pytest.raises(OversizedHeaderListError):
            d.decode(block)

    def test_duplicate_headers_are_each_accounted(self):
        headers = [(b'x-dup', b'v')] * 3
        each = table_entry_size(*headers[0])

        e = Encoder()
        block = e.encode(headers, huffman=False)

        Decoder(max_header_list_size=each * 3).decode(block)
        with pytest.raises(OversizedHeaderListError):
            Decoder(max_header_list_size=each * 3 - 1).decode(block)

    def test_limit_applies_per_header_block(self):
        """
        The limit applies to each header block independently: decoding
        several blocks in a row on one decoder does not accumulate size
        across blocks.
        """
        headers = [(b'a', b'b')]
        limit = table_entry_size(*headers[0])

        e = Encoder()
        block = e.encode(headers, huffman=False)
        d = Decoder(max_header_list_size=limit)

        for _ in range(3):
            assert d.decode(block) == [('a', 'b')]

    def test_decoder_remains_usable_after_oversized_block(self):
        """
        After an OversizedHeaderListError the decoder is in a consistent
        state and a subsequent, independent header block decodes correctly.
        """
        e = Encoder()
        d = Decoder(max_header_list_size=128)

        with pytest.raises(OversizedHeaderListError):
            d.decode(e.encode([(b'x' * 64, b'y' * 64)], huffman=False))

        good = e.encode([(b':method', b'GET'), (b'x-ok', b'1')], huffman=False)
        assert d.decode(good) == [(':method', 'GET'), ('x-ok', '1')]

    def test_oversized_entry_is_not_committed_to_table(self):
        """
        Decoding stops before the limit is exceeded: entries that fit remain
        committed to the dynamic table, the oversized entry does not.
        """
        headers = [(b'x-first', b'1'), (b'x-second', b'2' * 100)]
        limit = table_entry_size(*headers[0])

        e = Encoder()
        d = Decoder(max_header_list_size=limit)

        with pytest.raises(OversizedHeaderListError):
            d.decode(e.encode(headers, huffman=False))

        assert list(d.header_table.dynamic_entries) == [(b'x-first', b'1')]

    @pytest.mark.parametrize('headers', [
        [NeverIndexedHeaderTuple(b'authorization', b's' * 100)],
        [(b'authorization', b's' * 100, True)],
    ])
    def test_sensitive_headers_count_toward_limit(self, headers):
        """
        Headers marked sensitive (never indexed) are accounted for just like
        any other header.
        """
        e = Encoder()
        d = Decoder(max_header_list_size=64)

        with pytest.raises(OversizedHeaderListError):
            d.decode(e.encode(headers, huffman=False))

    def test_error_does_not_leak_header_values(self):
        """
        The OversizedHeaderListError message contains neither the name nor
        the value of the sensitive header that tripped the limit.
        """
        secret = b'super-secret-token-value'
        headers = [NeverIndexedHeaderTuple(b'authorization', secret)]

        e = Encoder()
        d = Decoder(max_header_list_size=32)

        with pytest.raises(OversizedHeaderListError) as exc_info:
            d.decode(e.encode(headers, huffman=False))

        message = str(exc_info.value)
        assert 'authorization' not in message
        assert secret.decode('utf-8') not in message

    def test_casing_and_duplicate_headers_unchanged(self):
        """
        Case and duplicate headers round-trip unchanged through the
        accounting decoder path.
        """
        headers = [
            (b'X-Mixed-Case', b'Value-One'),
            (b'x-mixed-case', b'Value-One'),
            (b'X-Mixed-Case', b'Value-One'),
        ]

        e = Encoder()
        d = Decoder()

        assert d.decode(e.encode(headers, huffman=True), raw=True) == headers
