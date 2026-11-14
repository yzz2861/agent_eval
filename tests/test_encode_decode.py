"""
Test for the integer encoding/decoding functionality in the HPACK library.
"""
import pytest

from hypothesis import given
from hypothesis.strategies import integers, binary, one_of

from hpack import HPACKDecodingError, InvalidTableSizeError, OversizedHeaderListError
from hpack.hpack import Decoder, encode_integer, decode_integer


def _table_size_update(size):
    """Build a dynamic table size update representation (001xxxxx)."""
    encoded = encode_integer(size, 5)
    encoded[0] |= 0x20
    return bytes(encoded)


def _literal_with_indexing(name, value):
    """Build a literal header field with incremental indexing."""
    return b"\x40" + bytes([len(name)]) + name + bytes([len(value)]) + value


class TestDecoderTableSizeUpdates:
    """
    Dynamic table size updates have a strict position, ordering and upper
    bound, and a failed block must never leave partial state behind.
    """

    def test_repeated_size_updates_at_start_apply_in_order(self):
        """
        Several size updates in the leading preamble are all applied, in
        order, before any header is decoded.
        """
        decoder = Decoder()
        data = _table_size_update(256) + _table_size_update(0) + b"\x82"

        assert decoder.decode(data) == [(":method", "GET")]
        assert decoder.header_table_size == 0
        assert len(decoder.header_table.dynamic_entries) == 0

    def test_repeated_size_updates_remain_compatible_with_eviction(self):
        """
        A legal encoder may shrink, regrow and re-index entries across
        multiple size updates and ordinary table eviction.
        """
        decoder = Decoder()
        first = _table_size_update(1) + _table_size_update(4096)
        indexed_header = _literal_with_indexing(b"name", b"value")

        assert decoder.decode(first + indexed_header) == [("name", "value")]
        assert len(decoder.header_table.dynamic_entries) == 1

        # Shrink so the entry gets evicted, then grow again and re-index it.
        second = _table_size_update(1) + _table_size_update(4096) + indexed_header
        assert decoder.decode(second) == [("name", "value")]
        assert len(decoder.header_table.dynamic_entries) == 1
        assert decoder.header_table.get_by_index(62) == (b"name", b"value")

    def test_size_zero_clears_the_dynamic_table(self):
        decoder = Decoder()
        decoder.decode(_literal_with_indexing(b"name", b"value"))
        assert len(decoder.header_table.dynamic_entries) == 1

        headers = decoder.decode(_table_size_update(0) + b"\x82")

        assert headers == [(":method", "GET")]
        assert decoder.header_table_size == 0
        assert len(decoder.header_table.dynamic_entries) == 0

    def test_negative_table_size_is_rejected_without_mutating_state(self):
        decoder = Decoder()
        original_size = decoder.header_table_size

        with pytest.raises(InvalidTableSizeError):
            decoder.header_table_size = -1

        assert decoder.header_table_size == original_size

    def test_update_above_limit_reports_index_and_phase(self):
        decoder = Decoder()
        decoder.max_allowed_table_size = 100
        # Two single-byte updates: 20 is fine, then 200 exceeds the limit.
        # The second update starts at byte index 1.
        data = _table_size_update(20) + _table_size_update(200)

        with pytest.raises(InvalidTableSizeError) as exc_info:
            decoder.decode(data)

        message = str(exc_info.value)
        assert "byte index 1" in message
        assert "table size update phase" in message
        # Nothing from the rejected block is committed.
        assert decoder.header_table_size == 4096

    def test_size_update_after_header_reports_index_and_phase(self):
        decoder = Decoder()
        # An indexed header (one byte), then a size update at byte index 1.
        data = b"\x82" + _table_size_update(0)

        with pytest.raises(HPACKDecodingError) as exc_info:
            decoder.decode(data)

        message = str(exc_info.value)
        assert "byte index 1" in message
        assert "header field phase" in message

    def test_failed_block_rolls_back_successful_updates_and_headers(self):
        """
        If a later update fails, earlier updates from the same block are not
        partially committed.
        """
        decoder = Decoder()
        decoder.max_allowed_table_size = 100
        data = (
            _table_size_update(50)
            + _table_size_update(0)
            + _table_size_update(200)
        )

        with pytest.raises(InvalidTableSizeError):
            decoder.decode(data)

        assert decoder.header_table_size == 4096

    def test_oversized_block_rolls_back_table_mutations(self):
        decoder = Decoder(max_header_list_size=10)
        data = (
            _literal_with_indexing(b"name", b"value")
            + _literal_with_indexing(b"other", b"header")
        )

        with pytest.raises(OversizedHeaderListError):
            decoder.decode(data)

        assert decoder.header_table_size == 4096
        assert len(decoder.header_table.dynamic_entries) == 0


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
