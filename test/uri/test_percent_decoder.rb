# frozen_string_literal: true
require 'test/unit'
require 'uri'

class URI::TestPercentDecoder < Test::Unit::TestCase
  def test_component_mode_decodes_escapes_and_keeps_plus
    assert_equal "a b+c", URI::PercentDecoder.decode("a%20b%2Bc")
  end

  def test_form_mode_decodes_plus_as_space
    assert_equal "a b+c", URI::PercentDecoder.decode("a+b%2Bc", mode: :form)
  end

  def test_mode_accepts_strings
    assert_equal "a b", URI::PercentDecoder.decode("a+b", mode: "form")
  end

  def test_unknown_mode_raises
    assert_raise(ArgumentError) { URI::PercentDecoder.new(mode: :bogus) }
  end

  def test_feed_returns_ready_output_and_finish_completes
    decoder = URI::PercentDecoder.new
    assert_equal "ab", decoder.feed("ab")
    assert_equal "", decoder.finish
    assert_predicate decoder, :finished?
  end

  def test_split_escape_across_chunks
    decoder = URI::PercentDecoder.new
    assert_equal "", decoder.feed("%")
    assert_equal "", decoder.feed("4")
    assert_equal "A", decoder.feed("1")
    assert_equal "", decoder.finish
  end

  def test_split_multibyte_character_across_chunks
    decoder = URI::PercentDecoder.new
    assert_equal "", decoder.feed("%E4%B8")
    assert_equal "中", decoder.feed("%AD")
    assert_equal "", decoder.finish
  end

  def test_split_literal_multibyte_character_across_chunks
    bytes = "中".b
    decoder = URI::PercentDecoder.new
    assert_equal "", decoder.feed(bytes.byteslice(0, 2))
    assert_equal "中", decoder.feed(bytes.byteslice(2, 1))
  end

  def test_output_is_not_released_before_character_completes
    decoder = URI::PercentDecoder.new
    assert_equal "a", decoder.feed("a%E4")
    assert_equal "", decoder.feed("%B8")
    assert_equal "中b", decoder.feed("%ADb")
  end

  def test_invalid_escape_reports_input_offset
    decoder = URI::PercentDecoder.new
    error = assert_raise(URI::PercentDecoder::InvalidEscapeError) do
      decoder.feed("abc%xy")
    end
    assert_equal 3, error.offset
    assert_equal "%x", error.sequence
  end

  def test_invalid_escape_at_second_hex_digit
    decoder = URI::PercentDecoder.new
    error = assert_raise(URI::PercentDecoder::InvalidEscapeError) do
      decoder.feed("%4g")
    end
    assert_equal 0, error.offset
    assert_equal "%4g", error.sequence
  end

  def test_invalid_escape_offset_accumulates_across_chunks
    decoder = URI::PercentDecoder.new
    decoder.feed("abcde")
    error = assert_raise(URI::PercentDecoder::InvalidEscapeError) do
      decoder.feed("f%zz")
    end
    assert_equal 6, error.offset
  end

  def test_finish_with_incomplete_escape
    decoder = URI::PercentDecoder.new
    decoder.feed("ab%")
    error = assert_raise(URI::PercentDecoder::TruncatedInputError) { decoder.finish }
    assert_equal 2, error.offset
    assert_equal "%", error.fragment
  end

  def test_finish_with_incomplete_escape_hex_digit
    decoder = URI::PercentDecoder.new
    decoder.feed("ab%4")
    error = assert_raise(URI::PercentDecoder::TruncatedInputError) { decoder.finish }
    assert_equal 2, error.offset
    assert_equal "%4", error.fragment
  end

  def test_finish_with_incomplete_character
    decoder = URI::PercentDecoder.new
    decoder.feed("x%E4%B8")
    error = assert_raise(URI::PercentDecoder::TruncatedInputError) { decoder.finish }
    assert_equal 1, error.offset
    assert_equal "\xE4\xB8".b, error.fragment
  end

  def test_invalid_byte_sequence_reports_input_offset
    decoder = URI::PercentDecoder.new
    error = assert_raise(URI::PercentDecoder::InvalidByteSequenceError) do
      decoder.feed("ok%FF")
    end
    assert_equal 2, error.offset
    assert_equal "\xFF".b, error.bytes
  end

  def test_invalid_byte_sequence_offset_points_at_escape_start
    decoder = URI::PercentDecoder.new
    error = assert_raise(URI::PercentDecoder::InvalidByteSequenceError) do
      decoder.feed("%C3%28")
    end
    assert_equal 0, error.offset
  end

  def test_decoder_is_dead_after_error
    decoder = URI::PercentDecoder.new
    assert_raise(URI::PercentDecoder::InvalidEscapeError) { decoder.feed("%zz") }
    assert_predicate decoder, :failed?
    assert_raise(URI::PercentDecoder::StateError) { decoder.feed("ok") }
    assert_raise(URI::PercentDecoder::StateError) { decoder.finish }
  end

  def test_decoder_is_dead_after_finish
    decoder = URI::PercentDecoder.new
    decoder.finish
    assert_raise(URI::PercentDecoder::StateError) { decoder.feed("ok") }
    assert_raise(URI::PercentDecoder::StateError) { decoder.finish }
  end

  def test_type_error_keeps_decoder_usable
    decoder = URI::PercentDecoder.new
    assert_raise(TypeError) { decoder.feed(nil) }
    assert_equal "ok", decoder.feed("ok")
  end

  def test_output_encoding_option
    decoder = URI::PercentDecoder.new(encoding: "Shift_JIS")
    assert_equal "", decoder.feed("%93")
    output = decoder.feed("%FA")
    assert_equal Encoding::Shift_JIS, output.encoding
    assert_equal "日".encode(Encoding::Shift_JIS), output
  end

  def test_output_encoding_validates_bytes
    decoder = URI::PercentDecoder.new(encoding: Encoding::US_ASCII)
    assert_raise(URI::PercentDecoder::InvalidByteSequenceError) do
      decoder.feed("%E4%B8%AD")
    end
  end

  def test_binary_encoding_passes_bytes_through
    decoder = URI::PercentDecoder.new(encoding: Encoding::BINARY)
    output = decoder.feed("%FF%FE")
    assert_equal "\xFF\xFE".b, output
    assert_equal "", decoder.finish
  end

  def test_empty_feed
    decoder = URI::PercentDecoder.new
    assert_equal "", decoder.feed("")
    assert_equal "", decoder.finish
  end

  def test_empty_finish_with_pending_escape
    decoder = URI::PercentDecoder.new
    decoder.feed("%")
    assert_raise(URI::PercentDecoder::TruncatedInputError) { decoder.finish }
  end

  def test_self_decode_matches_decode_www_form_component
    string = "a%20b%2Bc+%E4%B8%AD"
    assert_equal URI.decode_www_form_component(string),
                 URI::PercentDecoder.decode(string, mode: :form)
  end

  def test_self_decode_component_mode
    assert_equal "a+b 中", URI::PercentDecoder.decode("a+b%20%E4%B8%AD")
  end

  def test_chunk_boundaries_everywhere
    input = "a%20%E4%B8%AD+z%2B"
    expected = "a 中 z+"
    (0..input.length).each do |i|
      (i..input.length).each do |j|
        decoder = URI::PercentDecoder.new(mode: :form)
        output = decoder.feed(input[0...i]) +
                 decoder.feed(input[i...j]) +
                 decoder.feed(input[j..]) +
                 decoder.finish
        assert_equal expected, output, "split at #{i}, #{j}"
      end
    end
  end
end
