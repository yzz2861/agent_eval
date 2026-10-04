# frozen_string_literal: true
require 'test/unit'
require 'uri'

class URI::TestIncrementalDecoder < Test::Unit::TestCase
  Decoder = URI::IncrementalDecoder

  def decode_all(chunks, **opts)
    dec = Decoder.new(**opts)
    out = +""
    chunks.each { |chunk| out << dec.feed(chunk) }
    out << dec.finish
    out
  end

  def test_single_shot_component
    assert_equal "a+b! ", decode_all(["a+b%21%20"])
  end

  def test_single_shot_form
    assert_equal "a b! ", decode_all(["a+b%21%20"], mode: :form)
  end

  def test_plus_handling_per_mode
    assert_equal "+", decode_all(["+"], mode: :component)
    assert_equal " ", decode_all(["+"], mode: :form)
    assert_equal "+", decode_all(["%2B"], mode: :component)
    assert_equal "+", decode_all(["%2B"], mode: :form)
  end

  def test_split_escape_sequence
    dec = Decoder.new
    assert_equal "", dec.feed("%")
    assert_equal "", dec.feed("4")
    assert_equal "A", dec.feed("1")
    assert_equal "", dec.finish
  end

  def test_split_escape_across_many_chunks
    assert_equal "A", decode_all(["%", "4", "1"])
    assert_equal "AB", decode_all("%41%42".chars)
  end

  def test_split_multibyte_character
    dec = Decoder.new
    assert_equal "", dec.feed("%E4%BD")
    assert_equal "你", dec.feed("%A0")
    assert_equal "", dec.finish
  end

  def test_multibyte_character_not_emitted_early
    dec = Decoder.new
    assert_equal "", dec.feed("%E4")
    assert_equal "你", dec.feed("%BD%A0%E5")
    out = dec.feed("%A5%BD")
    assert_equal "好", out
    assert_equal Encoding::UTF_8, out.encoding
    assert_predicate out, :valid_encoding?
    assert_equal "", dec.finish
  end

  def test_chunked_equals_one_shot
    input = "q=%E4%BD%A0%E5%A5%BD+%26+%3F&x=%41%42%43"
    expected = URI.decode_www_form_component(input)
    (1..8).each do |n|
      chunks = input.chars.each_slice(n).map(&:join)
      assert_equal expected, decode_all(chunks, mode: :form), "slice size #{n}"
    end
  end

  def test_output_encoding
    dec = Decoder.new(encoding: Encoding::US_ASCII)
    out = dec.feed("abc")
    assert_equal Encoding::US_ASCII, out.encoding
    assert_equal "abc", out
    assert_equal "", dec.finish
  end

  def test_output_encoding_string_name
    dec = Decoder.new(encoding: "UTF-8")
    assert_equal Encoding::UTF_8, dec.encoding
  end

  def test_binary_encoding_emits_immediately
    dec = Decoder.new(encoding: Encoding::BINARY)
    assert_equal "\xE4".b, dec.feed("%E4")
    assert_equal "".b, dec.finish
  end

  def test_utf16_output_holds_incomplete_unit
    dec = Decoder.new(encoding: Encoding::UTF_16LE)
    assert_equal "", dec.feed("%61")       # low byte of 'a' only
    out = dec.feed("%00")                  # completes "a" in UTF-16LE
    assert_equal "a".encode(Encoding::UTF_16LE), out
    assert_equal "", dec.finish
  end

  def test_invalid_bytes_pass_through
    dec = Decoder.new
    out = dec.feed("%FF")
    assert_equal "\xFF".b, out.b
    assert_not_predicate out, :valid_encoding?
    assert_equal "", dec.finish
  end

  def test_invalid_escape_raises_with_offset
    dec = Decoder.new
    dec.feed("abc")
    error = assert_raise(Decoder::InvalidEscapeError) { dec.feed("xy%zz") }
    assert_equal 5, error.offset
    assert_equal "%zz", error.fragment
  end

  def test_invalid_escape_offset_across_chunks
    dec = Decoder.new
    dec.feed("hello ")
    dec.feed("wor")
    error = assert_raise(Decoder::InvalidEscapeError) { dec.feed("ld%2g") }
    assert_equal 11, error.offset
    assert_equal "%2g", error.fragment
  end

  def test_percent_at_chunk_end_is_not_an_error
    dec = Decoder.new
    assert_equal "a", dec.feed("a%")
    assert_equal "A", dec.feed("41")
    assert_equal "", dec.finish
  end

  def test_truncated_input_at_finish
    dec = Decoder.new
    dec.feed("ab%")
    error = assert_raise(Decoder::TruncatedInputError) { dec.finish }
    assert_equal 2, error.offset
    assert_equal "%", error.fragment
  end

  def test_truncated_input_single_hex_digit
    dec = Decoder.new
    dec.feed("ab%4")
    error = assert_raise(Decoder::TruncatedInputError) { dec.finish }
    assert_equal 2, error.offset
    assert_equal "%4", error.fragment
  end

  def test_truncated_offset_counts_all_chunks
    dec = Decoder.new
    dec.feed("foo")
    dec.feed("bar%")
    error = assert_raise(Decoder::TruncatedInputError) { dec.finish }
    assert_equal 6, error.offset
  end

  def test_feed_after_failure_raises_state_error
    dec = Decoder.new
    assert_raise(Decoder::InvalidEscapeError) { dec.feed("%zz") }
    assert_predicate dec, :failed?
    assert_raise(Decoder::StateError) { dec.feed("abc") }
    assert_raise(Decoder::StateError) { dec.finish }
  end

  def test_feed_after_truncated_finish_raises_state_error
    dec = Decoder.new
    dec.feed("%")
    assert_raise(Decoder::TruncatedInputError) { dec.finish }
    assert_raise(Decoder::StateError) { dec.feed("a") }
  end

  def test_feed_after_finish_raises_state_error
    dec = Decoder.new
    dec.feed("a")
    dec.finish
    assert_predicate dec, :finished?
    assert_raise(Decoder::StateError) { dec.feed("b") }
    assert_raise(Decoder::StateError) { dec.finish }
  end

  def test_reset_recovers_from_failure
    dec = Decoder.new(mode: :form)
    assert_raise(Decoder::InvalidEscapeError) { dec.feed("%zz") }
    assert_same dec, dec.reset
    assert_not_predicate dec, :failed?
    assert_equal "a b", dec.feed("a+b")
    assert_equal "", dec.finish
  end

  def test_reset_recovers_after_finish
    dec = Decoder.new
    dec.feed("a")
    dec.finish
    dec.reset
    assert_equal "b", dec.feed("b")
    assert_equal "", dec.finish
  end

  def test_unknown_mode
    assert_raise(ArgumentError) { Decoder.new(mode: :bogus) }
  end

  def test_non_string_chunk
    dec = Decoder.new
    assert_raise(TypeError) { dec.feed(42) }
  end

  def test_empty_feed
    dec = Decoder.new
    assert_equal "", dec.feed("")
    assert_equal "", dec.finish
  end

  def test_consecutive_escapes_split
    dec = Decoder.new
    assert_equal "", dec.feed("%4")
    assert_equal "A", dec.feed("1%4")
    assert_equal "B", dec.feed("2")
    assert_equal "", dec.finish
  end

  def test_matches_decode_www_form_component
    [
      "Here+are+some+punctuation+characters%3A+%2C%3B%3F%3A",
      "*.-_azAZ09",
      "%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C",
      "a%2bb%2Bc",
    ].each do |input|
      assert_equal URI.decode_www_form_component(input),
                   decode_all([input], mode: :form), input
      assert_equal URI.decode_uri_component(input),
                   decode_all([input], mode: :component), input
    end
  end
end
