# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "../helper"

class TestCSVParseBadRecord < Test::Unit::TestCase
  extend DifferentOFS
  include CSVHelper

  # Runs +block+ once with the in-memory Scanner and, when scanner
  # test mode is enabled, repeatedly with tiny chunk sizes so that the
  # streaming InputsScanner code paths are exercised too.
  def with_each_scanner
    unless ENV["CSV_PARSER_SCANNER_TEST"] == "yes"
      yield
      return
    end
    [nil, 1, 2, 3, 5, 64].each do |size|
      if size.nil?
        keep_test = ENV["CSV_PARSER_SCANNER_TEST"]
        keep_chunk = ENV["CSV_PARSER_SCANNER_TEST_CHUNK_SIZE"]
        begin
          ENV["CSV_PARSER_SCANNER_TEST"] = "no"
          ENV["CSV_PARSER_SCANNER_TEST_CHUNK_SIZE"] = nil
          yield
        ensure
          ENV["CSV_PARSER_SCANNER_TEST"] = keep_test
          ENV["CSV_PARSER_SCANNER_TEST_CHUNK_SIZE"] = keep_chunk
        end
      else
        with_chunk_size(size.to_s) { yield }
      end
    end
  end

  def test_default_is_strict
    data = "ok,1\nbad\"x,2\nnext,3\n"
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(data)
    end
    assert_equal("Illegal quoting in line 2.", error.message)
    assert_equal(2, error.line_number)
  end

  def test_strict_default_identical_without_option
    data = "a,b\n1,2\n3,4\n"
    assert_nil(CSV.new(data).bad_record)
  end

  def test_recoverable_quote_skips_bad_record_and_continues
    data = "ok,1\nbad\"x\"y,2\nnext,3\n"
    reported = []
    rows = []
    with_each_scanner do
      reported = []
      rows = []
      CSV.parse(data, bad_record: ->(error, raw,
                                    lineno:, byte_offset:, byte_range:) {
        reported << [error, raw, lineno, byte_offset, byte_range]
      }) { |row| rows << row }
      assert_equal([["ok", "1"], ["next", "3"]], rows)
      assert_equal(1, reported.size)
      error, raw, lineno, byte_offset, byte_range = reported.first
      assert_kind_of(CSV::MalformedCSVError, error)
      assert_equal("Illegal quoting in line 2.", error.message)
      assert_equal("bad\"x\"y,2\n", raw)
      assert_equal(2, lineno)
      assert_equal(5, byte_offset)
      assert_equal((5...15), byte_range)
      assert_equal(data.byteslice(byte_range), raw)
    end
  end

  def test_byte_range_covers_multibyte_content
    data = "\u{540d},1\nx\"\u{3042}\"y,2\n\u{6b21},3\n"
    reported = nil
    with_each_scanner do
      reported = nil
      CSV.parse(data, bad_record: ->(error, raw, **info) {
        reported = [raw, info]
      }) { }
      raw, info = reported
      assert_equal("x\"\u{3042}\"y,2\n", raw)
      assert_equal(6, info[:byte_offset])
      assert_equal((6...16), info[:byte_range])
      assert_equal(data.byteslice(info[:byte_range]), raw)
    end
  end

  def test_unclosed_quote_at_eof_is_not_recovered
    data = "ok,1\nx\"bad\n"
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(data, bad_record: ->(*) { flunk("handler must not run") }) { }
    end
    assert_match(/cannot be recovered/, error.message)
    assert_equal(2, error.line_number)
  end

  def test_ambiguous_quote_hiding_row_separator_is_not_recovered
    data = "good,1\nx\"a\nb\",2\nnext,3\n"
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(data, bad_record: ->(*) { flunk("handler must not run") }) { }
    end
    assert_match(/cannot be identified reliably/, error.message)
    assert_match(/row separator/, error.message)
  end

  def test_bare_line_ending_record_is_recoverable
    data = "a,b\r\n1,2\n3,4\r\n5,6\r\n"
    reported = []
    rows = []
    with_each_scanner do
      reported = []
      rows = []
      CSV.parse(data,
                row_sep: "\r\n",
                bad_record: ->(error, raw, lineno:, byte_offset:, byte_range:) {
                  reported << [raw, lineno, byte_offset, byte_range, error.message]
                }) { |row| rows << row }
      assert_equal([["a", "b"], ["5", "6"]], rows)
      assert_equal(1, reported.size)
      raw, lineno, byte_offset, byte_range, message = reported.first
      warn(format("SIZE=%s raw=%p range=%p",
                   ENV["CSV_PARSER_SCANNER_TEST_CHUNK_SIZE"], raw, byte_range))
      assert_equal("1,2\n3,4\r\n", raw)
      assert_equal(2, lineno)
      assert_equal((5...14), byte_range)
      assert_equal(data.byteslice(byte_range), raw)
      assert_match(/Unquoted fields do not allow new line/, message)
    end
  end

  def test_multiple_bad_records
    data = "g,1\nx\"a\"b,2\ny\"c\"d,3\nz,4\n"
    raws = []
    rows = []
    with_each_scanner do
      raws = []
      rows = []
      CSV.parse(data, bad_record: ->(error, raw, **) { raws << raw }) { |r| rows << r }
      assert_equal([["g", "1"], ["z", "4"]], rows)
      assert_equal(["x\"a\"b,2\n", "y\"c\"d,3\n"], raws)
    end
  end

  def test_bad_record_is_last_without_trailing_separator
    data = "a,b\nx\"q\"z"
    reported = []
    rows = []
    with_each_scanner do
      reported = []
      rows = []
      CSV.parse(data, bad_record: ->(error, raw, lineno:, byte_offset:, byte_range:) {
        reported << [raw, lineno, byte_offset, byte_range]
      }) { |r| rows << r }
      assert_equal([["a", "b"]], rows)
      assert_equal([["x\"q\"z", 2, 4, (4...9)]], reported)
    end
  end

  def test_handler_raising_aborts_parsing
    data = "g,1\nx\"a\"b,2\nn,3\n"
    rows = []
    assert_raise(RuntimeError) do
      CSV.parse(data, bad_record: ->(error, raw, **) { raise "stop" }) do |row|
        rows << row
      end
    end
    assert_equal([["g", "1"]], rows)
  end

  def test_legal_embedded_newline_around_bad_record
    data = "good,\"line1\nline2\"\nx\"a\"b,2\nn,3\n"
    reported = []
    rows = []
    with_each_scanner do
      reported = []
      rows = []
      CSV.parse(data, bad_record: ->(error, raw, lineno:, byte_offset:, byte_range:) {
        reported << [raw, lineno, byte_offset, byte_range]
      }) { |r| rows << r }
      assert_equal([["good", "line1\nline2"], ["n", "3"]], rows)
      assert_equal([["x\"a\"b,2\n", 2, 19, (19...27)]], reported)
    end
  end

  def test_recovery_with_headers
    data = "h1,h2\ngood,1\nx\"a\"b,2\nn,m\n"
    rows = []
    reported = []
    CSV.parse(data,
              headers: true,
              bad_record: ->(error, raw, lineno:, byte_offset:, byte_range:) {
                reported << [lineno, byte_offset, byte_range]
              }) { |row| rows << row.to_h }
    assert_equal([{"h1" => "good", "h2" => "1"},
                  {"h1" => "n", "h2" => "m"}], rows)
    assert_equal([[3, 13, (13...21)]], reported)
  end

  def test_shift_resumes_after_bad_record
    data = "a,1\nx\"q\"z,2\nn,3\n"
    csv = CSV.new(data, bad_record: ->(*) { })
    assert_equal(["a", "1"], csv.shift)
    assert_equal(["n", "3"], csv.shift)
    assert_nil(csv.shift)
    assert(csv.eof?)
  end

  def test_non_callable_bad_record_is_rejected
    assert_raise(ArgumentError) do
      CSV.parse("a,b\n", bad_record: 123) { }
    end
  end

  def test_multibyte_raw_record_encoding_preserved
    data = "a\nx\"\u{3042}\"b\nn\n"
    raw = nil
    CSV.parse(data, bad_record: ->(error, record, **) { raw = record }) { }
    assert_equal(Encoding::UTF_8, raw.encoding)
    assert_equal("x\"\u{3042}\"b\n", raw)
  end
end
