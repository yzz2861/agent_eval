# frozen_string_literal: true

require_relative "helper"
require "forwardable"

class TestCSVDialect < Test::Unit::TestCase
  class NonSeekableIO
    extend Forwardable

    def_delegators :@io, :gets, :eof?

    def initialize(data)
      @io = StringIO.new(data)
    end
  end

  def test_detects_comma
    dialect = CSV.detect_dialect("a,b\n1,2\n", read_limit: 32)
    assert_equal(:detected, dialect.status)
    assert_equal([","], dialect.col_seps)
    assert_equal(['"'], dialect.quote_chars)
    assert_equal(["\n"], dialect.row_seps)
  end

  def test_detects_semicolon_and_crlf
    dialect = CSV.detect_dialect("a;b\r\n1;2\r\n", read_limit: 32)
    assert_equal(:detected, dialect.status)
    assert_equal([";"], dialect.col_seps)
    assert_equal(["\r\n"], dialect.row_seps)
  end

  def test_detects_tab
    dialect = CSV.detect_dialect("a\tb\n1\t2\n", read_limit: 32)
    assert_equal(:detected, dialect.status)
    assert_equal(["\t"], dialect.col_seps)
  end

  def test_ignores_separators_and_newlines_inside_quotes
    data = "\"a,b;\t\nx\";y\r\n\"1,2;\t\nz\";w\r\n"
    dialect = CSV.detect_dialect(data, read_limit: data.bytesize)
    assert_equal(:detected, dialect.status)
    assert_equal([";"], dialect.col_seps)
    assert_equal(["\r\n"], dialect.row_seps)
  end

  def test_detects_quote_after_another_separator
    data = "a,\"b;c\"\n1,\"2;3\"\n"
    dialect = CSV.detect_dialect(data, read_limit: data.bytesize)
    assert_equal(:detected, dialect.status)
    assert_equal([","], dialect.col_seps)
  end

  def test_half_record_before_limit_is_insufficient_data
    data = "a;b\n1;2"
    dialect = CSV.detect_dialect(NonSeekableIO.new(data), read_limit: 6)
    assert_equal(:insufficient_data, dialect.status)
    assert_equal([";"], dialect.col_seps)
    assert_include(dialect.notes, "The sample ends in the middle of a record.")
  end

  def test_unclosed_quote_at_eof_is_malformed
    dialect = CSV.detect_dialect("\"unterminated\nvalue", read_limit: 32)
    assert_equal(:malformed, dialect.status)
    assert_include(dialect.notes, "Unclosed quoted field.")
  end

  def test_unclosed_quote_at_limit_is_insufficient_data
    data = "a,b\n\"unterminated,value"
    dialect = CSV.detect_dialect(NonSeekableIO.new(data), read_limit: 10)
    assert_equal(:insufficient_data, dialect.status)
  end

  def test_detects_single_quote_character
    data = "a,'b;c'\n1,'2;3'\n"
    dialect = CSV.detect_dialect(data, read_limit: data.bytesize)
    assert_equal(:detected, dialect.status)
    assert_equal([","], dialect.col_seps)
    assert_equal(["'"], dialect.quote_chars)
  end

  def test_replays_consumed_prefix_for_non_seekable_io
    io = NonSeekableIO.new("a;b\n1;2\n")
    dialect = CSV.detect_dialect(io, read_limit: 4)
    assert_equal("a;b\n", dialect.prefix)
    assert_equal([["a", "b"], ["1", "2"]], dialect.csv.to_a)
  end

  def test_block_replays_consumed_prefix_and_returns_block_value
    io = NonSeekableIO.new("a;b\n1;2\n")
    result = CSV.detect_dialect(io, read_limit: 4) do |csv|
      csv.to_a
    end
    assert_equal([["a", "b"], ["1", "2"]], result)
  end

  def test_detects_and_parses_from_open_file
    file = Tempfile.new(["dialect", ".csv"])
    file.binmode
    file.write("a;b\n1;2\n")
    file.rewind
    File.open(file.path, "rb") do |io|
      rows = CSV.detect_dialect(io, read_limit: 8) do |csv|
        csv.to_a
      end
      assert_equal([["a", "b"], ["1", "2"]], rows)
    end
  ensure
    file&.close(true)
  end

  def test_equally_consistent_separators_are_ambiguous
    data = "a,b;c\n1,2;3\n4,5;6\n"
    dialect = CSV.detect_dialect(data, read_limit: data.bytesize)
    assert_equal(:ambiguous, dialect.status)
    assert_equal([",", ";"], dialect.col_seps)
    assert_include(dialect.notes,
                   "Multiple column separators produced consistent field counts.")
  end

  def test_quote_character_in_normal_data_is_detected_as_unquoted
    data = "hello \"world\nsecond row\n"
    dialect = CSV.detect_dialect(data, read_limit: data.bytesize)
    assert_equal(:ambiguous, dialect.status)
    assert_equal([nil], dialect.quote_chars)
    assert_equal([["hello \"world"], ["second row"]],
                 dialect.csv(quote_char: nil).to_a)
  end

  def test_read_limit_is_validated
    error = assert_raise(ArgumentError) do
      CSV.detect_dialect("a,b\n", read_limit: 0)
    end
    assert_equal("read_limit must be a positive Integer", error.message)
  end
end
