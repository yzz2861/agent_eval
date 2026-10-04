# frozen_string_literal: false

require_relative "helper"

class TestCSVSniff < Test::Unit::TestCase
  class NonSeekableIO
    def initialize(string)
      @io = StringIO.new(string)
    end

    def read(*args)
      @io.read(*args)
    end

    def gets(*args)
      @io.gets(*args)
    end

    def eof?
      @io.eof?
    end
  end

  def test_comma
    dialect = CSV.sniff("a,b,c\n1,2,3\n")
    assert_equal([","], dialect.delimiters)
    assert_equal(",", dialect.delimiter)
    assert_equal('"', dialect.quote_char)
    assert_equal("\n", dialect.row_separator)
    assert_equal(:ok, dialect.status)
    assert do
      dialect.ok? and
        !dialect.ambiguous? and
        !dialect.need_more_data? and
        !dialect.malformed?
    end
  end

  def test_semicolon
    dialect = CSV.sniff("a;b;c\n1;2;3\n")
    assert_equal([";"], dialect.delimiters)
  end

  def test_tab
    dialect = CSV.sniff("a\tb\tc\n1\t2\t3\n")
    assert_equal(["\t"], dialect.delimiters)
  end

  def test_pipe_delimiter
    dialect = CSV.sniff("a|b\n1|2\n")
    assert_equal(["|"], dialect.delimiters)
  end

  def test_quoted_separators_are_not_boundaries
    dialect = CSV.sniff(%Q{a,"b,b",c\n1,"2,2",3\n})
    assert_equal([","], dialect.delimiters)
    assert_equal(:ok, dialect.status)
  end

  def test_quoted_newline_is_not_a_record_boundary
    dialect = CSV.sniff(%Q{a,"x\ny",c\n1,2,3\n})
    assert_equal([","], dialect.delimiters)
    assert_equal("\n", dialect.row_separator)
    assert_equal(:ok, dialect.status)
  end

  def test_crlf
    dialect = CSV.sniff("a,b\r\n1,2\r\n")
    assert_equal("\r\n", dialect.row_separator)
    assert_equal(:ok, dialect.status)
  end

  def test_cr
    dialect = CSV.sniff("a,b\r1,2\r")
    assert_equal("\r", dialect.row_separator)
  end

  def test_mixed_line_endings_use_majority
    dialect = CSV.sniff("a,b\r\n1,2\n3,4\r\n")
    assert_equal("\r\n", dialect.row_separator)
    assert_equal(:ok, dialect.status)
    assert_match(/mixed line endings/, dialect.notes.join(" "))
  end

  def test_tied_line_endings_fall_back_to_auto
    dialect = CSV.sniff("a,b\nc,d\r\n")
    assert_equal(:auto, dialect.row_separator)
    assert_match(/mixed line endings/, dialect.notes.join(" "))
  end

  def test_ambiguous_delimiters
    dialect = CSV.sniff("a,b;c\n1,2;3\n")
    assert_equal(:ambiguous, dialect.status)
    assert do
      dialect.ambiguous? and
        dialect.delimiters.include?(",") and
        dialect.delimiters.include?(";")
    end
    notes = dialect.notes.join(" ")
    assert_match(/ambiguous/, notes)
    assert_match(/","/, notes)
    assert_match(/";"/, notes)
  end

  def test_truncated_inside_quoted_field_needs_more_data
    data = "a,\"" + "x" * 500 + "\",c\n1,2,3\n"
    dialect = CSV.sniff(data, limit: 100)
    assert_equal(:need_more_data, dialect.status)
    assert do
      dialect.need_more_data? and !dialect.malformed?
    end
    assert_equal(100, dialect.sample.bytesize)
    assert do
      dialect.truncated?
    end
    assert_match(/inside a quoted field/, dialect.notes.join(" "))
  end

  def test_truncated_mid_record_needs_more_data
    data = "aaaa,bbbb\n" + "c" * 500
    dialect = CSV.sniff(data, limit: 15)
    assert_equal(:need_more_data, dialect.status)
    assert_match(/middle of a record/, dialect.notes.join(" "))
  end

  def test_unterminated_quote_at_eof_is_malformed
    dialect = CSV.sniff(%Q{a,"b\n1,2\n})
    assert_equal(:malformed, dialect.status)
    assert do
      dialect.malformed? and !dialect.need_more_data?
    end
    assert_match(/unterminated quoted field/, dialect.notes.join(" "))
  end

  def test_stray_character_after_quote_is_malformed
    dialect = CSV.sniff(%Q{a,"b"x,c\n1,2,3\n})
    assert_equal(:malformed, dialect.status)
    assert_match(/after a closing quote/, dialect.notes.join(" "))
  end

  def test_single_column
    dialect = CSV.sniff("a\nb\nc\n")
    assert_equal([], dialect.delimiters)
    assert_nil(dialect.delimiter)
    assert_equal(:ok, dialect.status)
    assert_match(/single column/, dialect.notes.join(" "))
  end

  def test_empty_input
    dialect = CSV.sniff("")
    assert_equal([], dialect.delimiters)
    assert_equal(:ok, dialect.status)
    assert_match(/no records/, dialect.notes.join(" "))
  end

  def test_single_quote_character
    dialect = CSV.sniff("'a,b',c\n'1,2',3\n")
    assert_equal("'", dialect.quote_char)
    assert_equal([","], dialect.delimiters)
    assert_equal(:ok, dialect.status)
  end

  def test_apostrophes_are_not_quotes
    dialect = CSV.sniff("It's,1\nJon's,2\n")
    assert_equal('"', dialect.quote_char)
    assert_equal([","], dialect.delimiters)
    assert_equal(:ok, dialect.status)
  end

  def test_final_record_without_trailing_newline
    dialect = CSV.sniff("a,b\n1,2")
    assert_equal([","], dialect.delimiters)
    assert_equal(:ok, dialect.status)
  end

  def test_to_options
    dialect = CSV.sniff("a;b\r\n1;2\r\n")
    assert_equal({col_sep: ";", quote_char: '"', row_sep: "\r\n"},
                 dialect.to_options)
    assert_equal([["a", "b"], ["1", "2"]],
                 CSV.parse("a;b\r\n1;2\r\n", **dialect.to_options))
  end

  def test_limit_is_respected
    data = "a,b\n" * 100
    dialect = CSV.sniff(data, limit: 64)
    assert_operator(dialect.sample.bytesize, :<=, 64)
    assert do
      dialect.truncated?
    end
  end

  def test_limit_must_be_positive
    assert_raise(ArgumentError) do
      CSV.sniff("a,b\n", limit: 0)
    end
  end

  def test_sample_is_the_consumed_prefix
    data = "a,b,c\n1,2,3\n"
    dialect = CSV.sniff(data, limit: 6)
    assert_equal(data.byteslice(0, 6), dialect.sample)
  end

  def test_seekable_io_position_is_restored
    io = StringIO.new("a;b\n1;2\n")
    dialect = CSV.sniff(io)
    assert_equal(0, io.pos)
    assert_equal([";"], dialect.delimiters)
    assert_equal([["a", "b"], ["1", "2"]],
                 CSV.new(io, **dialect.to_options).read)
  end

  def test_non_seekable_io_does_not_lose_the_first_line
    source = "a,b,c\n1,2,3\n4,5,6\n"
    dialect = CSV.sniff(NonSeekableIO.new(source))
    assert_equal([","], dialect.delimiters)
    assert_equal([["a", "b", "c"], ["1", "2", "3"], ["4", "5", "6"]],
                 CSV.new(dialect.io, **dialect.to_options).read)
  end

  def test_non_seekable_io_sample_holds_the_consumed_prefix
    source = "a,b,c\n1,2,3\n4,5,6\n"
    dialect = CSV.sniff(NonSeekableIO.new(source), limit: 8)
    assert_equal(source.byteslice(0, 8), dialect.sample)
    assert_equal([["a", "b", "c"], ["1", "2", "3"], ["4", "5", "6"]],
                 CSV.new(dialect.io, **dialect.to_options).read)
  end

  def test_pipe
    reader, writer = IO.pipe
    writer.write("x|y\n1|2\n")
    writer.close
    begin
      dialect = CSV.sniff(reader)
      assert_equal(["|"], dialect.delimiters)
      assert_equal([["x", "y"], ["1", "2"]],
                   CSV.new(dialect.io, **dialect.to_options).read)
    ensure
      reader.close
    end
  end

  def test_string_input_io_replays_the_whole_string
    dialect = CSV.sniff("a;b\n1;2\n")
    assert_equal([["a", "b"], ["1", "2"]],
                 CSV.new(dialect.io, **dialect.to_options).read)
  end
end
