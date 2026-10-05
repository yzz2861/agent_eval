# frozen_string_literal: false

require_relative "../helper"

class TestCSVParseOnError < Test::Unit::TestCase
  def parse(data, **options, &block)
    errors = []
    on_error = lambda do |error, raw_record|
      errors << [error, raw_record]
    end
    rows = CSV.parse(data, **options, on_error: on_error)
    [rows, errors]
  end

  def test_strict_mode_is_the_default
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(%Q{"a","b"x\n"c","d"\n})
    end
    assert_equal("Any value after quoted field isn't allowed in line 1.",
                 error.message)
    assert_nil(error.byte_range)
  end

  def test_recovers_and_continues_with_next_record
    rows, errors = parse(%Q{"a","b"x\n"c","d"\n})
    assert_equal([["c", "d"]], rows)
    assert_equal(1, errors.size)
    error, raw_record = errors[0]
    assert_equal("Any value after quoted field isn't allowed in line 1.",
                 error.message)
    assert_equal(1, error.line_number)
    assert_equal(0...9, error.byte_range)
    assert_equal(%Q{"a","b"x\n}, raw_record)
  end

  def test_does_not_jump_to_a_line_ending_inside_quotes
    rows, errors = parse("\"a\nb\"x,c\n\"d\",e\n")
    assert_equal([["d", "e"]], rows)
    error, raw_record = errors[0]
    assert_equal(1, error.line_number)
    assert_equal(0...9, error.byte_range)
    assert_equal("\"a\nb\"x,c\n", raw_record)
  end

  def test_stops_when_a_quote_makes_the_boundary_ambiguous
    error = assert_raise(CSV::MalformedCSVError) do
      parse("\"a\"x,\"b\nc\"\n")
    end
    assert_equal("Any value after quoted field isn't allowed " +
                 "(cannot recover: a quote character before the next " +
                 "line ending makes the record boundary ambiguous) " +
                 "in line 1.",
                 error.message)
  end

  def test_stops_when_the_record_is_not_terminated
    error = assert_raise(CSV::MalformedCSVError) do
      parse(%Q{"abc})
    end
    assert_equal("Unclosed quoted field " +
                 "(cannot recover: no record boundary follows " +
                 "before the end of the input) in line 1.",
                 error.message)
  end

  def test_stops_when_no_line_ending_follows
    error = assert_raise(CSV::MalformedCSVError) do
      parse(%Q{"a"x})
    end
    assert_equal("Any value after quoted field isn't allowed " +
                 "(cannot recover: the end of the input is reached " +
                 "before the next record boundary) in line 1.",
                 error.message)
  end

  def test_illegal_quoting_is_not_recoverable
    error = assert_raise(CSV::MalformedCSVError) do
      parse(%Q{aaa,bb"b,ccc\nddd,eee\n})
    end
    assert_equal("Illegal quoting " +
                 "(cannot recover: a quote character before the next " +
                 "line ending makes the record boundary ambiguous) " +
                 "in line 1.",
                 error.message)
  end

  def test_callback_can_abort
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(%Q{"a"x\n"b"\n}, on_error: ->(e, raw) { :abort })
    end
    assert_equal("Any value after quoted field isn't allowed in line 1.",
                 error.message)
    assert_equal(0...5, error.byte_range)
  end

  def test_callback_exception_propagates
    assert_raise(RuntimeError) do
      CSV.parse(%Q{"a"x\n}, on_error: ->(e, raw) { raise "boom" })
    end
  end

  def test_multiple_malformed_records
    rows, errors = parse(%Q{"a"x\nok,1\n"b"y\nok,2\n})
    assert_equal([["ok", "1"], ["ok", "2"]], rows)
    assert_equal([
                   [1, 0...5, %Q{"a"x\n}],
                   [3, 10...15, %Q{"b"y\n}],
                 ],
                 errors.collect do |error, raw_record|
                   [error.line_number, error.byte_range, raw_record]
                 end)
  end

  def test_field_size_exceeded
    rows, errors = parse("aaaa,bb\ncc,dd\n", max_field_size: 3)
    assert_equal([["cc", "dd"]], rows)
    error, raw_record = errors[0]
    assert_equal("Field size exceeded: 4 > 3 in line 1.", error.message)
    assert_equal(0...8, error.byte_range)
    assert_equal("aaaa,bb\n", raw_record)
  end

  def test_no_quote_field_size_exceeded
    rows, errors = parse("aaaa,bb\ncc,dd\n",
                         quote_char: nil, max_field_size: 3)
    assert_equal([["cc", "dd"]], rows)
    error, raw_record = errors[0]
    assert_equal("Field size exceeded: 4 > 3 in line 1.", error.message)
    assert_equal(0...8, error.byte_range)
    assert_equal("aaaa,bb\n", raw_record)
  end

  def test_unquoted_new_line_with_crlf_row_separator
    rows, errors = parse("a,b\nc,d\r\n", row_sep: "\r\n")
    assert_equal([["c", "d"]], rows)
    error, raw_record = errors[0]
    assert_equal('Unquoted fields do not allow new line <"\\n"> in line 1.',
                 error.message)
    assert_equal(0...4, error.byte_range)
    assert_equal("a,b\n", raw_record)
  end

  def test_byte_range_accounts_for_skipped_lines
    rows, errors = parse("# comment\n\"a\"x\nb,c\n", skip_lines: "#")
    assert_equal([["b", "c"]], rows)
    error, raw_record = errors[0]
    assert_equal(2, error.line_number)
    assert_equal(10...15, error.byte_range)
    assert_equal(%Q{"a"x\n}, raw_record)
  end

  def test_headers
    errors = []
    rows = CSV.parse("h1,h2\n\"a\"x,1\nb,2\n",
                     headers: true,
                     on_error: ->(e, raw) { errors << [e, raw] })
    assert_equal([{"h1" => "b", "h2" => "2"}],
                 rows.collect(&:to_h))
    error, raw_record = errors[0]
    assert_equal(2, error.line_number)
    assert_equal(6...13, error.byte_range)
    assert_equal(%Q{"a"x,1\n}, raw_record)
  end

  def test_io_input_spanning_chunks
    bad_record = %Q{"x"} + "j" * 10000 + %Q{\n}
    data = "a,b\n" * 5000 + bad_record + "c,d\n" * 3
    Tempfile.create("csv") do |file|
      file.write(data)
      file.flush
      errors = []
      count = 0
      CSV.foreach(file.path,
                  on_error: ->(e, raw) { errors << [e, raw] }) do |row|
        count += 1
      end
      assert_equal(5003, count)
      error, raw_record = errors[0]
      assert_equal(5001, error.line_number)
      assert_equal(20000...30004, error.byte_range)
      assert_equal(bad_record, raw_record)
    end
  end

  def test_on_error_must_be_callable
    assert_raise(ArgumentError) do
      CSV.parse("a,b\n", on_error: 42)
    end
  end

  def test_on_error_reader
    callback = ->(error, raw_record) {}
    assert_same(callback, CSV.new("", on_error: callback).on_error)
    assert_nil(CSV.new("").on_error)
  end
end
