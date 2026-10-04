# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "helper"
require "stringio"

class TestCSVAsymmetricQuotes < Test::Unit::TestCase
  OPEN_QUOTE = "\u{ab}"
  CLOSE_QUOTE = "\u{bb}"
  OPTIONS = {open_quote_char: OPEN_QUOTE, close_quote_char: CLOSE_QUOTE}

  def test_generate_line_with_open_and_close_quotes
    assert_equal("#{OPEN_QUOTE}a,»#{CLOSE_QUOTE}#{CLOSE_QUOTE}\n",
                 CSV.generate_line(["a,»"], **OPTIONS))
  end

  def test_round_trip_newline_close_and_column_separator
    rows = [
      ["plain", "a,»,x", "line\nbreak", "starts#{OPEN_QUOTE}"],
      ["ends#{CLOSE_QUOTE}", "#{CLOSE_QUOTE}middle", "", nil],
    ]
    csv = rows.map { |row| CSV.generate_line(row, **OPTIONS) }.join
    assert_equal(rows, CSV.parse(csv, **OPTIONS))
  end

  def test_opening_quote_inside_unquoted_field_is_literal
    assert_equal(["plain #{OPEN_QUOTE} text"],
                 CSV.parse_line("plain #{OPEN_QUOTE} text", **OPTIONS))
  end

  def test_closing_quote_inside_unquoted_field_is_literal
    assert_equal(["plain #{CLOSE_QUOTE} text"],
                 CSV.parse_line("plain #{CLOSE_QUOTE} text", **OPTIONS))
  end

  def test_opening_quote_only_starts_quoted_field_at_field_start
    assert_equal(["a#{OPEN_QUOTE}b"],
                 CSV.parse_line("a#{OPEN_QUOTE}b", **OPTIONS))
  end

  def test_escaped_closing_quote
    assert_equal(["a#{CLOSE_QUOTE}b"],
                 CSV.parse_line("#{OPEN_QUOTE}a#{CLOSE_QUOTE}#{CLOSE_QUOTE}b#{CLOSE_QUOTE}",
                                **OPTIONS))
  end

  def test_unclosed_quoted_field
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse_line("#{OPEN_QUOTE}a", **OPTIONS)
    end
    assert_equal("Unclosed quoted field in line 1.", error.message)
  end

  def test_open_and_close_quote_char_must_be_specified_together
    error = assert_raise(ArgumentError) do
      CSV.new("", open_quote_char: OPEN_QUOTE)
    end
    assert_equal(":open_quote_char and :close_quote_char must be specified together",
                 error.message)
  end

  def test_open_and_close_quote_char_must_be_single_characters
    error = assert_raise(ArgumentError) do
      CSV.parse_line("",
                     open_quote_char: OPEN_QUOTE,
                     close_quote_char: "xy")
    end
    assert_equal(":open_quote_char and :close_quote_char have to be single character Strings",
                 error.message)
  end

  def test_quote_characters_cannot_be_included_in_column_separator
    error = assert_raise(ArgumentError) do
      CSV.parse_line("", col_sep: "x#{CLOSE_QUOTE}y", **OPTIONS)
    end
    assert_equal("Quote character cannot be included in col_sep or row_sep",
                 error.message)
  end

  def test_quote_characters_cannot_be_included_in_row_separator
    error = assert_raise(ArgumentError) do
      CSV.parse_line("", row_sep: "x#{OPEN_QUOTE}y", **OPTIONS)
    end
    assert_equal("Quote character cannot be included in col_sep or row_sep",
                 error.message)
  end

  def test_quote_characters
    csv = CSV.new("", **OPTIONS)
    assert_equal(OPEN_QUOTE, csv.quote_char)
    assert_equal(OPEN_QUOTE, csv.open_quote_char)
    assert_equal(CLOSE_QUOTE, csv.close_quote_char)
    assert_include(csv.inspect, "open_quote_char:#{OPEN_QUOTE.inspect}")
    assert_include(csv.inspect, "close_quote_char:#{CLOSE_QUOTE.inspect}")
  end

  def test_quoted_field_information
    quoted = []
    converter = lambda do |field, info|
      quoted << info.quoted?
      field
    end

    CSV.parse_line("a,#{OPEN_QUOTE}b#{CLOSE_QUOTE}",
                   **OPTIONS,
                   converters: [converter])

    assert_equal([false, true], quoted)
  end

  def test_multibyte_quotes_across_input_chunks
    rows = [["a,»", "b»»", "c\nd", "e»f"]]
    data = CSV.generate_line(rows.first, **OPTIONS)
    [1, 2, 3, 4, 5, 8192].each do |chunk_size|
      assert_equal(rows, parse_chunks(data, chunk_size))
    end
  end

  def test_multibyte_row_separator_across_input_chunks
    data = "#{OPEN_QUOTE}a#{CLOSE_QUOTE}¶"
    options = OPTIONS.merge(row_sep: "¶")

    [1, 2, 3, 4, 5].each do |chunk_size|
      assert_equal([["a"]], parse_chunks(data, chunk_size, options))
    end
  end

  private

  def parse_chunks(data, chunk_size, options = OPTIONS)
    input = CSV::Parser::UnoptimizedStringIO.new(data)
    parser = CSV::Parser.allocate
    parser.instance_variable_set(:@input, input)
    parser.instance_variable_set(:@options, parser_options(options))
    parser.instance_variable_set(:@samples, [])
    parser.send(:prepare)
    parser.instance_variable_set(:@scanner,
                                 CSV::Parser::InputsScanner.new(
                                   [input], Encoding::UTF_8, "\n",
                                   chunk_size: chunk_size))
    parser.to_enum(:parse).to_a
  end

  def parser_options(options = OPTIONS)
    {
      column_separator: ",",
      row_separator: options.fetch(:row_sep, "\n"),
      quote_character: options.fetch(:open_quote_char, OPEN_QUOTE),
      open_quote_character: options.fetch(:open_quote_char, OPEN_QUOTE),
      close_quote_character: options.fetch(:close_quote_char, CLOSE_QUOTE),
      max_field_size: nil,
      unconverted_fields: nil,
      headers: false,
      return_headers: false,
      skip_blanks: false,
      skip_lines: nil,
      liberal_parsing: false,
      encoding: Encoding::UTF_8,
      nil_value: nil,
      empty_value: "",
      strip: false,
      header_fields_converter:
        CSV::FieldsConverter.new(builtin_converters_name: :HeaderConverters,
                                 accept_nil: true),
      fields_converter:
        CSV::FieldsConverter.new(builtin_converters_name: :Converters),
    }
  end
end
