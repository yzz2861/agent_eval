# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "../helper"

class TestCSVParseQuotePair < Test::Unit::TestCase
  extend DifferentOFS
  include CSVHelper

  OPEN_QUOTE = "\u{ab}"
  CLOSE_QUOTE = "\u{bb}"

  def pair_options(overrides = {})
    {
      open_quote_char: OPEN_QUOTE,
      close_quote_char: CLOSE_QUOTE,
      encoding: "UTF-8",
    }.merge(overrides)
  end

  def test_quoted_field
    assert_equal(["a", "b,c", "d"],
                 CSV.parse_line("a,#{OPEN_QUOTE}b,c#{CLOSE_QUOTE},d",
                                **pair_options))
  end

  def test_quoted_field_with_embedded_row_separator
    assert_equal([["a", "line1\nline2"]],
                 CSV.parse("a,#{OPEN_QUOTE}line1\nline2#{CLOSE_QUOTE}\n",
                           **pair_options))
  end

  def test_doubled_close_quote_is_escaped
    assert_equal(["he #{CLOSE_QUOTE} said hi#{CLOSE_QUOTE}"],
                 CSV.parse_line(
                   "#{OPEN_QUOTE}he #{CLOSE_QUOTE * 2} said hi#{CLOSE_QUOTE * 2}#{CLOSE_QUOTE}",
                   **pair_options))
  end

  def test_four_close_quotes
    assert_equal([CLOSE_QUOTE * 2],
                 CSV.parse_line("#{OPEN_QUOTE}#{CLOSE_QUOTE * 4}#{CLOSE_QUOTE}",
                                **pair_options))
  end

  def test_open_quote_in_unquoted_text_is_literal
    assert_equal(["a#{OPEN_QUOTE}b", "c"],
                 CSV.parse_line("a#{OPEN_QUOTE}b,c", **pair_options))
  end

  def test_open_quote_after_long_sample_for_string_io
    require "stringio"
    first = "x" * 200
    data = "#{first}\n#{OPEN_QUOTE}quoted#{CLOSE_QUOTE}\n"
    with_chunk_size("1") do
      env_keep = ENV["CSV_PARSER_SCANNER_TEST"]
      begin
        ENV["CSV_PARSER_SCANNER_TEST"] = "yes"
        rows = CSV.parse(StringIO.new(data), **pair_options)
      ensure
        if env_keep
          ENV["CSV_PARSER_SCANNER_TEST"] = env_keep
        else
          ENV.delete("CSV_PARSER_SCANNER_TEST")
        end
      end
      assert_equal([[first], ["quoted"]], rows)
    end
  end

  def test_field_starting_with_open_quote_is_quoted
    assert_equal(["abc", "d"],
                 CSV.parse_line("#{OPEN_QUOTE}abc#{CLOSE_QUOTE},d",
                                **pair_options))
  end

  def test_open_quote_does_not_need_escaping_inside_quoted_field
    assert_equal(["x#{OPEN_QUOTE}y"],
                 CSV.parse_line("#{OPEN_QUOTE}x#{OPEN_QUOTE}y#{CLOSE_QUOTE}",
                                **pair_options))
  end

  def test_bare_close_quote_in_unquoted_field_is_illegal
    assert_raise(CSV::MalformedCSVError) do
      CSV.parse_line("a#{CLOSE_QUOTE}b", **pair_options)
    end
  end

  def test_value_after_closing_quote_is_illegal
    assert_raise(CSV::MalformedCSVError) do
      CSV.parse_line("#{OPEN_QUOTE}a#{CLOSE_QUOTE}x,c", **pair_options)
    end
  end

  def test_unclosed_quoted_field
    assert_raise(CSV::MalformedCSVError) do
      CSV.parse_line("#{OPEN_QUOTE}abc", **pair_options)
    end
  end

  def test_empty_quoted_field
    assert_equal([""],
                 CSV.parse_line("#{OPEN_QUOTE}#{CLOSE_QUOTE}",
                                **pair_options))
  end

  def test_quoted_fields_info
    quoted_flags = []
    converter = lambda do |field, info|
      quoted_flags << info.quoted?
      field
    end
    CSV.parse_line("a,#{OPEN_QUOTE}b#{CLOSE_QUOTE}",
                   **pair_options.merge(converters: [converter]))
    assert_equal([false, true], quoted_flags)
  end

  def test_round_trip
    rows = [
      ["a,b", "line1\nline2", "x#{CLOSE_QUOTE}y", "u#{OPEN_QUOTE}v", ""],
      [OPEN_QUOTE, CLOSE_QUOTE, "z"],
    ]
    generated = CSV.generate(**pair_options.merge(col_sep: ";")) do |csv|
      rows.each { |row| csv << row }
    end
    assert_equal(rows,
                 CSV.parse(generated, **pair_options.merge(col_sep: ";")))
  end

  def test_across_chunks
    rows = [["a#{CLOSE_QUOTE}b", "x,y", "l1\nl2"],
            ["plain#{OPEN_QUOTE}text", "#{OPEN_QUOTE}#{CLOSE_QUOTE}", "w"]]
    data = CSV.generate(**pair_options.merge(col_sep: "|")) do |csv|
      rows.each { |row| csv << row }
    end
    with_chunk_size("1") do
      parsed = nil
      env_keep = ENV["CSV_PARSER_SCANNER_TEST"]
      begin
        ENV["CSV_PARSER_SCANNER_TEST"] = "yes"
        require "stringio"
        parsed = CSV.parse(StringIO.new(data),
                          **pair_options.merge(col_sep: "|"))
      ensure
        if env_keep
          ENV["CSV_PARSER_SCANNER_TEST"] = env_keep
        else
          ENV.delete("CSV_PARSER_SCANNER_TEST")
        end
      end
      assert_equal(rows, parsed)
    end
  end

  def test_only_open_quote_char_raises
    assert_raise(ArgumentError) do
      CSV.parse("", **pair_options.except(:close_quote_char))
    end
  end

  def test_only_close_quote_char_raises
    assert_raise(ArgumentError) do
      CSV.parse("", **pair_options.except(:open_quote_char))
    end
  end

  def test_quote_character_conflicts_with_col_sep
    assert_raise(ArgumentError) do
      CSV.parse("", **pair_options.merge(col_sep: OPEN_QUOTE))
    end
  end

  def test_quote_character_conflicts_with_row_sep
    assert_raise(ArgumentError) do
      CSV.parse("", **pair_options.merge(row_sep: CLOSE_QUOTE))
    end
  end

  def test_multi_character_quote_raises
    assert_raise(ArgumentError) do
      CSV.parse("", **pair_options.merge(open_quote_char: OPEN_QUOTE * 2))
    end
  end

  def test_symmetric_pair_is_equivalent_to_quote_char
    data = "'a''b','c'"
    assert_equal(CSV.parse_line(data, quote_char: "'"),
                 CSV.parse_line(data,
                                open_quote_char: "'",
                                close_quote_char: "'"))
  end

  def test_pair_takes_precedence_over_quote_char
    assert_equal(["a", '"b"'],
                 CSV.parse_line("#{OPEN_QUOTE}a#{CLOSE_QUOTE},\"b\"",
                                **pair_options.merge(quote_char: "'")))
  end

  def test_readers
    csv = CSV.new("", **pair_options)
    assert_equal(OPEN_QUOTE, csv.open_quote_char)
    assert_equal(CLOSE_QUOTE, csv.close_quote_char)
    assert_equal(OPEN_QUOTE, csv.quote_char)
  end

  def test_headers_string
    row = CSV.parse_line("#{OPEN_QUOTE}A#{CLOSE_QUOTE},B",
                         headers: "h1,h2",
                         **pair_options)
    assert_equal({"h1" => "A", "h2" => "B"}, row.to_h)
  end

  def test_headers_data
    data = "#{OPEN_QUOTE}h1#{CLOSE_QUOTE},h2\na,b"
    table = CSV.parse(data, headers: true, **pair_options)
    assert_equal([{"h1" => "a", "h2" => "b"}], table.map(&:to_h))
  end

  def test_special_regexp_characters
    assert_equal(["a]", "b"],
                 CSV.parse_line("[a]]],b",
                               encoding: "UTF-8",
                               open_quote_char: "[",
                               close_quote_char: "]"))
  end

  def test_liberal_parsing_preserves_close_quotes_outside_field
    assert_equal(["a#{CLOSE_QUOTE * 2}b", "c"],
                 CSV.parse_line("a#{CLOSE_QUOTE * 2}b,#{OPEN_QUOTE}c#{CLOSE_QUOTE}",
                               **pair_options.merge(liberal_parsing: true)))
  end

  def test_liberal_parsing_double_quote_outside_quote
    assert_equal(["#{OPEN_QUOTE}a#{CLOSE_QUOTE}b", "c"],
                 CSV.parse_line(
                   "#{OPEN_QUOTE}#{CLOSE_QUOTE}a#{CLOSE_QUOTE * 2}b,#{OPEN_QUOTE}c#{CLOSE_QUOTE}",
                   **pair_options.merge(
                     liberal_parsing: {double_quote_outside_quote: true})))
  end

  def test_liberal_parsing_backslash_quote
    assert_equal(["a#{CLOSE_QUOTE}b"],
                 CSV.parse_line("#{OPEN_QUOTE}a\\#{CLOSE_QUOTE}b#{CLOSE_QUOTE}",
                               **pair_options.merge(
                                 liberal_parsing: {backslash_quote: true})))
  end

  def test_strip
    assert_equal(["a", "b"],
                 CSV.parse_line("  #{OPEN_QUOTE}a#{CLOSE_QUOTE}  , b ",
                               **pair_options.merge(strip: true)))
  end
end
