# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "../helper"

class TestCSVWriteQuotePair < Test::Unit::TestCase
  extend DifferentOFS

  OPEN_QUOTE = "\u{ab}"
  CLOSE_QUOTE = "\u{bb}"

  def pair_options(overrides = {})
    {
      open_quote_char: OPEN_QUOTE,
      close_quote_char: CLOSE_QUOTE,
      encoding: "UTF-8",
      row_sep: "\n",
    }.merge(overrides)
  end

  def generate_line(row, overrides = {})
    CSV.generate_line(row, **pair_options(overrides))
  end

  def test_quotes_when_column_separator
    assert_equal("#{OPEN_QUOTE}a,b#{CLOSE_QUOTE}\n",
                 generate_line(["a,b"]))
  end

  def test_quotes_when_newline
    assert_equal("#{OPEN_QUOTE}a\nb#{CLOSE_QUOTE}\n",
                 generate_line(["a\nb"]))
  end

  def test_escapes_only_close_quote
    assert_equal("#{OPEN_QUOTE}a#{CLOSE_QUOTE * 2}b#{CLOSE_QUOTE}\n",
                 generate_line(["a#{CLOSE_QUOTE}b"]))
  end

  def test_open_quote_not_escaped_but_field_is_quoted
    assert_equal("#{OPEN_QUOTE}a#{OPEN_QUOTE}b#{CLOSE_QUOTE}\n",
                 generate_line(["a#{OPEN_QUOTE}b"]))
  end

  def test_open_quote_at_field_start_forces_quoting
    assert_equal("#{OPEN_QUOTE}#{OPEN_QUOTE}ab#{CLOSE_QUOTE}\n",
                 generate_line(["#{OPEN_QUOTE}ab"]))
  end

  def test_unquoted_simple_field
    assert_equal("abc\n", generate_line(["abc"]))
  end

  def test_force_quotes
    assert_equal("#{OPEN_QUOTE}a#{CLOSE_QUOTE},#{OPEN_QUOTE}b#{CLOSE_QUOTE}\n",
                 generate_line(["a", "b"], force_quotes: true))
  end

  def test_empty_field
    assert_equal("#{OPEN_QUOTE}#{CLOSE_QUOTE}\n", generate_line([""]))
  end

  def test_round_trip_with_newline_close_and_separators
    rows = [
      ["a,b", "l1\nl2", "x#{CLOSE_QUOTE}y", "u#{OPEN_QUOTE}v", ""],
      [OPEN_QUOTE, CLOSE_QUOTE],
    ]
    generated = CSV.generate(**pair_options.merge(col_sep: ";")) do |csv|
      rows.each { |row| csv << row }
    end
    assert_equal(rows,
                 CSV.parse(generated,
                           **pair_options.except(:row_sep).merge(col_sep: ";")))
  end

  def test_conflict_with_col_sep_raises
    assert_raise(ArgumentError) do
      CSV.generate(encoding: "UTF-8",
                   col_sep: "|",
                   open_quote_char: "|",
                   close_quote_char: "'") { |csv| csv << ["a"] }
    end
  end

  def test_only_open_quote_char_raises
    assert_raise(ArgumentError) do
      CSV.generate(encoding: "UTF-8", open_quote_char: OPEN_QUOTE) do |csv|
        csv << ["a"]
      end
    end
  end

  def test_symmetric_pair_matches_quote_char
    row = ["a'b", "c,d"]
    by_pair = CSV.generate_line(row,
                                open_quote_char: "'",
                                close_quote_char: "'",
                                row_sep: "\n")
    by_quote_char = CSV.generate_line(row, quote_char: "'", row_sep: "\n")
    assert_equal(by_quote_char, by_pair)
  end

  def test_multibyte_round_trip
    field = "你#{CLOSE_QUOTE}好\n世界，值"
    generated = generate_line([field])
    assert_equal([[field]],
                 CSV.parse(generated,
                           open_quote_char: OPEN_QUOTE,
                           close_quote_char: CLOSE_QUOTE,
                           encoding: "UTF-8"))
  end
end
