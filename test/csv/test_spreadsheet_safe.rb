# frozen_string_literal: true

require_relative "helper"

class TestCSVSpreadsheetSafe < Test::Unit::TestCase
  include CSVHelper

  def test_dangerous_formula_prefixes
    values = ["=1+1", "+1+1", "-1+1", "@SUM(1,2)"]
    assert do
      values.all? {|value| CSV::SpreadsheetSafe.dangerous?(value)}
    end
  end

  def test_dangerous_leading_whitespace
    values = [" =1+1", "\t=1+1", "\r\n=1+1", " \t -2"]
    assert do
      values.all? {|value| CSV::SpreadsheetSafe.dangerous?(value)}
    end
  end

  def test_dangerous_leading_control_characters
    values = ["\x01=1+1", "\x00@cmd", "\v+1"]
    assert do
      values.all? {|value| CSV::SpreadsheetSafe.dangerous?(value)}
    end
  end

  def test_safe_values
    values = ["foo", "", "1", "1-2", "a=b", " hello ", nil, 42, -3.14]
    assert do
      values.none? {|value| CSV::SpreadsheetSafe.dangerous?(value)}
    end
  end

  def test_sanitize_prefixes_dangerous_text
    assert_equal("'=1+1", CSV::SpreadsheetSafe.sanitize("=1+1"))
    assert_equal("foo", CSV::SpreadsheetSafe.sanitize("foo"))
    assert_equal(-5, CSV::SpreadsheetSafe.sanitize(-5))
  end

  def test_sanitize_custom_prefix
    assert_equal("!=1+1",
                 CSV::SpreadsheetSafe.sanitize("=1+1", prefix: "!"))
  end

  def test_export_escapes_untrusted_text
    rows = [
      ["alice", "ordinary text"],
      ["mallory", "=cmd|'/c calc'!A1"],
    ]
    csv_string, records = CSV::SpreadsheetSafe.generate(
      rows,
      headers: ["name", "note"],
    )
    assert_equal(<<~CSV, csv_string)
      name,note
      alice,ordinary text
      mallory,'=cmd|'/c calc'!A1
    CSV
    assert_equal(1, records.size)
  end

  def test_export_records_are_field_level
    rows = [
      ["ok", "=1+1", " @mention"],
    ]
    _csv_string, records = CSV::SpreadsheetSafe.generate(
      rows,
      headers: ["name", "note", "comment"],
    )
    assert_equal(2, records.size)
    first, second = records
    assert_equal(2, first.row)
    assert_equal("note", first.field)
    assert_equal(1, first.field_index)
    assert_equal("=1+1", first.original)
    assert_equal("'=1+1", first.sanitized)
    assert_equal("comment", second.field)
    assert_equal(2, second.field_index)
  end

  def test_export_without_headers_records_index
    _csv_string, records = CSV::SpreadsheetSafe.generate([["=1+1"]])
    assert_equal(1, records.size)
    assert_equal(1, records[0].row)
    assert_equal(0, records[0].field)
    assert_equal(0, records[0].field_index)
  end

  def test_numeric_fields_keep_legitimate_negative_numbers
    rows = [
      ["alice", 100],
      ["bob", -20],
      ["carol", -3.5],
    ]
    csv_string, records = CSV::SpreadsheetSafe.generate(
      rows,
      headers: ["name", "balance"],
      numeric_fields: ["balance"],
    )
    assert_equal(<<~CSV, csv_string)
      name,balance
      alice,100
      bob,-20
      carol,-3.5
    CSV
    assert_empty(records)
  end

  def test_numeric_fields_by_index
    csv_string, = CSV::SpreadsheetSafe.generate(
      [["alice", -20]],
      numeric_fields: [1],
    )
    assert_equal("alice,-20\n", csv_string)
  end

  def test_string_in_numeric_field_is_still_untrusted
    csv_string, records = CSV::SpreadsheetSafe.generate(
      [["=1+1"]],
      numeric_fields: [0],
    )
    assert_equal("'=1+1\n", csv_string)
    assert_equal(1, records.size)
  end

  def test_quoting_does_not_prevent_escaping
    csv_string, records = CSV::SpreadsheetSafe.generate(
      [["=1+1"]],
      force_quotes: true,
    )
    assert_equal(%Q["'=1+1"\n], csv_string)
    assert_equal(1, records.size)
  end

  def test_leading_whitespace_and_control_characters_escaped
    csv_string, records = CSV::SpreadsheetSafe.generate(
      [["  =1+1", "\t@cmd"]],
    )
    assert_equal("'  =1+1,'\t@cmd\n", csv_string)
    assert_equal(2, records.size)
  end

  def test_explicit_text_fields_and_undeclared_pass
    csv_string, records = CSV::SpreadsheetSafe.generate(
      [["=1+1", "=2+2"]],
      numeric_fields: [],
      text_fields: [0],
      undeclared: :pass,
    )
    assert_equal("'=1+1,=2+2\n", csv_string)
    assert_equal(1, records.size)
  end

  def test_undeclared_raise
    exporter = CSV::SpreadsheetSafe::Exporter.new(text_fields: [0],
                                                  undeclared: :raise)
    assert_raise(ArgumentError) do
      exporter.generate([["safe", "anything"]])
    end
  end

  def test_invalid_undeclared_option
    assert_raise(ArgumentError) do
      CSV::SpreadsheetSafe::Exporter.new(undeclared: :unknown)
    end
  end

  def test_unknown_field_name_raises
    exporter = CSV::SpreadsheetSafe::Exporter.new(numeric_fields: ["missing"])
    assert_raise(ArgumentError) do
      exporter.generate([["a", 1]], headers: ["name", "balance"])
    end
  end

  def test_field_name_requires_headers
    exporter = CSV::SpreadsheetSafe::Exporter.new(numeric_fields: ["balance"])
    assert_raise(ArgumentError) do
      exporter.generate([["a", 1]])
    end
  end

  def test_hash_rows
    csv_string, = CSV::SpreadsheetSafe.generate(
      [{"name" => "mallory", "note" => "=1+1"}],
      headers: ["name", "note"],
    )
    assert_equal("name,note\nmallory,'=1+1\n", csv_string)
  end

  def test_csv_row_rows
    row = CSV::Row.new(["name", "note"], ["mallory", "=1+1"])
    csv_string, = CSV::SpreadsheetSafe.generate([row],
                                                headers: ["name", "note"])
    assert_equal("name,note\nmallory,'=1+1\n", csv_string)
  end

  def test_dangerous_headers_are_escaped
    csv_string, records = CSV::SpreadsheetSafe.generate(
      [["alice"]],
      headers: ["=name"],
    )
    assert_equal("'=name\nalice\n", csv_string)
    assert_equal(1, records.size)
    assert_equal(1, records[0].row)
  end

  def test_exporter_records_reset_per_generate
    exporter = CSV::SpreadsheetSafe::Exporter.new
    exporter.generate([["=1+1"]])
    assert_equal(1, exporter.records.size)
    exporter.generate([["safe"]])
    assert_empty(exporter.records)
  end

  def test_default_csv_generate_is_unchanged
    assert_equal("=1+1\n", CSV.generate_line(["=1+1"]))
    assert_equal("=1+1\n",
                 CSV.generate {|csv| csv << ["=1+1"]})
  end
end
