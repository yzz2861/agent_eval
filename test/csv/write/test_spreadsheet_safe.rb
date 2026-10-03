# frozen_string_literal: false

require_relative "../helper"

class TestCSVWriteSpreadsheetSafe < Test::Unit::TestCase
  def generate_line(row, safe, **kwargs)
    CSV.generate_line(row,
                      **kwargs.merge(write_converters: safe.converter))
  end

  def test_dangerous_prefixes
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{'=cmd,'+cmd,'-cmd,'@cmd\n},
                 generate_line(["=cmd", "+cmd", "-cmd", "@cmd"], safe))
  end

  def test_leading_whitespace
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{'  =1+1\n},
                 generate_line(["  =1+1"], safe))
  end

  def test_leading_tab
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{'\t+sum\n},
                 generate_line(["\t+sum"], safe))
  end

  def test_leading_control_characters
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{'\u0000=cmd\n},
                 generate_line(["\u0000=cmd"], safe))
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{'\v@cmd\n},
                 generate_line(["\v@cmd"], safe))
  end

  def test_leading_row_separator_characters
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{"'\r\n-1"\n},
                 generate_line(["\r\n-1"], safe))
  end

  def test_safe_text_untouched
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{hello,a=b,1=2,'=already\n},
                 generate_line(["hello", "a=b", "1=2", "'=already"], safe))
    assert_false(safe.converted?)
  end

  def test_numeric_objects_untouched
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{-5,3.14,-0.5,0\n},
                 generate_line([-5, 3.14, -0.5, 0], safe))
    assert_false(safe.converted?)
  end

  def test_nil_and_non_string_objects_untouched
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{,sym\n},
                 generate_line([nil, :sym], safe))
    assert_false(safe.converted?)
  end

  def test_undeclared_string_number_sanitized
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{'-5\n},
                 generate_line(["-5"], safe))
  end

  def test_string_numbers_in_numeric_fields
    safe = CSV::SpreadsheetSafe.new(numeric_fields: [0, 1, 2])
    assert_equal(%Q{1.5e3, 42 ,-3.\n},
                 generate_line(["1.5e3", " 42 ", "-3."], safe))
    assert_false(safe.converted?)
  end

  def test_non_numeric_string_in_numeric_field_sanitized
    safe = CSV::SpreadsheetSafe.new(numeric_fields: [0])
    assert_equal(%Q{'=cmd\n},
                 generate_line(["=cmd"], safe))
  end

  def test_numeric_fields_by_index_and_name
    headers = ["name", "balance"]
    safe = CSV::SpreadsheetSafe.new(numeric_fields: [:balance],
                                    headers: headers)
    assert_equal(%Q{'-5,-5\n},
                 generate_line(["-5", "-5"], safe))
  end

  def test_numeric_fields_name_requires_headers
    error = assert_raise(ArgumentError) do
      CSV::SpreadsheetSafe.new(numeric_fields: ["balance"])
    end
    assert_include(error.message, ":headers")
  end

  def test_numeric_fields_unknown_name
    error = assert_raise(ArgumentError) do
      CSV::SpreadsheetSafe.new(numeric_fields: ["unknown"],
                               headers: ["balance"])
    end
    assert_include(error.message, "unknown field name")
  end

  def test_numeric_fields_invalid_element
    error = assert_raise(ArgumentError) do
      CSV::SpreadsheetSafe.new(numeric_fields: [1.5])
    end
    assert_include(error.message, "field index or a field name")
  end

  def test_conversions_records
    headers = ["name", "note"]
    safe = CSV::SpreadsheetSafe.new(headers: headers)
    output = CSV.generate(write_converters: safe.converter) do |csv|
      csv << ["=cmd", "ok"]
      csv << ["fine", " +1"]
    end
    assert_equal(%Q{'=cmd,ok\nfine,' +1\n}, output)
    assert_true(safe.converted?)
    assert_equal(2, safe.conversions.size)
    first, second = safe.conversions
    assert_equal(1, first.lineno)
    assert_equal(0, first.index)
    assert_equal("name", first.header)
    assert_equal("=cmd", first.field)
    assert_equal("'=cmd", first.sanitized)
    assert_equal(2, second.lineno)
    assert_equal(1, second.index)
    assert_equal("note", second.header)
    assert_equal(" +1", second.field)
    assert_equal("' +1", second.sanitized)
  end

  def test_quoting_does_not_sanitize
    safe = CSV::SpreadsheetSafe.new
    assert_equal(%Q{"'=cmd"\n},
                 generate_line(["=cmd"], safe, force_quotes: true))
  end

  def test_default_behavior_unchanged
    assert_equal(%Q{=cmd\n},
                 CSV.generate_line(["=cmd"]))
    assert_equal(%Q{=cmd\n},
                 CSV.generate {|csv| csv << ["=cmd"]})
    assert_equal(%Q{"=cmd"\n},
                 CSV.generate_line(["=cmd"], force_quotes: true))
  end
end
