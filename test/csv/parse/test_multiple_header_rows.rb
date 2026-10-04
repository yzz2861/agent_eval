# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "../helper"

class TestCSVMultipleHeaderRows < Test::Unit::TestCase
  extend DifferentOFS

  TWO_LEVEL = <<-CSV
Last year,,This year,,
Amount,Count,Amount,Count,Note
100,1,200,2,ok
300,3,400,4,no
  CSV

  THREE_LEVEL = <<-CSV
Region,,North,,South
Year,,2024,,2024
Amount,Count,Amount,Count,Amount
1,2,3,4,5
6,7,8,9,10
  CSV

  def test_single_row_header_keeps_scalar_headers
    table = CSV.parse("a,b\n1,2\n", headers: true)
    assert_equal(["a", "b"], table.headers)
    assert_equal([["a", "1"], ["b", "2"]], table.first.to_a)
  end

  def test_fill_headers_ignored_with_single_row_header
    table = CSV.parse("a,,b\n1,2,3\n", headers: true, fill_headers: true)
    assert_equal(["a", nil, "b"], table.headers)
  end

  def test_two_level_headers_become_paths_without_fill
    table = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2)
    assert_equal([
                   ["Last year", "Amount"],
                   [nil, "Count"],
                   ["This year", "Amount"],
                   [nil, "Count"],
                   [nil, "Note"],
                 ],
                 table.headers)
  end

  def test_fill_headers_inherits_only_with_option
    without_fill = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2)
    assert_nil(without_fill.headers[1].first)

    with_fill = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                                   fill_headers: true)
    assert_equal([
                   ["Last year", "Amount"],
                   ["Last year", "Count"],
                   ["This year", "Amount"],
                   ["This year", "Count"],
                   ["This year", "Note"],
                 ],
                 with_fill.headers)
  end

  def test_quoted_empty_cell_is_not_filled
    source = "A,\"\",B\nX,Y,Z\n1,2,3\n"
    table = CSV.parse(source, headers: true, header_rows: 2,
                             fill_headers: true)
    assert_equal([["A", "X"], ["", "Y"], ["B", "Z"]],
                 table.headers)
  end

  def test_three_level_headers_do_not_lose_columns
    table = CSV.parse(THREE_LEVEL, headers: true, header_rows: 3,
                               fill_headers: true)
    expected_headers = [
      ["Region", "Year", "Amount"],
      ["Region", "Year", "Count"],
      ["North", "2024", "Amount"],
      ["North", "2024", "Count"],
      ["South", "2024", "Amount"],
    ]
    assert_equal(expected_headers, table.headers)
    assert_equal(5, table.headers.size)
    assert_equal(2, table.size)
    assert_equal(["1", "2", "3", "4", "5"], table.first.fields)
    assert_equal(["6", "7", "8", "9", "10"], table[1].fields)
    table.each do |row|
      assert_equal(expected_headers, row.headers)
      assert_equal(5, row.size)
    end
  end

  def test_three_level_headers_without_fill_keep_blanks
    table = CSV.parse(THREE_LEVEL, headers: true, header_rows: 3)
    assert_equal([
                   ["Region", "Year", "Amount"],
                   [nil, nil, "Count"],
                   ["North", "2024", "Amount"],
                   [nil, nil, "Count"],
                   ["South", "2024", "Amount"],
                 ],
                 table.headers)
  end

  def test_data_rows_keep_original_column_order
    table = CSV.parse(THREE_LEVEL, headers: true, header_rows: 3,
                               fill_headers: true)
    row = table.first
    assert_equal([
                   [["Region", "Year", "Amount"], "1"],
                   [["Region", "Year", "Count"], "2"],
                   [["North", "2024", "Amount"], "3"],
                   [["North", "2024", "Count"], "4"],
                   [["South", "2024", "Amount"], "5"],
                 ],
                 row.to_a)
  end

  def test_duplicate_full_paths_keep_column_identity
    source = <<-CSV
Last year,This year,This year
Amount,Amount,Amount
100,200,2
    CSV
    table = CSV.parse(source, headers: true, header_rows: 2,
                               fill_headers: true)
    assert_equal([
                   ["Last year", "Amount"],
                   ["This year", "Amount"],
                   ["This year", "Amount"],
                 ],
                 table.headers)
    row = table.first
    multi = row.field_path(["This year", "Amount"])
    assert_instance_of(CSV::HeaderPathMatch, multi)
    assert_equal([[1, "200"], [2, "2"]], multi.to_a)
    assert_predicate(multi, :matches?)
    assert_equal(1, row.index(["This year", "Amount"], 1))
  end

  def test_row_field_path_single_and_none
    table = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                               fill_headers: true)
    row = table.first
    assert_equal("100", row.field_path(["Last year", "Amount"]))
    assert_equal("100", row.field_path("Last year", "Amount"))
    assert_nil(row.field_path(["No such", "Amount"]))
  end

  def test_field_path_requires_arguments
    row = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                             fill_headers: true).first
    assert_raise(ArgumentError) { row.field_path }
  end

  def test_row_field_path_prefix_returns_multi_match
    table = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                               fill_headers: true)
    row = table.first
    multi = row.field_path(["This year"])
    assert_instance_of(CSV::HeaderPathMatch, multi)
    assert_equal([[2, "200"], [3, "2"], [4, "ok"]], multi.to_a)
  end

  def test_table_field_path
    table = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                               fill_headers: true)
    assert_equal(["100", "300"],
                 table.field_path(["Last year", "Amount"]))
    assert_nil(table.field_path(["Nope"]))
    multi = table.field_path(["This year"])
    assert_instance_of(CSV::HeaderPathMatch, multi)
    assert_equal([
                   [2, ["200", "400"]],
                   [3, ["2", "4"]],
                   [4, ["ok", "no"]],
                 ],
                 multi.to_a)
  end

  def test_header_converters_apply_to_each_header_cell_only
    table = CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                               fill_headers: true,
                               converters: :integer,
                               header_converters: :symbol)
    assert_equal([
                   [:last_year, :amount],
                   [:last_year, :count],
                   [:this_year, :amount],
                   [:this_year, :count],
                   [:this_year, :note],
                 ],
                 table.headers)
    # Data converters still apply to data fields, not headers.
    assert_equal(100, table.first[[:last_year, :amount]])
  end

  def test_return_headers_emits_each_physical_header_row
    emitted = []
    CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                         fill_headers: true, return_headers: true) do |row|
      emitted << row
    end
    assert_equal(4, emitted.size)
    paths = [
      ["Last year", "Amount"],
      ["Last year", "Count"],
      ["This year", "Amount"],
      ["This year", "Count"],
      ["This year", "Note"],
    ]
    assert_predicate(emitted[0], :header_row?)
    assert_equal(paths, emitted[0].headers)
    assert_equal(["Last year", nil, "This year", nil, nil],
                 emitted[0].fields)
    assert_predicate(emitted[1], :header_row?)
    assert_equal(%w[Amount Count Amount Count Note],
                 emitted[1].fields)
    assert_not_predicate(emitted[2], :header_row?)
    assert_equal(["100", "1", "200", "2", "ok"],
                 emitted[2].fields)
  end

  def test_return_headers_with_unconverted_fields
    emitted = []
    CSV.parse(TWO_LEVEL, headers: true, header_rows: 2,
                         fill_headers: true, return_headers: true,
                         unconverted_fields: true) do |row|
      emitted << row
    end
    assert_equal(["Last year", nil, "This year", nil, nil],
                 emitted[0].unconverted_fields)
    assert_equal(%w[Amount Count Amount Count Note],
                 emitted[1].unconverted_fields)
  end

  def test_streaming_collects_header_rows_before_data
    csv = CSV.new(THREE_LEVEL, headers: true, header_rows: 3,
                             fill_headers: true)
    assert_equal(true, csv.headers) # not read yet
    first = csv.shift
    assert_equal([
                   ["Region", "Year", "Amount"],
                   ["Region", "Year", "Count"],
                   ["North", "2024", "Amount"],
                   ["North", "2024", "Count"],
                   ["South", "2024", "Amount"],
                 ],
                 csv.headers)
    assert_equal(["1", "2", "3", "4", "5"], first.fields)
  end

  def test_ragged_header_rows_keep_all_columns
    source = "a,b\nx,y,z\n1,2,3\n"
    table = CSV.parse(source, headers: true, header_rows: 2)
    assert_equal([["a", "x"], ["b", "y"], [nil, "z"]],
                 table.headers)
    assert_equal(["1", "2", "3"], table.first.fields)
  end

  def test_short_input_truncates_header_levels
    table = CSV.parse("a,b\n", headers: true, header_rows: 3,
                               return_headers: true)
    assert_equal(["a", "b"], table.headers)
  end

  def test_explicit_headers_array_ignores_header_rows
    table = CSV.parse("1,2\n3,4\n",
                      headers: %w[a b], header_rows: 2)
    assert_equal(%w[a b], table.headers)
    assert_equal([["a", "1"], ["b", "2"]], table.first.to_a)
  end

  def test_invalid_header_rows
    assert_raise(ArgumentError) do
      CSV.parse("a\n", headers: true, header_rows: 0)
    end
  end

  def test_accessors
    csv = CSV.new("", header_rows: 3, fill_headers: true)
    assert_equal(3, csv.header_rows)
    assert_predicate(csv, :fill_headers?)
  end
end
