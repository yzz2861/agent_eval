# frozen_string_literal: false

require_relative "../helper"

class TestCSVMultiRowHeaders < Test::Unit::TestCase
  extend DifferentOFS

  def setup
    super
    @finance = <<-CSV
last year,,,this year,,
amount,count,note,amount,count,note
1,2,a,3,4,b
    CSV
  end

  def test_two_row_headers_build_column_paths
    table = CSV.parse(@finance, headers: 2)
    assert_equal([["last year", "amount"],
                  ["count"],
                  ["note"],
                  ["this year", "amount"],
                  ["count"],
                  ["note"]],
                 table.headers)
  end

  def test_data_rows_keep_original_column_order
    table = CSV.parse(@finance, headers: 2)
    row = table.first
    assert_equal(%w[1 2 a 3 4 b], row.fields)
    assert_equal(6, table.headers.size)
    assert_equal(6, row.size)
  end

  def test_three_row_headers_do_not_lose_columns
    data = <<-CSV
A,,B,,,
A1,,,B1,B2,
x,y,z,x,y,z
1,2,3,4,5,6
    CSV
    table = CSV.parse(data, headers: 3)
    assert_equal([["A", "A1", "x"],
                  ["y"],
                  ["B", "z"],
                  ["B1", "x"],
                  ["B2", "y"],
                  ["z"]],
                 table.headers)
    assert_equal(%w[1 2 3 4 5 6], table.first.fields)
    assert_equal(6, table.headers.size)
  end

  def test_fill_headers_inherits_from_the_left
    table = CSV.parse(@finance, headers: 2, fill_headers: true)
    assert_equal([["last year", "amount"],
                  ["last year", "count"],
                  ["last year", "note"],
                  ["this year", "amount"],
                  ["this year", "count"],
                  ["this year", "note"]],
                 table.headers)
  end

  def test_fill_headers_is_opt_in
    without_fill = CSV.parse(@finance, headers: 2)
    with_fill = CSV.parse(@finance, headers: 2, fill_headers: true)
    assert_not_equal(without_fill.headers, with_fill.headers)
    assert_equal(["count"], without_fill.headers[1])
  end

  def test_fill_headers_leaves_fully_blank_column_empty
    data = <<-CSV
A,,B
x,,y
1,2,3
    CSV
    table = CSV.parse(data, headers: 2, fill_headers: true)
    assert_equal([["A", "x"], [], ["B", "y"]], table.headers)
    assert_equal(%w[1 2 3], table.first.fields)
  end

  def test_duplicate_paths_keep_column_identities
    table = CSV.parse(@finance, headers: 2)
    row = table.first
    assert_equal([1, 4], row.indices(["count"]))
    assert_equal(["2", "4"], row.fetch_all(["count"]))
    assert_equal("2", row[["count"]])
    assert_equal(["1"], row.fetch_all(["last year", "amount"]))
  end

  def test_fetch_all_with_fill_reports_matches_explicitly
    table = CSV.parse(@finance, headers: 2, fill_headers: true)
    row = table.first
    assert_equal(["1"], row.fetch_all(["last year", "amount"]))
    assert_equal(["3"], row.fetch_all(["this year", "amount"]))
    assert_equal([], row.fetch_all(["missing", "path"]))
  end

  def test_fetch_all_unknown_header
    row = CSV.parse(@finance, headers: 2).first
    assert_equal([], row.fetch_all("unknown"))
  end

  def test_indices_with_offset
    row = CSV.parse(@finance, headers: 2).first
    assert_equal([4], row.indices(["count"], 2))
    assert_equal([1, 4], row.indices(["count"], 0))
  end

  def test_header_converters_apply_per_layer
    data = <<-CSV
Last Year,This Year
Amount,Amount
1,2
    CSV
    table = CSV.parse(data,
                       headers: 2,
                       fill_headers: true,
                       header_converters: :symbol)
    assert_equal([[:last_year, :amount],
                  [:this_year, :amount]],
                 table.headers)
  end

  def test_header_converters_do_not_affect_data_fields
    data = <<-CSV
Name,Name
Given,Count
a,1
    CSV
    table = CSV.parse(data,
                       headers: 2,
                       fill_headers: true,
                       header_converters: :symbol,
                       converters: :integer)
    row = table.first
    assert_equal(1, row.fields.last)
    assert_instance_of(Symbol, row.headers.first.first)
  end

  def test_return_headers_emits_each_header_row_with_final_paths
    rows = CSV.parse(@finance,
                     headers: 2,
                     return_headers: true,
                     fill_headers: true).each.to_a
    assert_equal(3, rows.size)
    assert_equal(true, rows[0].header_row?)
    assert_equal(true, rows[1].header_row?)
    assert_equal(false, rows[2].header_row?)
    expected_paths = [
      ["last year", "amount"],
      ["last year", "count"],
      ["last year", "note"],
      ["this year", "amount"],
      ["this year", "count"],
      ["this year", "note"],
    ]
    assert_equal(expected_paths, rows[0].headers)
    assert_equal(expected_paths, rows[1].headers)
    assert_equal(["last year", nil, nil, "this year", nil, nil],
                 rows[0].fields)
    assert_equal(%w[amount count note amount count note],
                 rows[1].fields)
    assert_equal(%w[1 2 a 3 4 b], rows[2].fields)
  end

  def test_explicit_array_of_arrays_is_used_as_paths
    table = CSV.parse("1,2,3\n",
                     headers: [["a", "x"], ["a", "y"], ["b"]])
    assert_equal([["a", "x"], ["a", "y"], ["b"]], table.headers)
    assert_equal(%w[1 2 3], table.first.fields)
  end

  def test_explicit_paths_return_headers_emit_physical_rows
    rows = CSV.parse("1,2\n",
                     headers: [["a", "x"], ["b", "y"]],
                     return_headers: true).each.to_a
    assert_equal([["a", "x"], ["b", "y"]], rows[0].headers)
    assert_equal(["a", "b"], rows[0].fields)
    assert_equal(["x", "y"], rows[1].fields)
    assert_equal(false, rows[2].header_row?)
  end

  def test_integer_one_matches_first_row_behavior
    data = "h1,h2\nv1,v2\n"
    integer_table = CSV.parse(data, headers: 1)
    boolean_table = CSV.parse(data, headers: true)
    assert_equal(boolean_table.headers, integer_table.headers)
    assert_equal(%w[h1 h2], integer_table.headers)
    assert_equal(%w[v1 v2], integer_table.first.fields)
  end

  def test_invalid_non_positive_header_count
    assert_raise(ArgumentError) do
      CSV.parse("a\nb\n", headers: 0).to_a
    end
  end

  def test_headers_before_parsing_are_nil
    csv = CSV.new(@finance, headers: 2, fill_headers: true)
    assert_nil(csv.headers)
    csv.shift
    assert_equal([["last year", "amount"],
                  ["last year", "count"],
                  ["last year", "note"],
                  ["this year", "amount"],
                  ["this year", "count"],
                  ["this year", "note"]],
                 csv.headers)
  end
end
