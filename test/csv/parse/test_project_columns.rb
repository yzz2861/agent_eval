# frozen_string_literal: true

require_relative "../helper"

class TestCSVParseProjectColumns < Test::Unit::TestCase
  include CSVHelper

  # An IO-like object that is not a StringIO, so that the parser reads
  # the input in chunks through CSV::Parser::InputsScanner.
  class ChunkedIO
    def initialize(string)
      @io = StringIO.new(string)
    end

    def gets(*args)
      @io.gets(*args)
    end

    def eof?
      @io.eof?
    end
  end

  def count_allocations
    GC.start
    before = GC.stat(:total_allocated_objects)
    yield
    GC.stat(:total_allocated_objects) - before
  end

  def test_select_by_index
    assert_equal([["a", "c"], ["1", "3"]],
                 CSV.parse("a,b,c\n1,2,3\n", project_columns: [0, 2]))
  end

  def test_select_all_columns_keeps_original_behavior
    data = "a,\"b,b\",c\n1,2,\n"
    assert_equal(CSV.parse(data),
                 CSV.parse(data, project_columns: [0, 1, 2]))
  end

  def test_selection_preserves_original_column_order
    assert_equal([["a", "c"]],
                 CSV.parse("a,b,c\n", project_columns: [2, 0]))
  end

  def test_duplicated_selectors_are_kept_once
    assert_equal([["a", "c"]],
                 CSV.parse("a,b,c\n", project_columns: [2, 0, 2]))
  end

  def test_out_of_range_index_is_dropped
    assert_equal([["a"]],
                 CSV.parse("a,b,c\n", project_columns: [0, 5]))
  end

  def test_nil_and_empty_fields
    assert_equal([["a", nil], ["1", nil]],
                 CSV.parse("a,,c\n1,,\n", project_columns: [0, 1]))
  end

  def test_select_by_header_name
    table = CSV.parse("id,name,comment\n1,foo,hello\n2,bar,world\n",
                      headers: true,
                      project_columns: ["id", :name])
    assert_equal(["id", "name"], table.headers)
    assert_equal([["id", "name"], ["1", "foo"], ["2", "bar"]],
                 table.to_a)
    assert_equal("foo", table[0]["name"])
    assert_nil(table[0]["comment"])
  end

  def test_select_by_index_with_headers
    table = CSV.parse("id,name,comment\n1,foo,hello\n",
                      headers: true,
                      project_columns: [2, 0])
    assert_equal(["id", "comment"], table.headers)
    assert_equal([["id", "comment"], ["1", "hello"]], table.to_a)
  end

  def test_select_mixed_index_and_header_name
    table = CSV.parse("id,name,comment\n1,foo,hello\n",
                      headers: true,
                      project_columns: ["comment", 0])
    assert_equal(["id", "comment"], table.headers)
    assert_equal([["id", "comment"], ["1", "hello"]], table.to_a)
  end

  def test_select_with_headers_given_as_array
    table = CSV.parse("1,foo,hello\n",
                      headers: ["id", "name", "comment"],
                      project_columns: ["name", 2])
    assert_equal(["name", "comment"], table.headers)
    assert_equal([["name", "comment"], ["foo", "hello"]], table.to_a)
  end

  def test_select_with_header_converters
    table = CSV.parse("ID,Name,Comment\n1,foo,hello\n",
                      headers: true,
                      header_converters: :symbol,
                      project_columns: [:name])
    assert_equal([:name], table.headers)
    assert_equal("foo", table[0][:name])
  end

  def test_return_headers
    rows = CSV.parse("h1,h2,h3\nv1,v2,v3\n",
                     headers: true,
                     return_headers: true,
                     project_columns: [2, 0])
    assert_equal([["h1", "h1"], ["h3", "h3"]], rows[0].to_a)
    assert_equal([["h1", "v1"], ["h3", "v3"]], rows[1].to_a)
  end

  def test_unknown_header_name
    error = assert_raise(ArgumentError) do
      CSV.parse("a,b\n", headers: true, project_columns: ["unknown"])
    end
    assert_equal(":project_columns has unknown header: \"unknown\"",
                 error.message)
  end

  def test_header_name_requires_headers
    error = assert_raise(ArgumentError) do
      CSV.parse("a,b\n", project_columns: ["a"])
    end
    assert_equal(":project_columns header names require the :headers option",
                 error.message)
  end

  def test_invalid_option_value
    assert_raise(ArgumentError) do
      CSV.parse("a,b\n", project_columns: 0)
    end
    assert_raise(ArgumentError) do
      CSV.parse("a,b\n", project_columns: [-1])
    end
    assert_raise(ArgumentError) do
      CSV.parse("a,b\n", project_columns: [0.5])
    end
  end

  def test_converters_are_not_called_for_skipped_columns
    converted = []
    converter = lambda do |field, info|
      converted << [info.index, info.header]
      field
    end
    rows = CSV.parse("a,b,c\n1,2,3\n",
                     headers: true,
                     converters: converter,
                     project_columns: [2])
    assert_equal([[0, "c"]], converted)
    assert_equal(["3"], rows[0].fields)
  end

  def test_quoted_and_multi_row_fields
    data = "1,\"x\ny\",3\n4,\"5\",6\n"
    assert_equal([["1", "3"], ["4", "6"]],
                 CSV.parse(data, project_columns: [0, 2]))
  end

  def test_multi_character_column_separator
    assert_equal([["a", "c"]],
                 CSV.parse("a..b..c\n", col_sep: "..",
                             project_columns: [0, 2]))
  end

  def test_quote_char_nil
    assert_equal([["a", "c"]],
                 CSV.parse("a,b,c\n", quote_char: nil,
                             project_columns: [0, 2]))
  end

  def test_liberal_parsing
    data = "1,\"2\" ,3\n"
    assert_equal([["1", "3"]],
                 CSV.parse(data, liberal_parsing: true,
                             project_columns: [0, 2]))
  end

  def test_strip
    assert_equal([["a", "c"]],
                 CSV.parse(" a , b , c \n", strip: true,
                             project_columns: [0, 2]))
  end

  def test_skip_blanks
    assert_equal([["a"], ["b"]],
                 CSV.parse("a,1\n\nb,2\n", skip_blanks: true,
                             project_columns: [0]))
  end

  def test_max_field_size_is_checked_on_skipped_column
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse("a,bbbb,c\n", max_field_size: 3,
                           project_columns: [0, 2])
    end
    assert_equal("Field size exceeded: 4 > 3 in line 1.", error.message)
  end

  def test_max_field_size_accepts_skipped_column_within_limit
    assert_equal([["a", "c"]],
                 CSV.parse("a,bbb,c\n", max_field_size: 3,
                             project_columns: [0, 2]))
  end

  def test_max_field_size_measures_stripped_value_of_skipped_column
    # The skipped column holds "bb" after stripping, which fits; the
    # unstripped size would exceed the limit.
    assert_equal([["a"]],
                 CSV.parse("a,bb   \n", strip: true, max_field_size: 2,
                             project_columns: [0]))
  end

  def test_max_field_size_measures_unescaped_value_of_skipped_column
    # The skipped column holds b"c (3 characters) after backslash
    # unescaping; the escaped size would exceed the limit.
    assert_equal([["a"]],
                 CSV.parse("a,b\\\"c\n",
                           liberal_parsing: {backslash_quote: true},
                           max_field_size: 3,
                           project_columns: [0]))
  end

  def test_error_location_is_not_changed
    data = "a,b,c\n1,2,3\n4,\"broken\"junk,6\n7,8,9\n"
    [nil, [0, 2], [1]].each do |projection|
      error = assert_raise(CSV::MalformedCSVError) do
        CSV.parse(data, project_columns: projection)
      end
      assert_equal(3, error.line_number)
    end
  end

  def test_illegal_quoting_in_skipped_column
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse("a,b\n1,2\"3\n", project_columns: [0])
    end
    assert_equal("Illegal quoting in line 2.", error.message)
  end

  def test_unclosed_quote_in_skipped_column
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse("a,b\n1,\"unclosed\n", project_columns: [0])
    end
    assert_equal("Unclosed quoted field in line 2.", error.message)
  end

  def test_broken_quote_in_chunked_large_skipped_field
    with_chunk_size("8192") do
      big_field = "a" * (256 * 1024)
      data = "id,big,tail\n1,\"#{big_field}junk,1\n"
      error = assert_raise(CSV::MalformedCSVError) do
        CSV.new(ChunkedIO.new(data), project_columns: [0, 2]).each.to_a
      end
      assert_equal(2, error.line_number)
    end
  end

  def test_unclosed_quote_in_chunked_large_skipped_field
    with_chunk_size("8192") do
      big_field = "a" * (256 * 1024)
      data = "id,big,tail\n1,\"#{big_field}\n"
      error = assert_raise(CSV::MalformedCSVError) do
        CSV.new(ChunkedIO.new(data), project_columns: [0, 2]).each.to_a
      end
      assert_equal("Unclosed quoted field in line 2.", error.message)
    end
  end

  def test_skipped_column_does_not_build_field_string
    with_chunk_size("8192") do
      # The input is delivered in 8192-byte chunks; without projection,
      # scanning the 512KiB field allocates at least one String per chunk
      # (64+ per row), while a projected-out field is skipped without
      # building any field String.
      big_field = "a" * (512 * 1024)
      data = +""
      10.times do |i|
        data << i.to_s << ",\"" << big_field << "\n" << big_field <<
                "\"," << i.to_s << "\n"
      end

      unprojected = count_allocations do
        CSV.new(ChunkedIO.new(data), row_sep: "\n").each.to_a
      end
      projected_rows = nil
      projected = count_allocations do
        projected_rows = CSV.new(ChunkedIO.new(data),
                                 row_sep: "\n",
                                 project_columns: [0, 2]).each.to_a
      end

      assert_equal(10.times.map {|i| [i.to_s, i.to_s]}, projected_rows)
      assert_operator(projected, :<, unprojected)
      assert_operator(unprojected - projected, :>, 500)
    end
  end

  def test_false_disables_projection
    assert_equal([["a", "b"]],
                 CSV.parse("a,b\n", project_columns: false))
  end

  def test_max_field_size_measures_double_quote_outside_quote_of_skipped_column
    # The skipped column holds "\"b\"" (3 characters) after
    # double_quote_outside_quote unescaping; the raw size would be 5.
    data = "a,\"\"b\"\"\n"
    options = {liberal_parsing: {double_quote_outside_quote: true}}
    assert_equal([["a"]],
                 CSV.parse(data, **options, max_field_size: 3,
                             project_columns: [0]))
    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(data, **options, max_field_size: 2, project_columns: [0])
    end
    assert_equal("Field size exceeded: 3 > 2 in line 1.", error.message)
  end
end
