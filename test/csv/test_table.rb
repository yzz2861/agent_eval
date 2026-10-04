# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "helper"

class TestCSVTable < Test::Unit::TestCase
  extend DifferentOFS

  def setup
    super
    @rows  = [ CSV::Row.new(%w{A B C}, [1, 2, 3]),
               CSV::Row.new(%w{A B C}, [4, 5, 6]),
               CSV::Row.new(%w{A B C}, [7, 8, 9]) ]
    @table = CSV::Table.new(@rows)

    @header_table = CSV::Table.new(
      [CSV::Row.new(%w{A B C}, %w{A B C}, true)] + @rows
    )

    @header_only_table = CSV::Table.new([], headers: %w{A B C})
  end

  def test_initialize
    assert_not_nil(@table)
    assert_instance_of(CSV::Table, @table)
  end

  def test_modes
    assert_equal(:col_or_row, @table.mode)

    # non-destructive changes, intended for one shot calls
    cols = @table.by_col
    assert_equal(:col_or_row, @table.mode)
    assert_equal(:col, cols.mode)
    assert_equal(@table, cols)

    rows = @table.by_row
    assert_equal(:col_or_row, @table.mode)
    assert_equal(:row, rows.mode)
    assert_equal(@table, rows)

    col_or_row = rows.by_col_or_row
    assert_equal(:row, rows.mode)
    assert_equal(:col_or_row, col_or_row.mode)
    assert_equal(@table, col_or_row)

    # destructive mode changing calls
    assert_equal(@table, @table.by_row!)
    assert_equal(:row, @table.mode)
    assert_equal(@table, @table.by_col_or_row!)
    assert_equal(:col_or_row, @table.mode)
  end

  def test_headers
    assert_equal(@rows.first.headers, @table.headers)
  end

  def test_headers_empty
    t = CSV::Table.new([])
    assert_equal Array.new, t.headers
  end

  def test_headers_only
    assert_equal(%w[A B C], @header_only_table.headers)
  end

  def test_headers_modified_by_row
    table = CSV::Table.new([], headers: ["A", "B"])
    table << ["a", "b"]
    table.first << {"C" => "c"}
    assert_equal(["A", "B", "C"], table.headers)
  end

  def test_index
    ##################
    ### Mixed Mode ###
    ##################
    # by row
    @rows.each_index { |i| assert_equal(@rows[i], @table[i]) }
    assert_equal(nil, @table[100])  # empty row

    # by row with Range
    assert_equal([@table[1], @table[2]], @table[1..2])

    # by col
    @rows.first.headers.each do |header|
      assert_equal(@rows.map { |row| row[header] }, @table[header])
    end
    assert_equal([nil] * @rows.size, @table["Z"])  # empty col

    # by cell, row then col
    assert_equal(2, @table[0][1])
    assert_equal(6, @table[1]["C"])

    # by cell, col then row
    assert_equal(5, @table["B"][1])
    assert_equal(9, @table["C"][2])

    # with headers (by col)
    assert_equal(["B", 2, 5, 8], @header_table["B"])

    ###################
    ### Column Mode ###
    ###################
    @table.by_col!

    assert_equal([2, 5, 8], @table[1])
    assert_equal([2, 5, 8], @table["B"])

    ################
    ### Row Mode ###
    ################
    @table.by_row!

    assert_equal(@rows[1], @table[1])
    assert_raise(TypeError) { @table["B"] }

    ############################
    ### One Shot Mode Change ###
    ############################
    assert_equal(@rows[1], @table[1])
    assert_equal([2, 5, 8], @table.by_col[1])
    assert_equal(@rows[1], @table[1])
  end

  def test_set_row_or_column
    ##################
    ### Mixed Mode ###
    ##################
    # set row
    @table[2] = [10, 11, 12]
    assert_equal([%w[A B C], [1, 2, 3], [4, 5, 6], [10, 11, 12]], @table.to_a)

    @table[3] = CSV::Row.new(%w[A B C], [13, 14, 15])
    assert_equal( [%w[A B C], [1, 2, 3], [4, 5, 6], [10, 11, 12], [13, 14, 15]],
                  @table.to_a )

    # set col
    @table["Type"] = "data"
    assert_equal( [ %w[A B C Type],
                    [1, 2, 3, "data"],
                    [4, 5, 6, "data"],
                    [10, 11, 12, "data"],
                    [13, 14, 15, "data"] ],
                  @table.to_a )

    @table["Index"] = [1, 2, 3]
    assert_equal( [ %w[A B C Type Index],
                    [1, 2, 3, "data", 1],
                    [4, 5, 6, "data", 2],
                    [10, 11, 12, "data", 3],
                    [13, 14, 15, "data", nil] ],
                  @table.to_a )

    @table["B"] = [100, 200]
    assert_equal( [ %w[A B C Type Index],
                    [1, 100, 3, "data", 1],
                    [4, 200, 6, "data", 2],
                    [10, nil, 12, "data", 3],
                    [13, nil, 15, "data", nil] ],
                  @table.to_a )

    # verify resulting table
    assert_equal(<<-CSV, @table.to_csv)
A,B,C,Type,Index
1,100,3,data,1
4,200,6,data,2
10,,12,data,3
13,,15,data,
    CSV

    # with headers
    @header_table["Type"] = "data"
    assert_equal(%w[Type data data data], @header_table["Type"])

    ###################
    ### Column Mode ###
    ###################
    @table.by_col!

    @table[1] = [2, 5, 11, 14]
    assert_equal( [ %w[A B C Type Index],
                    [1, 2, 3, "data", 1],
                    [4, 5, 6, "data", 2],
                    [10, 11, 12, "data", 3],
                    [13, 14, 15, "data", nil] ],
                  @table.to_a )

    @table["Extra"] = "new stuff"
    assert_equal( [ %w[A B C Type Index Extra],
                    [1, 2, 3, "data", 1, "new stuff"],
                    [4, 5, 6, "data", 2, "new stuff"],
                    [10, 11, 12, "data", 3, "new stuff"],
                    [13, 14, 15, "data", nil, "new stuff"] ],
                  @table.to_a )

    ################
    ### Row Mode ###
    ################
    @table.by_row!

    @table[1] = (1..6).to_a
    assert_equal( [ %w[A B C Type Index Extra],
                    [1, 2, 3, "data", 1, "new stuff"],
                    [1, 2, 3, 4, 5, 6],
                    [10, 11, 12, "data", 3, "new stuff"],
                    [13, 14, 15, "data", nil, "new stuff"] ],
                  @table.to_a )

    assert_raise(TypeError) { @table["Extra"] = nil }
  end

  def test_set_by_col_with_header_row
    r  = [ CSV::Row.new(%w{X Y Z}, [97, 98, 99], true) ]
    t = CSV::Table.new(r)
    t.by_col!
    t['A'] = [42]
    assert_equal(['A'], t['A'])
  end

  def test_each
    ######################
    ### Mixed/Row Mode ###
    ######################
    i = 0
    @table.each do |row|
      assert_equal(@rows[i], row)
      i += 1
    end

    # verify that we can chain the call
    assert_equal(@table, @table.each { })

    # without block
    enum = @table.each
    assert_instance_of(Enumerator, enum)
    assert_equal(@table.size, enum.size)

    i = 0
    enum.each do |row|
      assert_equal(@rows[i], row)
      i += 1
    end

    ###################
    ### Column Mode ###
    ###################
    @table.by_col!

    headers = @table.headers
    @table.each do |header, column|
      assert_equal(headers.shift, header)
      assert_equal(@table[header], column)
    end

    # without block
    enum = @table.each
    assert_instance_of(Enumerator, enum)
    assert_equal(@table.headers.size, enum.size)

    headers = @table.headers
    enum.each do |header, column|
      assert_equal(headers.shift, header)
      assert_equal(@table[header], column)
    end

    ############################
    ### One Shot Mode Change ###
    ############################
    @table.by_col_or_row!

    @table.each { |row| assert_instance_of(CSV::Row, row) }
    @table.by_col.each { |tuple| assert_instance_of(Array, tuple) }
    @table.each { |row| assert_instance_of(CSV::Row, row) }
  end

  def test_each_by_col_duplicated_headers
    table = CSV.parse(<<-CSV, headers: true)
a,a,,,b
1,2,3,4,5
11,12,13,14,15
    CSV
    assert_equal([
                   ["a", ["1", "11"]],
                   ["a", ["2", "12"]],
                   [nil, ["3", "13"]],
                   [nil, ["4", "14"]],
                   ["b", ["5", "15"]],
                 ],
                 table.by_col.each.to_a)
  end

  def test_each_split
    yielded_values = []
    @table.each do |column1, column2, column3|
      yielded_values << [column1, column2, column3]
    end
    assert_equal(@rows.collect(&:to_a),
                 yielded_values)
  end

  def test_enumerable
    assert_equal( @rows.values_at(0, 2),
                  @table.select { |row| (row["B"] % 2).zero? } )

    assert_equal(@rows[1], @table.find { |row| row["C"] > 5 })
  end

  def test_to_a
    assert_equal([%w[A B C], [1, 2, 3], [4, 5, 6], [7, 8, 9]], @table.to_a)

    # with headers
    assert_equal( [%w[A B C], [1, 2, 3], [4, 5, 6], [7, 8, 9]],
                  @header_table.to_a )
  end

  def test_to_csv
    csv = <<-CSV
A,B,C
1,2,3
4,5,6
7,8,9
    CSV

    # normal conversion
    assert_equal(csv, @table.to_csv)
    assert_equal(csv, @table.to_s)  # alias

    # with options
    assert_equal( csv.gsub(",", "|").gsub("\n", "\r\n"),
                  @table.to_csv(col_sep: "|", row_sep: "\r\n") )
    assert_equal( csv.lines.to_a[1..-1].join(''),
                  @table.to_csv(:write_headers => false) )

    # with headers
    assert_equal(csv, @header_table.to_csv)
  end

  def test_to_csv_limit_positive
    assert_equal(<<-CSV, @table.to_csv(limit: 2))
A,B,C
1,2,3
4,5,6
    CSV
  end

  def test_to_csv_limit_positive_over
    assert_equal(<<-CSV, @table.to_csv(limit: 5))
A,B,C
1,2,3
4,5,6
7,8,9
    CSV
  end

  def test_to_csv_limit_zero
    assert_equal(<<-CSV, @table.to_csv(limit: 0))
A,B,C
    CSV
  end

  def test_to_csv_limit_negative
    assert_equal(<<-CSV, @table.to_csv(limit: -2))
A,B,C
1,2,3
4,5,6
    CSV
  end

  def test_to_csv_limit_negative_over
    assert_equal(<<-CSV, @table.to_csv(limit: -5))
A,B,C
    CSV
  end

  def test_append
    # verify that we can chain the call
    assert_equal(@table, @table << [10, 11, 12])

    # Array append
    assert_equal(CSV::Row.new(%w[A B C], [10, 11, 12]), @table[-1])

    # Row append
    assert_equal(@table, @table << CSV::Row.new(%w[A B C], [13, 14, 15]))
    assert_equal(CSV::Row.new(%w[A B C], [13, 14, 15]), @table[-1])
  end

  def test_delete_mixed_one
    ##################
    ### Mixed Mode ###
    ##################
    # delete a row
    assert_equal(@rows[1], @table.delete(1))

    # delete a col
    assert_equal(@rows.map { |row| row["A"] }, @table.delete("A"))

    # verify resulting table
    assert_equal(<<-CSV, @table.to_csv)
B,C
2,3
8,9
    CSV
  end

  def test_delete_mixed_multiple
    ##################
    ### Mixed Mode ###
    ##################
    # delete row and col
    second_row = @rows[1]
    a_col = @rows.map { |row| row["A"] }
    a_col_without_second_row = a_col[0..0] + a_col[2..-1]
    assert_equal([
                   second_row,
                   a_col_without_second_row,
                 ],
                 @table.delete(1, "A"))

    # verify resulting table
    assert_equal(<<-CSV, @table.to_csv)
B,C
2,3
8,9
    CSV
  end

  def test_delete_column
    ###################
    ### Column Mode ###
    ###################
    @table.by_col!

    assert_equal(@rows.map { |row| row[0] }, @table.delete(0))
    assert_equal(@rows.map { |row| row["C"] }, @table.delete("C"))

    # verify resulting table
    assert_equal(<<-CSV, @table.to_csv)
B
2
5
8
    CSV
  end

  def test_delete_row
    ################
    ### Row Mode ###
    ################
    @table.by_row!

    assert_equal(@rows[1], @table.delete(1))
    assert_raise(TypeError) { @table.delete("C") }

    # verify resulting table
    assert_equal(<<-CSV, @table.to_csv)
A,B,C
1,2,3
7,8,9
    CSV
  end

  def test_delete_with_blank_rows
    data = "col1,col2\nra1,ra2\n\nrb1,rb2"
    table = CSV.parse(data, :headers => true)
    assert_equal(["ra2", nil, "rb2"], table.delete("col2"))
  end

  def test_delete_if_row
    ######################
    ### Mixed/Row Mode ###
    ######################
    # verify that we can chain the call
    assert_equal(@table, @table.delete_if { |row| (row["B"] % 2).zero? })

    # verify resulting table
    assert_equal(<<-CSV, @table.to_csv)
A,B,C
4,5,6
    CSV
  end

  def test_delete_if_row_without_block
    ######################
    ### Mixed/Row Mode ###
    ######################
    enum = @table.delete_if
    assert_instance_of(Enumerator, enum)
    assert_equal(@table.size, enum.size)

    # verify that we can chain the call
    assert_equal(@table, enum.each { |row| (row["B"] % 2).zero? })

    # verify resulting table
    assert_equal(<<-CSV, @table.to_csv)
A,B,C
4,5,6
    CSV
  end

  def test_delete_if_column
    ###################
    ### Column Mode ###
    ###################
    @table.by_col!

    assert_equal(@table, @table.delete_if { |h, v| h > "A" })
    assert_equal(<<-CSV, @table.to_csv)
A
1
4
7
    CSV
  end

  def test_delete_if_column_without_block
    ###################
    ### Column Mode ###
    ###################
    @table.by_col!

    enum = @table.delete_if
    assert_instance_of(Enumerator, enum)
    assert_equal(@table.headers.size, enum.size)

    assert_equal(@table, enum.each { |h, v| h > "A" })
    assert_equal(<<-CSV, @table.to_csv)
A
1
4
7
    CSV
  end

  def test_delete_headers_only
    ###################
    ### Column Mode ###
    ###################
    @header_only_table.by_col!

    # delete by index
    assert_equal([], @header_only_table.delete(0))
    assert_equal(%w[B C], @header_only_table.headers)

    # delete by header
    assert_equal([], @header_only_table.delete("C"))
    assert_equal(%w[B], @header_only_table.headers)
  end

  def test_values_at
    ##################
    ### Mixed Mode ###
    ##################
    # rows
    assert_equal(@rows.values_at(0, 2), @table.values_at(0, 2))
    assert_equal(@rows.values_at(1..2), @table.values_at(1..2))

    # cols
    assert_equal([[1, 3], [4, 6], [7, 9]], @table.values_at("A", "C"))
    assert_equal([[2, 3], [5, 6], [8, 9]], @table.values_at("B".."C"))

    ###################
    ### Column Mode ###
    ###################
    @table.by_col!

    assert_equal([[1, 3], [4, 6], [7, 9]], @table.values_at(0, 2))
    assert_equal([[1, 3], [4, 6], [7, 9]], @table.values_at("A", "C"))

    ################
    ### Row Mode ###
    ################
    @table.by_row!

    assert_equal(@rows.values_at(0, 2), @table.values_at(0, 2))
    assert_raise(TypeError) { @table.values_at("A", "C") }

    ############################
    ### One Shot Mode Change ###
    ############################
    assert_equal(@rows.values_at(0, 2), @table.values_at(0, 2))
    assert_equal([[1, 3], [4, 6], [7, 9]], @table.by_col.values_at(0, 2))
    assert_equal(@rows.values_at(0, 2), @table.values_at(0, 2))
  end

  def test_array_delegation
    assert_not_empty(@table, "Table was empty.")

    assert_equal(@rows.size, @table.size)
  end

  def test_inspect_shows_current_mode
    str = @table.inspect
    assert_include(str, "mode:#{@table.mode}", "Mode not shown.")

    @table.by_col!
    str = @table.inspect
    assert_include(str, "mode:#{@table.mode}", "Mode not shown.")
  end

  def test_inspect_encoding_is_ascii_compatible
    assert_send([Encoding, :compatible?,
                 Encoding.find("US-ASCII"),
                 @table.inspect.encoding],
                "inspect() was not ASCII compatible." )
  end

  def test_inspect_with_rows
    additional_rows  = [ CSV::Row.new(%w{A B C}, [101, 102, 103]),
                         CSV::Row.new(%w{A B C}, [104, 105, 106]),
                         CSV::Row.new(%w{A B C}, [107, 108, 109]) ]
    table = CSV::Table.new(@rows + additional_rows)
    str_table = table.inspect

    assert_equal(<<-CSV, str_table)
#<CSV::Table mode:col_or_row row_count:7>
A,B,C
1,2,3
4,5,6
7,8,9
101,102,103
104,105,106
    CSV
  end

  def test_dig_mixed
    # by row
    assert_equal(@rows[0], @table.dig(0))
    assert_nil(@table.dig(100))  # empty row

    # by col
    assert_equal([2, 5, 8], @table.dig("B"))
    assert_equal([nil] * @rows.size, @table.dig("Z"))  # empty col

    # by row then col
    assert_equal(2, @table.dig(0, 1))
    assert_equal(6, @table.dig(1, "C"))

    # by col then row
    assert_equal(5, @table.dig("B", 1))
    assert_equal(9, @table.dig("C", 2))
  end

  def test_dig_by_column
    @table.by_col!

    assert_equal([2, 5, 8], @table.dig(1))
    assert_equal([2, 5, 8], @table.dig("B"))

    # by col then row
    assert_equal(5, @table.dig("B", 1))
    assert_equal(9, @table.dig("C", 2))
  end

  def test_dig_by_row
    @table.by_row!

    assert_equal(@rows[1], @table.dig(1))
    assert_raise(TypeError) { @table.dig("B") }

    # by row then col
    assert_equal(2, @table.dig(0, 1))
    assert_equal(6, @table.dig(1, "C"))
  end

  def test_dig_cell
    table = CSV::Table.new([CSV::Row.new(["A"], [["foo", ["bar", ["baz"]]]])])

    # by row, col then cell
    assert_equal("foo", table.dig(0, "A", 0))
    assert_equal(["baz"], table.dig(0, "A", 1, 1))

    # by col, row then cell
    assert_equal("foo", table.dig("A", 0, 0))
    assert_equal(["baz"], table.dig("A", 0, 1, 1))
  end

  def test_dig_cell_no_dig
    table = CSV::Table.new([CSV::Row.new(["A"], ["foo"])])

    # by row, col then cell
    assert_raise(TypeError) do
      table.dig(0, "A", 0)
    end

    # by col, row then cell
    assert_raise(TypeError) do
      table.dig("A", 0, 0)
    end
  end

  def test_pivot
    table = CSV::Table.new([
      CSV::Row.new(%w[account month value], ["Cash", "Jan", "10"]),
      CSV::Row.new(%w[account month value], ["Cash", "Feb", "20"]),
      CSV::Row.new(%w[account month value], ["AR", "Jan", "30"]),
    ])

    pivoted = table.pivot("account", "month", "value")

    assert_equal([%w[account Jan Feb],
                  ["Cash", "10", "20"],
                  ["AR", "30", nil]],
                 pivoted.to_a)
    assert_equal(<<-CSV, pivoted.to_csv)
account,Jan,Feb
Cash,10,20
AR,30,
    CSV
  end

  def test_pivot_with_multiple_row_keys
    table = CSV::Table.new([
      CSV::Row.new(%w[region account month value], ["West", "Cash", "Jan", "10"]),
      CSV::Row.new(%w[region account month value], ["West", "Cash", "Feb", "20"]),
      CSV::Row.new(%w[region account month value], ["East", "Cash", "Jan", "30"]),
    ])

    pivoted = table.pivot(%w[region account], "month", "value")

    assert_equal([%w[region account Jan Feb],
                  ["West", "Cash", "10", "20"],
                  ["East", "Cash", "30", nil]],
                 pivoted.to_a)
  end

  def test_pivot_with_column_indices_and_duplicate_headers
    table = CSV::Table.new([
      CSV::Row.new(["id", "dimension", "dimension", "value"],
                   [1, "Cash", "Jan", "10"]),
      CSV::Row.new(["id", "dimension", "dimension", "value"],
                   [1, "Cash", "Feb", "20"]),
    ])

    pivoted = table.pivot([0, 1], 2, 3)

    assert_equal([%w[id dimension Jan Feb],
                  [1, "Cash", "10", "20"]],
                 pivoted.to_a)
  end

  def test_pivot_with_duplicate_row_key_headers
    table = CSV::Table.new([
      CSV::Row.new(["name", "name", "month", "value"],
                   ["Cash", "Account", "Jan", "10"]),
      CSV::Row.new(["name", "name", "month", "value"],
                   ["Cash", "Account", "name", "20"]),
    ])

    pivoted = table.pivot([0, 1], 2, 3)

    assert_equal(["name", "name", "Jan", "name"], pivoted.headers)
    assert_equal(["Cash", "Account", "10", "20"], pivoted.first.fields)
    assert_equal("20", pivoted.first.field("name", 2))
    assert_equal(true, pivoted.first.header?("name", 2))
    assert_equal([%w[name name column value],
                  ["Cash", "Account", "Jan", "10"],
                  ["Cash", "Account", "name", "20"]],
                 pivoted.unpivot([0, 1]).to_a)
  end

  def test_pivot_explicit_columns_order_and_missing_coordinates
    table = CSV::Table.new([
      CSV::Row.new(%w[account month value], ["Cash", "Jan", nil]),
      CSV::Row.new(%w[account month value], ["AR", "Mar", "30"]),
    ])

    pivoted = table.pivot(0, 1, 2, columns: %w[Feb Jan Mar])

    assert_equal(%w[account Feb Jan Mar], pivoted.headers)
    assert_equal(["Cash", nil, nil, nil], pivoted.first.fields)
    assert_equal(["AR", nil, nil, "30"], pivoted[-1].fields)
    assert_equal(<<-CSV, pivoted.to_csv)
account,Feb,Jan,Mar
Cash,,,
AR,,,30
    CSV

    cash = pivoted.first
    assert_equal(true, cash.header?("Jan"))
    assert_nil(cash["Jan"])
    assert_equal(false, cash.header?("Feb"))
    assert_equal(false, cash.header?("Mar"))
  end

  def test_pivot_distinguishes_nil_from_missing_coordinate_on_unpivot
    table = CSV::Table.new([
      CSV::Row.new(%w[account month value], ["Cash", "Jan", nil]),
      CSV::Row.new(%w[account month value], ["Cash", "Feb", "20"]),
    ])

    pivoted = table.pivot(0, 1, 2, columns: %w[Jan Feb Mar])
    unpivoted = pivoted.unpivot(0, [1, 2, 3],
                                column_key: "month",
                                value_key: "value")

    assert_equal([%w[account month value],
                  ["Cash", "Jan", nil],
                  ["Cash", "Feb", "20"]],
                 unpivoted.to_a)
  end

  def test_pivot_conflict
    table = CSV::Table.new([
      CSV::Row.new(%w[account month value], ["Cash", "Jan", 10]),
      CSV::Row.new(%w[account month value], ["Cash", "Jan", 20]),
    ])

    message = assert_raise(ArgumentError) do
      table.pivot(0, 1, 2)
    end.message
    assert_match(/multiple values/, message)
  end

  def test_pivot_with_merge_function
    table = CSV::Table.new([
      CSV::Row.new(%w[account month value], ["Cash", "Jan", 10]),
      CSV::Row.new(%w[account month value], ["Cash", "Jan", 20]),
    ])

    pivoted = table.pivot(0, 1, 2) { |old_value, new_value| old_value + new_value }

    assert_equal(30, pivoted.first["Jan"])

    pivoted = table.pivot(0, 1, 2, merge: ->(old_value, new_value) { old_value * new_value })
    assert_equal(200, pivoted.first["Jan"])
  end

  def test_pivot_rejects_unexpected_explicit_column
    table = CSV::Table.new([
      CSV::Row.new(%w[account month value], ["Cash", "Jan", "10"]),
    ])

    assert_raise(ArgumentError) do
      table.pivot(0, 1, 2, columns: %w[Feb])
    end
  end

  def test_pivot_with_empty_string_column_label
    table = CSV::Table.new([
      CSV::Row.new(%w[account month value], ["Cash", "", "10"]),
      CSV::Row.new(%w[account month value], ["Cash", "Jan", "20"]),
    ])

    pivoted = table.pivot(0, 1, 2)

    assert_equal(["account", "", "Jan"], pivoted.headers)
    assert_equal(["Cash", "10", "20"], pivoted.first.fields)
    assert_equal(<<-CSV, pivoted.to_csv)
account,"",Jan
Cash,10,20
    CSV
  end

  def test_pivot_empty_table_preserves_headers
    table = CSV::Table.new([], headers: %w[account month value])

    pivoted = table.pivot(0, 1, 2, columns: %w[Jan Feb])

    assert_equal([], pivoted.to_a[1..])
    assert_equal(%w[account Jan Feb], pivoted.headers)
  end

  def test_pivot_does_not_modify_input
    rows = [
      CSV::Row.new(%w[account month value], ["Cash", "Jan", "10"]),
      CSV::Row.new(%w[account month value], ["Cash", "Feb", "20"]),
    ]
    table = CSV::Table.new(rows)
    before = table.to_a

    pivoted = table.pivot(0, 1, 2)
    pivoted["Jan"] = ["99"]

    assert_equal(before, table.to_a)
    assert_equal(["Cash", "Jan", "10"], rows.first.fields)
    assert_equal(["Cash", "Feb", "20"], rows[-1].fields)
  end

  def test_unpivot
    table = CSV::Table.new([
      CSV::Row.new(%w[account Jan Feb], ["Cash", "10", "20"]),
      CSV::Row.new(%w[account Jan Feb], ["AR", "30", nil]),
    ])

    unpivoted = table.unpivot("account", ["Jan", "Feb"],
                              column_key: "month",
                              value_key: "value")

    assert_equal([%w[account month value],
                  ["Cash", "Jan", "10"],
                  ["Cash", "Feb", "20"],
                  ["AR", "Jan", "30"],
                  ["AR", "Feb", nil]],
                 unpivoted.to_a)
  end

  def test_unpivot_defaults_to_remaining_columns
    table = CSV::Table.new([
      CSV::Row.new(%w[account Jan Feb], ["Cash", "10", "20"]),
    ])

    unpivoted = table.unpivot("account")

    assert_equal([%w[account column value],
                  ["Cash", "Jan", "10"],
                  ["Cash", "Feb", "20"]],
                 unpivoted.to_a)
  end

  def test_unpivot_with_nil_output_headers
    table = CSV::Table.new([
      CSV::Row.new(%w[account Jan], ["Cash", "10"]),
    ])

    unpivoted = table.unpivot("account", ["Jan"],
                              column_key: nil,
                              value_key: nil)

    assert_equal(["account", nil, nil], unpivoted.headers)
    assert_equal(["Cash", "Jan", "10"], unpivoted.first.fields)
  end

  def test_unpivot_with_column_indices_and_empty_string_label
    table = CSV::Table.new([
      CSV::Row.new(["account", "", "Jan"], ["Cash", "10", "20"]),
    ])

    unpivoted = table.unpivot(0, [1, 2],
                              column_key: "month",
                              value_key: "value")

    assert_equal([%w[account month value],
                  ["Cash", "", "10"],
                  ["Cash", "Jan", "20"]],
                 unpivoted.to_a)
  end

  def test_unpivot_empty_table_preserves_headers
    table = CSV::Table.new([], headers: %w[account Jan Feb])

    unpivoted = table.unpivot("account", ["Jan", "Feb"],
                              column_key: "month",
                              value_key: "value")

    assert_equal([], unpivoted.to_a[1..])
    assert_equal(%w[account month value], unpivoted.headers)
  end
end
