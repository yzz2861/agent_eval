# frozen_string_literal: false

require_relative "../helper"
require "objspace"

class TestCSVParseProjection < Test::Unit::TestCase
  def test_selects_columns_by_original_index
    data = "zero,one,two,three\n0,1,2,3\n"

    assert_equal([%w{two zero}, %w{2 0}],
                 CSV.parse(data, projection: [2, 0]))
  end

  def test_ignores_trailing_line_ending_when_last_column_is_selected
    assert_equal([["b"], ["2"]],
                 CSV.parse("a,b\n1,2\n", projection: [1]))
  end

  def test_chunked_multibyte_ignored_columns
    io = ChunkedIO.new("あ,い,う\n1,2,3\n", 3)

    assert_equal([["う", "あ"], ["3", "1"]],
                 CSV.new(io, projection: [2, 0]).to_a)
  end

  def test_selects_columns_by_header
    data = "first,second,third\nA,B,C\n"

    table = CSV.parse(data, headers: true, projection: ["third", "first"])

    assert_equal(CSV::Row.new(%w{third first}, %w{C A}), table.first)
  end

  def test_mixes_header_and_index_selectors
    data = "First Name,Score\nAlice,100\n"

    table = CSV.parse(data,
                     headers: true,
                     header_converters: :symbol,
                     projection: [:score, 0])

    assert_equal(CSV::Row.new([:score, :first_name], %w{100 Alice}),
                 table.first)
  end

  def test_does_not_call_converter_for_ignored_columns
    converted_indices = []
    converter = lambda do |field, field_info|
      converted_indices << field_info.index
      field
    end
    data = "1,2,3\n"

    result = CSV.parse_line(data, projection: [2], converters: [converter])

    assert_equal(["3"], result)
    assert_equal([2], converted_indices)
  end

  def test_ignored_column_still_checks_max_field_size
    data = "keep,\"#{'x' * 10}\"\n"

    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(data, projection: [0], max_field_size: 9)
    end
    assert_equal("Field size exceeded: 10 > 9 in line 1.", error.message)
  end

  def test_ignored_column_still_checks_quoting
    data = "before,\"broken\"quote,after\n"

    error = assert_raise(CSV::MalformedCSVError) do
      CSV.parse(data, projection: [0, 2])
    end
    assert_equal("Any value after quoted field isn't allowed in line 1.",
                 error.message)
  end

  def test_ignored_quoted_field_does_not_allocate_large_field
    large_value = "x" * 10_000
    io = ChunkedIO.new("keep,\"#{large_value}\"\n", 32)
    allocations = trace_string_allocations(500) do
      CSV.new(io, projection: [0]).to_a
    end

    assert_equal([["keep"]], @parsed_rows)
    assert_equal([], allocations)
  end

  def test_ignored_unquoted_field_does_not_allocate_large_field
    large_value = "x" * 10_000
    io = ChunkedIO.new("keep,#{large_value}\n", 32)
    allocations = trace_string_allocations(500) do
      CSV.new(io, projection: [0], quote_char: nil).to_a
    end

    assert_equal([["keep"]], @parsed_rows)
    assert_equal([], allocations)
  end

  def test_ignored_unclosed_quoted_field_still_raises_with_chunks
    io = ChunkedIO.new("before,\"unclosed\n", 7)

    error = assert_raise(CSV::MalformedCSVError) do
      CSV.new(io, projection: [0]).to_a
    end
    assert_equal("Unclosed quoted field in line 1.", error.message)
  end

  private

  class ChunkedIO
    def initialize(data, chunk_size)
      @data = data
      @chunk_size = chunk_size
      @offset = 0
    end

    def gets(_row_separator, limit)
      return nil if @offset >= @data.bytesize

      chunk = @data.byteslice(@offset, @chunk_size)
      @offset += chunk.bytesize
      chunk
    end

    def eof?
      @offset >= @data.bytesize
    end
  end

  def trace_string_allocations(minimum_size)
    @parsed_rows = nil
    allocations = []
    GC.start
    GC.disable
    begin
      ObjectSpace.trace_object_allocations do
        @parsed_rows = yield
      end
      ObjectSpace.each_object(String) do |string|
        allocation_path = ObjectSpace.allocation_sourcefile(string)
        next unless allocation_path
        next unless allocation_path.end_with?("lib/csv/parser.rb")
        allocations << string if string.size >= minimum_size
      end
    ensure
      GC.enable
    end
    allocations
  end
end
