# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Pagination::MergedConnection do
  Connection = GraphQL::Pagination::MergedConnection

  def schema
    @schema ||= Class.new(GraphQL::Schema) do
      cursor_encoder(ConnectionAssertions::NonceEnabledEncoder)
    end
  end

  def context
    GraphQL::Query.new(schema, "{ __typename }").context
  end

  def connection_for(
    sources,
    first: 2,
    after: nil,
    last_value: nil,
    before: nil,
    direction: :asc,
    comparison_key: nil,
    sort_definition: nil,
    read_batch_size: 1
  )
    Connection.new(
      sources,
      context: context,
      first: first,
      after: after,
      last: last_value,
      before: before,
      max_page_size: 10,
      comparison_key: comparison_key || ->(node) { node[:key] },
      sort_definition: sort_definition || { "key" => "key", "direction" => "asc" },
      direction: direction,
      read_batch_size: read_batch_size,
    )
  end

  def source(id, rows, reads)
    Connection::Source.new(id, identity: ->(node) { node[:id] }) do |after:, limit:, context:|
      reads << { source: id, after: after, limit: limit, has_context: !context.nil? }
      start_index = after.nil? ? 0 : rows.index { |node| node[:id] == after } + 1
      rows[start_index, limit]
    end
  end

  def ascending_data
    {
      "a" => [
        { id: "a1", key: 1 },
        { id: "a2", key: 2 },
        { id: "a3", key: 2 },
        { id: "a4", key: 4 },
      ],
      "b" => [
        { id: "b1", key: 2 },
        { id: "b2", key: 3 },
        { id: "b3", key: 5 },
      ],
      "c" => [],
    }
  end

  def fresh_sources(data, reads)
    [
      source("a", data["a"], reads),
      source("b", data["b"], reads),
      source("c", data["c"], reads),
    ]
  end

  it "merges duplicate keys deterministically and resumes every page in a new connection" do
    data = ascending_data
    page1_reads = []
    page1 = connection_for(fresh_sources(data, page1_reads))

    assert_equal %w[a1 a2], page1.nodes.map { |node| node[:id] }
    assert_equal true, page1.has_next_page
    assert_equal false, page1.has_previous_page
    assert_equal [
      { source: "a", after: nil, limit: 1, has_context: true },
      { source: "b", after: nil, limit: 1, has_context: true },
      { source: "c", after: nil, limit: 1, has_context: true },
      { source: "a", after: "a1", limit: 1, has_context: true },
    ], page1_reads

    page2_reads = []
    page2 = connection_for(fresh_sources(data, page2_reads), after: page1.end_cursor)

    assert_equal %w[a3 b1], page2.nodes.map { |node| node[:id] }
    assert_equal true, page2.has_next_page
    assert_equal true, page2.has_previous_page
    assert_equal [
      { source: "a", after: "a2", limit: 1, has_context: true },
      { source: "b", after: nil, limit: 1, has_context: true },
      { source: "a", after: "a3", limit: 1, has_context: true },
    ], page2_reads
    assert_equal page2.end_cursor, page2.cursor_for(page2.nodes.last)
    assert_equal page2.start_cursor, page2.edges.first.cursor

    middle_page_reads = []
    middle_cursor = page1.cursor_for(page1.nodes.first)
    middle_page = connection_for(fresh_sources(data, middle_page_reads), first: 2, after: middle_cursor)
    assert_equal %w[a2 a3], middle_page.nodes.map { |node| node[:id] }

    page3_reads = []
    page3 = connection_for(fresh_sources(data, page3_reads), after: page2.end_cursor)
    assert_equal %w[b2 a4], page3.nodes.map { |node| node[:id] }

    page4_reads = []
    page4 = connection_for(fresh_sources(data, page4_reads), first: 3, after: page3.end_cursor)
    assert_equal %w[b3], page4.nodes.map { |node| node[:id] }
    assert_equal false, page4.has_next_page
  end

  it "does not reread a source whose cursor marks it exhausted" do
    data = ascending_data
    page1_reads = []
    page1 = connection_for(fresh_sources(data, page1_reads))
    page1.nodes

    page2_reads = []
    page2 = connection_for(fresh_sources(data, page2_reads), after: page1.end_cursor)
    page2.nodes

    refute_includes page2_reads.map { |read| read[:source] }, "c"
  end

  it "returns no nodes for first: 0 but probes only the next segment for has_next_page" do
    reads = []
    data = ascending_data
    page = connection_for(fresh_sources(data, reads), first: 0)

    assert_equal [], page.nodes
    assert_equal true, page.has_next_page
    assert_equal [
      { source: "a", after: nil, limit: 1, has_context: true },
      { source: "b", after: nil, limit: 1, has_context: true },
      { source: "c", after: nil, limit: 1, has_context: true },
    ], reads
  end

  it "merges descending sources with source and source-local identity tie-breakers" do
    data = {
      "a" => [
        { id: "a3", key: 3 },
        { id: "a1", key: 2 },
        { id: "a2", key: 2 },
      ],
      "b" => [
        { id: "b2", key: 2 },
        { id: "b1", key: 1 },
      ],
    }
    reads = []
    sources = [
      source("a", data["a"], reads),
      source("b", data["b"], reads),
    ]
    page = connection_for(
      sources,
      first: 10,
      direction: :desc,
      sort_definition: { "key" => "key", "direction" => "desc" },
    )

    assert_equal %w[a3 a1 a2 b2 b1], page.nodes.map { |node| node[:id] }
  end

  it "does not depend on source registration order when keys tie" do
    data = ascending_data
    reads = []
    page = connection_for(fresh_sources(data, reads).reverse, first: 4)

    assert_equal %w[a1 a2 a3 b1], page.nodes.map { |node| node[:id] }
  end

  it "rejects malformed cursors" do
    data = ascending_data
    encoded_cursor = ConnectionAssertions::NonceEnabledEncoder.encode("not-json")
    error = assert_raises(Connection::InvalidCursorError) do
      connection_for(fresh_sources(data, []), after: encoded_cursor).nodes
    end
    assert_includes error.message, "Invalid cursor"
  end

  it "rejects unsupported reverse pagination combinations" do
    reads = []
    data = ascending_data

    error = assert_raises(GraphQL::ExecutionError) do
      connection_for(fresh_sources(data, reads), first: 2, last_value: 2).nodes
    end
    assert_includes error.message, "last is not supported"

    cursor = connection_for(fresh_sources(data, [])).end_cursor
    error = assert_raises(GraphQL::ExecutionError) do
      connection_for(fresh_sources(data, reads), before: cursor).nodes
    end
    assert_includes error.message, "before is not supported"
  end

  it "rejects cursors from another source set or sort definition" do
    data = ascending_data
    cursor = connection_for(fresh_sources(data, [])).end_cursor

    wrong_sources = [
      source("a", data["a"], []),
      source("b", data["b"], []),
    ]
    error = assert_raises(Connection::InvalidCursorError) do
      connection_for(wrong_sources, after: cursor).nodes
    end
    assert_equal "Cursor was created for a different set of sources", error.message

    error = assert_raises(Connection::InvalidCursorError) do
      connection_for(
        fresh_sources(data, []),
        after: cursor,
        direction: :desc,
        sort_definition: { "key" => "key", "direction" => "desc" },
      ).nodes
    end
    assert_equal "Cursor was created with a different sort definition", error.message
  end

  it "requires an explicit sort definition for callable comparison keys" do
    empty_source = Class.new(Connection::Source) do
      def node_id(node)
        node[:id]
      end

      def read_batch(after:, limit:, context:)
        []
      end
    end
    error = assert_raises(Connection::SourceError) do
      Connection.new(
        [empty_source.new("a")],
        context: context,
        first: 1,
        comparison_key: ->(node) { node[:key] },
      )
    end
    assert_includes error.message, "sort_definition: is required"
  end

  it "requires JSON primitive values in cursor bindings and source cursors" do
    error = assert_raises(Connection::SourceError) do
      connection_for(
        fresh_sources(ascending_data, []),
        sort_definition: Object.new,
      )
    end
    assert_includes error.message, "sort_definition must be JSON-serializable"

    invalid_source = Connection::Source.new(
      "a",
      identity: ->(node) { node[:id] },
      cursor_for: ->(_node) { Object.new },
    ) { |after:, limit:, context:| [{ id: 1, key: 1 }][0, limit] }
    error = assert_raises(Connection::SourceError) do
      connection_for([invalid_source]).nodes
    end
    assert_includes error.message, "cursor_for must return a JSON-serializable value"
  end

  it "rejects sources whose next segment is not ordered as declared" do
    reads = []
    ordered_source = Class.new(Connection::Source) do
      def initialize(rows, reads)
        super("a", identity: ->(node) { node[:id] })
        @rows = rows
        @reads = reads
      end

      def read_batch(after:, limit:, context:)
        @reads << after
        start_index = after.nil? ? 0 : after.to_i
        @rows[start_index, limit]
      end

      def cursor_for(node)
        node[:id]
      end
    end
    rows = [
      { id: "1", key: 1 },
      { id: "2", key: 2 },
      { id: "0", key: 0 },
    ]
    page = connection_for([ordered_source.new(rows, reads)], read_batch_size: 1)

    error = assert_raises(Connection::SourceError) { page.nodes }
    assert_includes error.message, "out of order"
    assert_equal [nil, "1", "2"], reads
  end

  it "accepts an explicit node identity callback and opaque source cursor" do
    reads = []
    rows = [
      { id: 1, key: 1 },
      { id: 2, key: 2 },
    ]
    source = Connection::Source.new(
      "a",
      node_id: ->(node) { node[:id] },
      cursor_for: ->(node) { "cursor-#{node[:id]}" },
    ) do |after:, limit:, context:|
      reads << { after: after, limit: limit, has_context: !context.nil? }
      start_index = after.nil? ? 0 : after.delete_prefix("cursor-").to_i
      rows[start_index, limit]
    end
    page = connection_for([source])

    assert_equal %w[1 2], page.nodes.map { |node| node[:id].to_s }
    end_cursor_value = JSON.parse(
      schema.cursor_encoder.decode(page.end_cursor, nonce: true)
    ).dig("progress", "a", "cursor")
    assert_equal "cursor-2", end_cursor_value
    integer_source = Connection::Source.new(
      "i",
      identity: ->(node) { node[:id] },
      cursor_for: ->(node) { node[:id] },
    ) do |after:, limit:, context:|
      Array([{ id: 7, key: 7 }][after.to_i, limit])
    end
    integer_page = connection_for([integer_source])
    integer_cursor = JSON.parse(
      schema.cursor_encoder.decode(integer_page.end_cursor, nonce: true)
    ).dig("progress", "i", "cursor")
    assert_equal 7, integer_cursor
    assert_equal [
      { after: nil, limit: 1, has_context: true },
      { after: "cursor-1", limit: 1, has_context: true },
      { after: "cursor-2", limit: 1, has_context: true },
    ], reads
  end
end
