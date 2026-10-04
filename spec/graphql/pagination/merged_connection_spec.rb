# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Pagination::MergedConnection do
  # A source that records every fetch, to prove reads stay small and lazy.
  class RecordingSource
    attr_reader :source_id, :fetches

    def initialize(items, source_id:)
      @items = items
      @source_id = source_id
      @fetches = []
    end

    def fetch_entries(after:, limit:)
      start_index = after.nil? ? 0 : after + 1
      slice = @items[start_index, limit] || []
      @fetches << { after: after, limit: limit, returned: slice.length }
      slice.each_with_index.map { |item, offset| [start_index + offset, item] }
    end

    def fetched_count
      @fetches.sum { |fetch| fetch[:returned] }
    end
  end

  let(:schema) do
    Class.new(GraphQL::Schema) do
      cursor_encoder(ConnectionAssertions::NonceEnabledEncoder)
    end
  end

  let(:context) { GraphQL::Query.new(schema, "{ __typename }").context }

  let(:connection_class) do
    Class.new(GraphQL::Pagination::MergedConnection) do
      sort_key { |item| item[:name] }
      sort_id "by-name-v1"
    end
  end

  def build_connection(sources, **kwargs)
    connection_class.new(sources, context: context, **kwargs)
  end

  def array_source(items, source_id)
    GraphQL::Pagination::MergedConnection::ArraySource.new(items, source_id: source_id)
  end

  it "merges sources according to the caller-provided sort key" do
    sources = [
      array_source([{ name: "Beet" }, { name: "Dill" }], "b"),
      array_source([{ name: "Avocado" }, { name: "Cucumber" }], "a"),
    ]
    conn = build_connection(sources)
    assert_equal %w[Avocado Beet Cucumber Dill], conn.nodes.map { |node| node[:name] }
    assert_equal false, conn.has_next_page
    assert_equal false, conn.has_previous_page
  end

  it "wraps plain arrays with index-based source ids" do
    conn = build_connection([[{ name: "Beet" }], [{ name: "Avocado" }]])
    assert_equal %w[Avocado Beet], conn.nodes.map { |node| node[:name] }
  end

  it "breaks ties by stable source id, then in-source position" do
    sources = [
      array_source([{ name: "Same", tag: "b1" }, { name: "Same", tag: "b2" }], "b"),
      array_source([{ name: "Same", tag: "a1" }], "a"),
    ]
    conn = build_connection(sources)
    assert_equal %w[a1 b1 b2], conn.nodes.map { |node| node[:tag] }
  end

  it "paginates forward across duplicate keys, resuming each page in a fresh instance" do
    make_sources = -> {
      [
        array_source([{ name: "a", tag: "x1" }, { name: "a", tag: "x2" }, { name: "c", tag: "x3" }], "x"),
        array_source([{ name: "a", tag: "y1" }, { name: "b", tag: "y2" }, { name: "b", tag: "y3" }], "y"),
      ]
    }

    expected_pages = [
      %w[x1 x2],
      %w[y1 y2],
      %w[y3 x3],
    ]

    after_cursor = nil
    expected_pages.each_with_index do |expected_tags, page|
      conn = build_connection(make_sources.call, first: 2, after: after_cursor)
      assert_equal expected_tags, conn.nodes.map { |node| node[:tag] }, "page #{page + 1} nodes"
      assert_equal page > 0, conn.has_previous_page
      assert_equal page < expected_pages.length - 1, conn.has_next_page
      after_cursor = conn.end_cursor
      assert_instance_of String, after_cursor
    end
  end

  it "handles empty sources" do
    conn = build_connection([
      array_source([], "empty"),
      array_source([{ name: "Avocado" }], "full"),
    ])
    assert_equal %w[Avocado], conn.nodes.map { |node| node[:name] }
    assert_equal false, conn.has_next_page

    all_empty = build_connection([array_source([], "e1"), array_source([], "e2")])
    assert_equal [], all_empty.nodes
    assert_equal false, all_empty.has_next_page
    assert_nil all_empty.start_cursor
    assert_nil all_empty.end_cursor
  end

  it "rejects cursors bound to a different source set" do
    sources = [array_source([{ name: "Avocado" }], "a"), array_source([{ name: "Beet" }], "b")]
    cursor = build_connection(sources, first: 1).end_cursor

    other_sources = [array_source([{ name: "Avocado" }], "a"), array_source([{ name: "Beet" }], "c")]
    error = assert_raises(GraphQL::ExecutionError) do
      build_connection(other_sources, first: 1, after: cursor).nodes
    end
    assert_includes error.message, "Invalid cursor"
  end

  it "rejects cursors bound to a different sort definition" do
    sources = [array_source([{ name: "Avocado" }], "a")]
    cursor = build_connection(sources, first: 1).end_cursor

    other_connection_class = Class.new(GraphQL::Pagination::MergedConnection) do
      sort_key { |item| item[:name] }
      sort_id "by-name-v2"
    end
    error = assert_raises(GraphQL::ExecutionError) do
      other_connection_class.new(sources, context: context, first: 1, after: cursor).nodes
    end
    assert_includes error.message, "Invalid cursor"
  end

  it "rejects malformed cursors" do
    sources = [array_source([{ name: "Avocado" }], "a")]
    bogus = ConnectionAssertions::NonceEnabledEncoder.encode("not-a-merged-cursor", nonce: true)
    error = assert_raises(GraphQL::ExecutionError) do
      build_connection(sources, first: 1, after: bogus).nodes
    end
    assert_includes error.message, "Invalid cursor"
  end

  it "raises a clear error for unsupported backward pagination" do
    sources = [array_source([{ name: "Avocado" }, { name: "Beet" }], "a")]

    last_error = assert_raises(GraphQL::ExecutionError) do
      build_connection(sources, last: 1).nodes
    end
    assert_includes last_error.message, "forward pagination"

    cursor = build_connection(sources, first: 1).end_cursor
    before_error = assert_raises(GraphQL::ExecutionError) do
      build_connection(sources, before: cursor).nodes
    end
    assert_includes before_error.message, "forward pagination"
  end

  it "reads only small batches from the sources it needs" do
    source_a = RecordingSource.new(10.times.map { |i| { name: "a#{i}" } }, source_id: "a")
    source_b = RecordingSource.new(10.times.map { |i| { name: "b#{i}" } }, source_id: "b")
    conn = build_connection([source_a, source_b], first: 2)

    assert_equal [], source_a.fetches
    assert_equal [], source_b.fetches

    assert_equal [{ name: "a0" }, { name: "a1" }], conn.nodes
    assert_equal true, conn.has_next_page

    [source_a, source_b].each do |source|
      assert source.fetched_count <= 3, "expected small batches, fetched #{source.fetched_count} of 10 from #{source.source_id}"
      assert source.fetches.all? { |fetch| fetch[:limit] <= 3 }, "expected bounded batch sizes, got #{source.fetches.inspect}"
    end
  end

  it "resumes from cursors without relying on the previous instance" do
    source_a = RecordingSource.new(5.times.map { |i| { name: "a#{i}" } }, source_id: "a")
    source_b = RecordingSource.new(5.times.map { |i| { name: "b#{i}" } }, source_id: "b")
    page_one = build_connection([source_a, source_b], first: 3)
    assert_equal %w[a0 a1 a2], page_one.nodes.map { |node| node[:name] }

    # A brand-new instance with brand-new sources continues from the cursor:
    resumed_a = RecordingSource.new(5.times.map { |i| { name: "a#{i}" } }, source_id: "a")
    resumed_b = RecordingSource.new(5.times.map { |i| { name: "b#{i}" } }, source_id: "b")
    page_two = build_connection([resumed_a, resumed_b], first: 3, after: page_one.end_cursor)
    assert_equal %w[a3 a4 b0], page_two.nodes.map { |node| node[:name] }
    assert_equal true, page_two.has_previous_page
    assert_equal true, page_two.has_next_page

    # The resumed sources only read after their recorded positions:
    assert_equal 2, resumed_a.fetches.first[:after]
    assert_nil resumed_b.fetches.first[:after]
  end

  it "requires unique source ids" do
    sources = [array_source([], "dup"), array_source([], "dup")]
    error = assert_raises(GraphQL::Error) { build_connection(sources).nodes }
    assert_includes error.message, "unique"
  end
end
