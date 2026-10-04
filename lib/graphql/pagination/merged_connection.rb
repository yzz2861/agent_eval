# frozen_string_literal: true
require "graphql/pagination/connection"

module GraphQL
  module Pagination
    # A connection that merges several already-sorted sources into a single
    # forward-paginated list, ordered by a caller-provided comparison key.
    #
    # Each source must be sorted by the same key and must provide:
    #
    # - `source_id`: a stable identifier, unique among the merged sources. It's
    #   used to break ties between equal keys and is recorded in cursors.
    # - `fetch_entries(after:, limit:)`: returns up to `limit` entries strictly
    #   after the given position (`after: nil` means "from the beginning").
    #   Each entry is a `[position, item]` pair. Positions must be stable,
    #   JSON-serializable, and strictly increasing within the source, so that a
    #   new connection instance can resume from a cursor without relying on any
    #   previously-open iterator or IO.
    #
    # {ArraySource} implements this interface for in-memory arrays, and plain
    # arrays are wrapped automatically (using their index as `source_id`).
    #
    # The comparison key is provided by the caller with {.sort_key}:
    #
    # @example Merging two sorted sources
    #   class FeedConnection < GraphQL::Pagination::MergedConnection
    #     sort_key { |item| item.created_at }
    #     sort_id "feed-by-created-at-v1"
    #   end
    #
    # Items are ordered by `(key, source_id, position)`, so equal keys are
    # resolved deterministically instead of depending on incidental fetch order.
    #
    # Cursors record the sort identifier and the per-source positions, so any
    # page can be resumed by a fresh connection instance. Cursors are bound to
    # the source set and sort definition: a cursor issued for a different set of
    # sources or a different {.sort_id} is rejected.
    #
    # Only forward pagination (`first`/`after`) is supported; `last`/`before`
    # raise {GraphQL::ExecutionError}.
    class MergedConnection < Pagination::Connection
      # Number of entries to read from a source at a time when no `first` limit applies.
      DEFAULT_BATCH_SIZE = 100

      class << self
        # @param key_proc [Proc, nil] When given, sets the comparison key for this connection
        # @return [Proc, nil] The configured comparison key
        def sort_key(key_proc = nil, &block)
          key_proc ||= block
          if key_proc
            @sort_key = key_proc
          elsif defined?(@sort_key) && @sort_key
            @sort_key
          elsif superclass.respond_to?(:sort_key)
            superclass.sort_key
          end
        end

        # @param new_id [String, nil] When given, sets the sort identifier recorded in cursors
        # @return [String] An identifier for the sort definition, used to bind cursors
        def sort_id(new_id = nil)
          if new_id
            @sort_id = new_id.to_s
          elsif defined?(@sort_id) && @sort_id
            @sort_id
          elsif superclass.respond_to?(:sort_id) && superclass.sort_id
            superclass.sort_id
          else
            name || "GraphQL::Pagination::MergedConnection"
          end
        end

        # @api private
        def normalize_source(source, index)
          if source.respond_to?(:source_id) && source.respond_to?(:fetch_entries)
            source
          elsif source.is_a?(Array)
            ArraySource.new(source, source_id: index.to_s)
          else
            raise GraphQL::Error, "MergedConnection sources must respond to `source_id` and `fetch_entries(after:, limit:)` (or be Arrays), got: #{source.inspect}"
          end
        end
      end

      def nodes
        load_nodes
        @nodes
      end

      def has_next_page
        load_nodes
        @has_next_page
      end

      def has_previous_page
        !after.nil?
      end

      def cursor_for(item)
        load_nodes
        cursors = @cursors_by_item[item]
        if cursors.nil? || cursors.empty?
          raise GraphQL::ExecutionError, "Can't generate a cursor for an item that isn't in this page"
        end
        # Items are emitted in order, so identical objects get their cursors in emission order.
        cursors.length > 1 ? cursors.shift : cursors.first
      end

      private

      def sources
        @sources ||= begin
          normalized = items.each_with_index.map { |source, idx| self.class.normalize_source(source, idx) }
          ids = normalized.map { |source| source.source_id.to_s }
          if ids.uniq.length != ids.length
            raise GraphQL::Error, "MergedConnection sources must have unique `source_id`s, got: #{ids.inspect}"
          end
          normalized
        end
      end

      def key_for(item)
        key_proc = self.class.sort_key
        if key_proc.nil?
          raise GraphQL::Error, "Define a comparison key with `#{(self.class.name || "MergedConnection")}.sort_key { |item| ... }`"
        end
        key_proc.call(item)
      end

      def load_nodes
        @nodes ||= begin
          if before || last
            raise GraphQL::ExecutionError, "#{(self.class.name || "MergedConnection")} only supports forward pagination (`first`/`after`); `before`/`last` are not supported."
          end

          resumed_positions = positions_from_cursor(after)
          states = sources.map { |source| SourceState.new(source, resumed_positions[source.source_id.to_s]) }
          limit = first
          nodes = []
          @cursors_by_item = Hash.new { |hash, key| hash[key] = [] }.compare_by_identity

          loop do
            break if limit && nodes.length >= limit
            remaining = limit ? limit - nodes.length : nil
            batch_size = remaining ? remaining + 1 : DEFAULT_BATCH_SIZE

            best_state = nil
            best_entry = nil
            states.each do |state|
              entry = state.peek(batch_size)
              next if entry.nil?
              if best_entry.nil? || head_comes_first?(entry, state.source_id, best_entry, best_state.source_id)
                best_state = state
                best_entry = entry
              end
            end
            break if best_entry.nil?

            best_state.advance
            nodes << best_entry[1]
            @cursors_by_item[best_entry[1]] << encode_cursor(states)
          end

          @has_next_page = limit ? states.any? { |state| !state.peek(1).nil? } : false
          nodes
        end
      end

      # Total order: comparison key, then stable source id, then in-source position.
      def head_comes_first?(entry_a, source_id_a, entry_b, source_id_b)
        key_a = key_for(entry_a[1])
        key_b = key_for(entry_b[1])
        cmp = key_a <=> key_b
        if cmp.nil?
          raise GraphQL::Error, "Can't compare sort keys #{key_a.inspect} and #{key_b.inspect}; make sure `sort_key` returns comparable values"
        end
        return true if cmp < 0
        return false if cmp > 0
        cmp = source_id_a <=> source_id_b
        return true if cmp < 0
        return false if cmp > 0
        position_cmp = entry_a[0] <=> entry_b[0]
        !position_cmp.nil? && position_cmp < 0
      end

      def encode_cursor(states)
        positions = {}
        states.each { |state| positions[state.source_id] = state.last_position }
        encode(JSON.dump({ "v" => 1, "sort" => self.class.sort_id, "pos" => positions }))
      end

      def positions_from_cursor(cursor)
        return {} if cursor.nil?
        payload = begin
          JSON.parse(decode(cursor))
        rescue StandardError
          raise GraphQL::ExecutionError, "Invalid cursor: #{cursor.inspect}"
        end
        positions = payload.is_a?(Hash) ? payload["pos"] : nil
        if !payload.is_a?(Hash) ||
            payload["v"] != 1 ||
            payload["sort"] != self.class.sort_id ||
            !positions.is_a?(Hash) ||
            positions.keys != sources.map { |source| source.source_id.to_s }
          raise GraphQL::ExecutionError, "Invalid cursor: #{cursor.inspect} doesn't match this connection's sources and sort definition"
        end
        positions
      end

      # Runtime merge state for one source. Holds only a small buffer of fetched
      # entries; all resumable state lives in `last_position`, which is recorded
      # in cursors.
      # @api private
      class SourceState
        attr_reader :source_id, :last_position

        def initialize(source, resumed_position)
          @source = source
          @source_id = source.source_id.to_s
          @last_position = resumed_position
          @buffer = []
          @exhausted = false
        end

        def peek(batch_size)
          fill(batch_size) if @buffer.empty? && !@exhausted
          @buffer.first
        end

        def advance
          position, _item = @buffer.shift
          @last_position = position
        end

        private

        def fill(batch_size)
          entries = @source.fetch_entries(after: @last_position, limit: batch_size)
          @exhausted = true if entries.length < batch_size
          @buffer.concat(entries)
        end
      end

      # An in-memory array back-end for {MergedConnection}; positions are array indexes.
      class ArraySource
        attr_reader :source_id

        def initialize(items, source_id:)
          @items = items
          @source_id = source_id.to_s
        end

        def fetch_entries(after:, limit:)
          start_index = after.nil? ? 0 : after + 1
          slice = @items[start_index, limit] || []
          slice.each_with_index.map { |item, offset| [start_index + offset, item] }
        end
      end
    end
  end
end
