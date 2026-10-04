# frozen_string_literal: true
require "digest"
require "graphql/pagination/connection"

module GraphQL
  module Pagination
    # Merge several independently sorted, independently readable data sources
    # into one forward-only connection.
    #
    # Each page is recoverable from its cursor alone. Sources are therefore
    # called with the source-local cursor from the merged cursor; no source IO
    # or iterator is retained between connection instances.
    class MergedConnection < Pagination::Connection
      # Raised when a cursor cannot be used by the connection which received it.
      class InvalidCursorError < GraphQL::ExecutionError
      end

      # Raised when sources or their ordering do not satisfy this connection.
      class SourceError < GraphQL::Error
      end

      # Describes one pre-sorted source participating in the merge.
      class Source
        # @return [String, Symbol] A stable identifier, persisted in merged cursors.
        attr_reader :id

        # @param id [String, Symbol] A stable identifier, persisted in merged cursors.
        # @param identity [#call] Returns a value that is unique within this source.
        # @param cursor_for [#call] Returns the source-local cursor for a node.
        # @param read_batch [#call] Reads up to `limit` nodes after a source-local cursor.
        #   Returning fewer than `limit` nodes means the source is exhausted.
        def initialize(id, identity: nil, node_id: identity, cursor_for: nil, read_batch: nil, &read_batch_block)
          @id = id
          @node_id_callback = node_id
          @cursor_for_callback = cursor_for
          @read_batch = read_batch || read_batch_block
        end

        # Override this when subclassing instead of passing callbacks.
        # @return [Object] A value that uniquely identifies `node` in this source.
        def node_id(node)
          call_or_raise(@node_id_callback, node, :node_id)
        end

        # Override this when subclassing instead of passing callbacks.
        # @return [Object, nil] The opaque JSON-serializable source-local cursor for `node`.
        def cursor_for(node)
          return node_id(node).to_s if @cursor_for_callback.nil?
          @cursor_for_callback.call(node)
        end

        # Override this when subclassing instead of passing callbacks.
        #
        # @param after [Object, nil] The cursor of the last node already consumed.
        # @param limit [Integer] The maximum number of nodes to return.
        # @param context [GraphQL::Query::Context, nil] The query context.
        # @return [Array<Object>] Nodes sorted in the order declared by the merged connection.
        def read_batch(after:, limit:, context:)
          if @read_batch.nil?
            raise SourceError, "#{self.class}#read_batch(after:, limit:, context:) must be implemented"
          end
          @read_batch.call(after: after, limit: limit, context: context)
        end

        private

        def call_or_raise(callback, node, method_name)
          if callback.nil?
            raise SourceError, "#{self.class}##{method_name}(node) must be implemented"
          end
          callback.call(node)
        end
      end

      Entry = Struct.new(:node, :source_id, :sort_rank, :source_cursor, :merged_progress) # :nodoc:

      # @param sources [Array<Source>] The sorted sources included in this connection.
      # @param comparison_key [#call, Symbol] Returns the caller-defined key used to compare nodes.
      # @param direction [Symbol] `:asc` (the default) or `:desc`.
      # @param sort_definition [Object] A JSON-serializable value embedded in the cursor binding.
      # @param read_batch_size [Integer] The number of nodes requested from one source at a time.
      def initialize(
        sources,
        *,
        comparison_key: nil,
        direction: :asc,
        sort_definition: nil,
        read_batch_size: 1,
        **options
      )
        super(sources, **options)
        @comparison_key = comparison_key
        @direction = direction
        @sort_definition = sort_definition
        @read_batch_size = read_batch_size
        validate_configuration
      end

      def nodes
        load_page
        @nodes
      end

      def has_next_page
        load_page
        @has_next_page
      end

      def has_previous_page
        load_page
        @has_previous_page
      end

      def cursor_for(item)
        load_page
        entry = entry_for(item)
        encode(serialize_cursor(entry.merged_progress))
      end

      def start_cursor
        load_page
        cursor_for_entry(@entries.first)
      end

      def end_cursor
        load_page
        cursor_for_entry(@entries.last)
      end

      private

      def comparison_key_for(node)
        if @comparison_key.is_a?(Symbol)
          node.public_send(@comparison_key)
        elsif @comparison_key.respond_to?(:call)
          @comparison_key.call(node)
        else
          raise SourceError, "comparison_key must be a Symbol or callable"
        end
      end

      def read_batch_size
        @read_batch_size
      end

      def json_primitive?(value)
        value.nil? ||
          value.is_a?(String) ||
          value.is_a?(Numeric) ||
          value == true ||
          value == false ||
          (value.is_a?(Array) && value.all? { |item| json_primitive?(item) }) ||
          (value.is_a?(Hash) && value.all? { |key, item| key.is_a?(String) && json_primitive?(item) })
      end

      def validate_configuration
        unless @comparison_key.is_a?(Symbol) || @comparison_key.respond_to?(:call)
          raise SourceError, "comparison_key must be a Symbol or callable"
        end

        unless @comparison_key.is_a?(Symbol) || !@sort_definition.nil?
          raise SourceError, "sort_definition: is required when comparison_key is callable"
        end

        unless %i[asc desc].include?(@direction)
          raise SourceError, "direction must be :asc or :desc, but was #{@direction.inspect}"
        end

        unless read_batch_size.is_a?(Integer) && read_batch_size.positive?
          raise SourceError, "read_batch_size must be a positive Integer"
        end

        unless @sort_definition.nil? || json_primitive?(@sort_definition)
          raise SourceError, "sort_definition must be JSON-serializable"
        end

        if items.empty?
          raise SourceError, "at least one source is required"
        end

        items.each do |source|
          unless source.respond_to?(:read_batch) && source.respond_to?(:node_id) && source.respond_to?(:cursor_for)
            raise SourceError, "source #{source.inspect} must respond to read_batch, node_id, and cursor_for"
          end
        end

        ids = items.map { |source| source.id.to_s }
        duplicates = ids.select { |id| ids.count(id) > 1 }.uniq
        unless duplicates.empty?
          raise SourceError, "source ids must be unique: #{duplicates.join(", ")}"
        end
      end

      def load_page
        return if defined?(@nodes)

        reject_reverse_pagination!
        @progress = decoded_progress
        states = build_states
        @entries = []
        needed = first

        while needed.nil? || @entries.length < needed
          entry = next_entry(states)
          break if entry.nil?
          @entries << entry
        end

        unless states.any?(&:buffered?)
          fill_states(states)
        end
        @has_next_page = states.any?(&:buffered?)
        @nodes = @entries.map(&:node)
        @has_previous_page = !after.nil?
      end

      def reject_reverse_pagination!
        unsupported = []
        unsupported << "last" unless last_value.nil?
        unsupported << "before" unless before.nil?
        unless unsupported.empty?
          verb = unsupported.length == 1 ? "is" : "are"
          message = "MergedConnection only supports forward pagination; " \
            "#{unsupported.join(" and ")} #{verb} not supported"
          raise GraphQL::ExecutionError, message
        end
      end

      def next_entry(states)
        fill_states(states)
        candidate_states = states.select(&:buffered?)

        winning_state = candidate_states.min_by(&:front_rank)
        return nil if winning_state.nil?

        entry = winning_state.shift
        entry.merged_progress = progress_after(states, entry)
        @progress = entry.merged_progress
        entry
      end

      def build_states
        states = items.map do |source|
          source_id = source.id.to_s
          SourceState.new(
            source,
            source_id,
            @progress.fetch(source_id),
            self,
          )
        end
        states
      end

      def entry_for(item)
        entry = @entries.find { |candidate| candidate.node.equal?(item) }
        if entry.nil?
          raise SourceError, "#{item.inspect} is not a node on the current page"
        end
        entry
      end

      def cursor_for_entry(entry)
        return nil if entry.nil?
        encode(serialize_cursor(entry.merged_progress))
      end

      def decoded_progress
        return initial_progress if after.nil?

        cursor = JSON.parse(decode(after))
        unless cursor.is_a?(Hash) && cursor["v"] == 1
          raise InvalidCursorError, "Invalid cursor: #{after.inspect}"
        end

        unless cursor["sources"] == source_binding
          raise InvalidCursorError, "Cursor was created for a different set of sources"
        end

        unless cursor["sort"] == sort_binding
          raise InvalidCursorError, "Cursor was created with a different sort definition"
        end

        progress = cursor["progress"]
        valid_progress = progress.is_a?(Hash) &&
          progress.keys.sort == source_binding.sort &&
          progress.values.all? do |value|
            value.is_a?(Hash) &&
              json_primitive?(value["cursor"]) &&
              (value["exhausted"] == true || value["exhausted"] == false)
          end
        unless valid_progress
          raise InvalidCursorError, "Invalid cursor: #{after.inspect}"
        end

        progress.each_with_object({}) do |(source_id, value), normalized|
          normalized[source_id] = { "cursor" => value["cursor"], "exhausted" => value["exhausted"] }
        end
      rescue JSON::ParserError
        raise InvalidCursorError, "Invalid cursor: #{after.inspect}"
      end

      def initial_progress
        @initial_progress ||= source_binding.each_with_object({}) do |source_id, progress|
          progress[source_id] = { "cursor" => nil, "exhausted" => false }
        end
      end

      def source_binding
        @source_binding ||= items.map { |source| source.id.to_s }.sort
      end

      def sort_binding
        @sort_binding ||= begin
          key_definition = @sort_definition || @comparison_key.to_s
          serialized = JSON.generate("key" => key_definition, "direction" => @direction.to_s)
          Digest::SHA256.hexdigest(serialized)[0, 32]
        end
      end

      def serialize_cursor(progress)
        JSON.generate(
          "v" => 1,
          "sources" => source_binding,
          "sort" => sort_binding,
          "progress" => progress,
        )
      end

      def fill_states(states)
        states.each do |item_state|
          item_state.fill if item_state.fillable?
        end
      end

      def progress_after(states, entry)
        progress = states.each_with_object({}) do |item_state, copied|
          copied[item_state.source_id] = item_state.progress.dup
        end
        progress[entry.source_id] = {
          "cursor" => entry.source_cursor,
          "exhausted" => states.find { |item_state| item_state.source_id == entry.source_id }.all_consumed?,
        }
        progress
      end

      class SourceState # :nodoc:
        attr_reader :front_rank, :source_id

        def initialize(source, source_id, after_cursor, connection)
          @source = source
          @source_id = source_id
          @after_cursor = after_cursor
          @connection = connection
          @buffer = []
          @may_have_more = !(after_cursor.is_a?(Hash) && after_cursor["exhausted"] == true)
          @after_cursor = after_cursor.is_a?(Hash) ? after_cursor["cursor"] : after_cursor
          @consumed_cursor = @after_cursor
          @front_rank = nil
          @seen_ids = {}
        end

        def fill
          refill if fillable?
        end

        def fillable?
          @buffer.empty? && @may_have_more
        end

        def buffered?
          !@buffer.empty?
        end

        def all_consumed?
          !@may_have_more && @buffer.empty?
        end

        def progress
          { "cursor" => @consumed_cursor, "exhausted" => all_consumed? }
        end

        def shift
          entry = @buffer.shift
          @front_rank = @buffer.first&.sort_rank
          @consumed_cursor = entry.source_cursor
          entry
        end

        private

        def refill
          limit = @connection.send(:read_batch_size)
          nodes = @source.read_batch(after: @after_cursor, limit: limit, context: @connection.context)
          unless nodes.is_a?(Array)
            raise SourceError, "source #{@source_id.inspect} read_batch must return an Array"
          end

          nodes.each_with_index do |node, index|
            add_node(node, first_in_batch: index.zero?)
          end
          @may_have_more = nodes.length == limit
        end

        def add_node(node, first_in_batch:)
          source_node_id = @source.node_id(node)
          source_id_value = source_node_id.to_s
          if @seen_ids.key?(source_id_value)
            message = "source #{@source_id.inspect} returned duplicate node identity #{source_id_value.inspect}"
            raise SourceError, message
          end

          sort_key = @connection.send(:comparison_key_for, node)
          sort_rank = @connection.send(:sort_rank, sort_key, @source_id, source_node_id)
          previous_rank = first_in_batch ? @previous_rank : @buffer.last&.sort_rank
          if previous_rank && (previous_rank <=> sort_rank) == 1
            raise SourceError, "source #{@source_id.inspect} returned nodes out of order"
          end

          @seen_ids[source_id_value] = true
          source_cursor = @source.cursor_for(node)
          unless @connection.send(:json_primitive?, source_cursor)
            raise SourceError, "source #{@source_id.inspect} cursor_for must return a JSON-serializable value"
          end
          entry = Entry.new(node, @source_id, sort_rank, source_cursor, nil)
          @buffer << entry
          @front_rank ||= sort_rank
          @after_cursor = source_cursor
          @previous_rank = sort_rank
        end
      end

      def sort_rank(key, source_id, source_node_id)
        sort_values = key.is_a?(Array) ? key : [key]
        direction_rank = sort_values.map { |value| value_rank(ComparableValue.new(value)) }
        [
          direction_rank,
          [source_id, source_node_id.to_s],
        ]
      end

      def value_rank(value)
        @direction == :desc ? ReverseValue.new(value) : value
      end

      class ComparableValue # :nodoc:
        include Comparable

        def initialize(value)
          @value = value
        end

        def <=>(other)
          other_value = other.is_a?(ComparableValue) ? other.instance_variable_get(:@value) : other
          @value <=> other_value
        end
      end

      class ReverseValue < ComparableValue # :nodoc:
        def <=>(other)
          other_value = other.is_a?(ComparableValue) ? other.instance_variable_get(:@value) : other
          comparison = @value <=> other_value
          return nil if comparison.nil?
          -comparison
        end
      end
      private_constant :ComparableValue, :ReverseValue
    end
  end
end
