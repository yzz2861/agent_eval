# frozen_string_literal: true

module Dry
  module Validation
    module Macros
      # Detects overlapping time intervals grouped by a resource key
      #
      # Records are grouped and sorted by their start endpoint, so finding all
      # conflicts takes O(n log n) comparisons per group instead of the O(n^2)
      # of checking every pair of records.
      #
      # @api public
      class NonOverlappingIntervals
        # Endpoint presets mapping to a [left_open, right_open] pair
        #
        # @return [Hash{Symbol, String => Array<Boolean>}]
        #
        # @api public
        ENDPOINTS = {
          "[]" => [false, false],
          "[)" => [false, true],
          "(]" => [true, false],
          "()" => [true, true],
          :"[]" => [false, false],
          :"[)" => [false, true],
          :"(]" => [true, false],
          :"()" => [true, true],
          :closed_open => [false, true],
          :open => [true, true],
          :closed => [false, false]
        }.freeze

        DEFAULT_MESSAGE = "overlaps with another record"

        # @!attribute [r] group_key
        #   @return [Symbol, String]
        # @!attribute [r] start_key
        #   @return [Symbol, String]
        # @!attribute [r] end_key
        #   @return [Symbol, String]
        attr_reader :group_key, :start_key, :end_key

        # @!attribute [r] left_open
        #   @return [Boolean] Whether the start endpoint is excluded
        # @!attribute [r] right_open
        #   @return [Boolean] Whether the finish endpoint is excluded
        attr_reader :left_open, :right_open

        # @!attribute [r] message
        #   @return [String]
        attr_reader :message

        # @param group_key [Symbol, String] Key identifying the resource
        # @param start_key [Symbol, String] Key of the interval start field
        # @param end_key [Symbol, String] Key of the interval finish field
        # @param endpoints [Symbol, String] Endpoint preset, see {ENDPOINTS}
        # @param left_open [Boolean, nil] Override the start endpoint openness
        # @param right_open [Boolean, nil] Override the finish endpoint openness
        # @param message [String, nil] Failure message
        #
        # @api public
        def initialize(group_key:, start_key:, end_key:, endpoints: "[]",
                       left_open: nil, right_open: nil, message: nil)
          @group_key = group_key
          @start_key = start_key
          @end_key = end_key

          preset = ENDPOINTS.fetch(endpoints) do
            raise ArgumentError,
                  "+endpoints+ must be one of #{ENDPOINTS.keys.map(&:inspect).join(", ")} " \
                  "(#{endpoints.inspect} given)"
          end

          @left_open = left_open.nil? ? preset.fetch(0) : left_open
          @right_open = right_open.nil? ? preset.fetch(1) : right_open
          @message = message || DEFAULT_MESSAGE
        end

        # Return the sorted pairs of original indices of conflicting records
        #
        # Records whose group, start or finish fields are missing, whose start
        # or finish value failed schema checks, or whose interval is empty are
        # skipped and never participate in relation checks.
        #
        # @param records [Array<Hash>] Schema-coerced records
        # @param schema_error [#call] Callable receiving a field path and
        #   returning whether the field has a schema error
        # @param path_prefix [Array] Prefix for error paths (e.g. [:bookings])
        #
        # @return [Array<Array(Integer, Integer)>]
        #
        # @api public
        def call(records, schema_error, path_prefix = EMPTY_ARRAY)
          entries = collect_entries(records, schema_error, path_prefix)

          entries.group_by { |entry| entry[:group] }.values.flat_map do |group|
            conflicts_in_group(group)
          end
        end

        private

        # @api private
        def collect_entries(records, schema_error, path_prefix)
          records.each_with_index.each_with_object([]) do |(record, index), entries|
            next unless record.is_a?(::Hash)

            next if field_error?(record, index, schema_error, path_prefix)
            next unless complete?(record)

            start_value = record[start_key]
            end_value = record[end_key]

            next if start_value.nil? || end_value.nil?
            next unless comparable?(start_value, end_value)
            # Empty intervals (and inverted ranges) never overlap anything
            next if empty_interval?(start_value, end_value)

            entries << {
              index: index,
              group: record[group_key],
              start: start_value,
              finish: end_value
            }
          end
        end

        # @api private
        def field_error?(record, index, schema_error, path_prefix)
          [group_key, start_key, end_key].any? do |field|
            path = [*path_prefix, index, *::Dry::Schema::Path[field].to_a]
            schema_error.call(path)
          end
        end

        # @api private
        def complete?(record)
          record.key?(group_key) &&
            record.key?(start_key) &&
            record.key?(end_key)
        end

        # @api private
        def comparable?(start_value, end_value)
          !start_value.<=>(end_value).nil?
        rescue StandardError
          false
        end

        # An interval is empty whenever start > finish, and also when start ==
        # finish unless both of that record's endpoints are closed.
        #
        # @api private
        def empty_interval?(start_value, end_value)
          return true if start_value > end_value
          return left_open || right_open if start_value == end_value

          false
        end

        # Sweep the sorted group while maintaining the active intervals (those
        # that started no later than the current one and have not ended). Every
        # still-active interval overlaps the current one in at least one point.
        #
        # The active set stays sorted by its finish endpoint, so inserting,
        # expiring and reading it is logarithmic; the whole sweep is
        # O(n log n) without comparing every pair of records.
        #
        # @api private
        def conflicts_in_group(group)
          ordered = group.sort_by { |entry| [entry[:start], entry[:index]] }
          conflicts = []
          active = []

          ordered.each do |entry|
            expire(active, entry[:start])

            active.each do |other|
              if overlap?(other, entry)
                conflicts << [other[:index], entry[:index]].sort
              end
            end

            insert_active(active, entry)
          end

          conflicts
        end

        # Drop an active interval once its finish is strictly before the next
        # start. When the finish equals the start the intervals merely touch;
        # they remain active so {#overlap?} can apply the endpoint rules.
        #
        # @api private
        def expire(active, start_value)
          active.shift while active.any? && active.first[:finish] < start_value
        end

        # Insert while preserving finish order, then start order on ties.
        #
        # @api private
        def insert_active(active, entry)
          key = [entry[:finish], entry[:start], entry[:index]]
          position = active.bsearch_index do |other|
            ([other[:finish], other[:start], other[:index]] <=> key) == 1
          end || active.size
          active.insert(position, entry)
        end

        # Both entries are active at this point, so their interiors either
        # intersect or the intervals merely touch at an endpoint. A shared
        # point counts as overlap only when both sides that meet there are
        # closed: the earlier interval's finish (right side) and the later
        # interval's start (left side).
        #
        # @api private
        def overlap?(other, entry)
          if other[:finish] == entry[:start]
            # other contributes its right side, entry its left side
            !right_open && !left_open
          else
            true
          end
        end
      end
    end
  end
end
