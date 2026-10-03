# frozen_string_literal: true

require "dry/schema/path"

module Dry
  module Validation
    # Matched array records and their original indexes
    #
    # @api public
    class Association
      # A pair of records joined by their association keys
      #
      # @api public
      class Match
        # @return [Object]
        attr_reader :left_value, :right_value

        # @return [Integer]
        attr_reader :left_index, :right_index

        # @api private
        def initialize(left_index:, left_value:, right_index:, right_value:)
          @left_index = left_index
          @left_value = left_value
          @right_index = right_index
          @right_value = right_value
        end
      end

      # @return [Array<Match>]
      attr_reader :matches

      # @return [Array<(Integer, Object)>]
      attr_reader :left_records, :right_records

      # @api private
      def initialize(
        left:, right:, left_key:, right_key:,
        left_path: EMPTY_ARRAY, right_path: EMPTY_ARRAY, result: nil
      )
        @left_path = Schema::Path[left_path].to_a
        @right_path = Schema::Path[right_path].to_a
        @left_key = left_key
        @right_key = right_key
        @left_records = valid_records(left, @left_path, left_key, result)
        @right_records = valid_records(right, @right_path, right_key, result)
        @matches = build_matches
      end

      # Return left records grouped with every matching right record
      #
      # @return [Array<Hash>]
      #
      # @api public
      def groups
        left_records.map do |left_index, left_value|
          group_matches = matches.select { |match| match.left_index == left_index }

          {
            left_index: left_index,
            left_value: left_value,
            right_indexes: group_matches.map(&:right_index),
            right_values: group_matches.map(&:right_value),
            matches: group_matches
          }
        end
      end

      # Return records from the left array without a matching right record
      #
      # @return [Array<(Integer, Object)>]
      #
      # @api public
      def unmatched_left
        matched_left = matches.map(&:left_index).uniq
        left_records.reject { |index,| matched_left.include?(index) }
      end

      # Return records from the right array without a matching left record
      #
      # @return [Array<(Integer, Object)>]
      #
      # @api public
      def unmatched_right
        matched_right = matches.map(&:right_index).uniq
        right_records.reject { |index,| matched_right.include?(index) }
      end

      private

      def build_matches
        left_records.product(right_records).filter_map do |(left_index, left_value), (right_index, right_value)|
          next unless association_key(left_value, :@left_key) == association_key(right_value, :@right_key)

          Match.new(
            left_index: left_index,
            left_value: left_value,
            right_index: right_index,
            right_value: right_value
          )
        end
      end

      def valid_records(array, path, key, result)
        return [] unless array.is_a?(::Array)

        array.each_with_index.filter_map do |value, index|
          next unless value.is_a?(::Hash)
          next if result&.schema_error?([*path, index, *Schema::Path[key].to_a])

          [index, value]
        end
      end

      def association_key(value, key_ivar)
        key = instance_variable_get(key_ivar)
        fetch_value(value, Schema::Path[key].to_a)
      end

      def fetch_value(value, path)
        path.reduce(value) do |current, key|
          return unless current.respond_to?(:dig)

          current[key]
        end
      end
    end
  end
end
