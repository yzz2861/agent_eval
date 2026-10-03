# frozen_string_literal: true

require "dry/initializer"
require "dry/validation/constants"

module Dry
  module Validation
    # Matched and unmatched items from two arrays
    #
    # @api public
    class Association
      extend Dry::Initializer

      Pair = ::Data.define(:key, :left, :right) do
        def left_index
          left.index
        end

        def right_index
          right.index
        end
      end

      Item = ::Data.define(:value, :index)

      # @!attribute [r] left_path
      #   @return [Array<Symbol, Integer>]
      #   @api private
      option :left_path

      # @!attribute [r] right_path
      #   @return [Array<Symbol, Integer>]
      #   @api private
      option :right_path

      # @!attribute [r] left_key
      #   @return [Symbol, #call]
      #   @api private
      option :left_key

      # @!attribute [r] right_key
      #   @return [Symbol, #call]
      #   @api private
      option :right_key

      # @!attribute [r] result
      #   @return [Result]
      #   @api private
      option :result

      # Return one group for every distinct key with items on both sides
      #
      # @return [Array<Hash>]
      #
      # @api public
      def groups
        matched_left.map do |key, left_items|
          {key: key, left: left_items, right: right_indexes.fetch(key)}
        end
      end

      # Return every left/right pair with equal keys
      #
      # @return [Array<Pair>]
      #
      # @api public
      def matches
        groups.flat_map do |group|
          group[:right].product(group[:left]).map do |right, left|
            Pair.new(group[:key], left, right)
          end
        end
      end

      # Return valid left items that are not referenced by the right side
      #
      # @return [Array<Item>]
      #
      # @api public
      def unmatched_left
        valid_left.reject { |item| matched_left.key?(key_for(item.value, left_key)) }
      end

      # Return valid right items that do not have a matching left item
      #
      # @return [Array<Item>]
      #
      # @api public
      def unmatched_right
        valid_right.reject { |item| valid_left_by_key.key?(key_for(item.value, right_key)) }
      end

      # Build an absolute error path for a left item
      #
      # @return [Array<Symbol, Integer>]
      #
      # @api public
      def left_error_path(index, *keys)
        [*left_path, index, *keys]
      end

      # Build an absolute error path for a right item
      #
      # @return [Array<Symbol, Integer>]
      #
      # @api public
      def right_error_path(index, *keys)
        [*right_path, index, *keys]
      end

      private

      def valid_left
        @valid_left ||= valid_items(:left)
      end

      def valid_right
        @valid_right ||= valid_items(:right)
      end

      def valid_left_by_key
        @valid_left_by_key ||= valid_left.group_by { |item| key_for(item.value, left_key) }
      end

      def matched_left
        @matched_left ||= valid_left_by_key.select { |key, _| right_indexes.key?(key) }
      end

      def right_indexes
        @right_indexes ||= valid_right.group_by { |item| key_for(item.value, right_key) }
      end

      def valid_items(side)
        path = public_send("#{side}_path")
        array = result.values[*path]

        return [] unless array.is_a?(::Array)

        array.each_with_index.filter_map do |value, index|
          item_path = [*path, index]
          next if result.schema_error?(item_path)

          Item.new(value, index)
        end
      end

      def key_for(value, key)
        if key.respond_to?(:call)
          key.call(value)
        else
          value[key]
        end
      end
    end
  end
end
