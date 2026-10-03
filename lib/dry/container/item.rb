# frozen_string_literal: true

module Dry
  class Container
    # Base class to abstract Memoizable and Callable implementations
    #
    # @api abstract
    #
    class Item
      EMPTY_TAGS = [].freeze

      # @return [Mixed] the item to be solved later
      attr_reader :item

      # @return [Hash] the options to memoize, call or no.
      attr_reader :options

      # @api abstract
      def initialize(item, options = {})
        @item = item
        @options = {
          call: item.is_a?(::Proc) && item.parameters.empty?,
          tags: EMPTY_TAGS,
          priority: 0,
          sequence: 0
        }.merge(options)
      end

      # @api abstract
      def call
        raise NotImplementedError
      end

      # @private
      def value?
        !callable?
      end

      # @private
      def callable?
        options[:call]
      end

      # @return [Array<String>] tags the item is bound to
      #
      # @api public
      def tags
        options[:tags]
      end

      # @return [Integer] resolution priority (smaller values are resolved first)
      #
      # @api public
      def priority
        options[:priority]
      end

      # @return [Integer] registration sequence used as a tie-breaker
      #
      # @api public
      def sequence
        options[:sequence]
      end

      # @return [Boolean] whether the item is bound to the given tag
      #
      # @api public
      def tagged?(tag)
        tags.include?(tag.to_s)
      end

      # Build a new item with transformation applied
      #
      # @private
      def map(func)
        if callable?
          self.class.new(-> { func.(item.call) }, options)
        else
          self.class.new(func.(item), options)
        end
      end
    end
  end
end
