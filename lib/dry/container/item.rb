# frozen_string_literal: true

module Dry
  class Container
    # Base class to abstract Memoizable and Callable implementations
    #
    # @api abstract
    #
    class Item
      # @return [Mixed] the item to be solved later
      attr_reader :item

      # @return [Hash] the options to memoize, call or no.
      attr_reader :options

      # @api abstract
      def initialize(item, options = {})
        @item = item
        @options = {
          call: item.is_a?(::Proc) && item.parameters.empty?
        }.merge(options)
      end

      # @api abstract
      def call
        raise NotImplementedError
      end

      # Build a copy with an empty instance cache when memoized
      #
      # Plain values and non-memoized factories are shared by reference
      #
      # @return [Dry::Container::Item]
      #
      # @api private
      def fork
        self
      end

      # @private
      def value?
        !callable?
      end

      # @private
      def callable?
        options[:call]
      end

      # Whether the registered item should be given the resolving container
      #
      # @return [Bool]
      #
      # @private
      def containerized?
        false
      end

      # Build a new item with transformation applied
      #
      # @private
      def map(func)
        if callable?
          if containerized?
            self.class.new(->(container) { func.(call_item(container)) }, options)
          else
            self.class.new(-> { func.(call_item(nil)) }, options)
          end
        else
          self.class.new(func.(item), options)
        end
      end

      # Whether the proc declares a positional parameter (besides a splat)
      #
      # @return [Bool]
      #
      # @private
      def self.accepts_container?(item)
        item.is_a?(::Proc) &&
          item.parameters.any? { |type,| type == :req || type == :opt }
      end

      # Invoke the wrapped factory, passing the resolving container when it
      # asks for it
      #
      # @private
      def call_item(container)
        if containerized?
          item.call(container)
        else
          item.call
        end
      end
    end
  end
end
