# frozen_string_literal: true

require "dry/container/item"

module Dry
  class Container
    class Item
      # Memoizable class to store and execute item calls
      #
      # @api public
      #
      class Memoizable < Item
        # @return [Mutex] the stored mutex
        attr_reader :memoize_mutex

        # Returns a new Memoizable instance
        #
        # @param [Mixed] item
        # @param [Hash] options
        #
        # @raise [Dry::Container::Error]
        #
        # @return [Dry::Container::Item::Base]
        def initialize(item, options = {})
          super
          raise_not_supported_error unless callable?

          @memoize_mutex = ::Mutex.new
        end

        # Build a fresh, unresolved copy so a forked container keeps the
        # factory definition but has its own cache and initialization lock
        #
        # @return [Dry::Container::Item::Memoizable]
        #
        # @api private
        def fork
          self.class.new(item, options)
        end

        # Returns the result of item call using a syncronized mutex
        #
        # @param [Dry::Container::Mixin] container
        #   The container that is resolving the item
        #
        # @return [Dry::Container::Item::Base]
        def call(container = nil)
          memoize_mutex.synchronize do
            @memoized_item ||= call_item(container)
          end
        end

        # Whether the registered item should be given the resolving container
        #
        # @return [Bool]
        #
        # @private
        def containerized?
          Item.accepts_container?(item)
        end

        private

        # @private
        def raise_not_supported_error
          raise ::Dry::Container::Error, "Memoize only supported for a block or a proc"
        end
      end
    end
  end
end
