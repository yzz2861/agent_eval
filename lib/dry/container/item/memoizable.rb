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

        # Returns the result of item call using a syncronized mutex
        #
        # @param [Dry::Container::Mixin, nil] container
        #   The container performing the resolution, passed to factories
        #   that declare a single positional parameter
        #
        # @return [Dry::Container::Item::Base]
        def call(container = nil)
          memoize_mutex.synchronize do
            @memoized_item ||= invoke(item, container)
          end
        end

        # Build a copy with a fresh cache and initialization mutex
        #
        # @return [Dry::Container::Item::Memoizable]
        #
        # @private
        def fork
          inner_item = item.is_a?(Item) ? item.fork : item
          self.class.new(inner_item, options.merge(call: true))
        end

        # Memoize the decorated result while keeping the inner chain
        # independently forkable
        #
        # @private
        def map(func)
          inner_item =
            if item.is_a?(Item)
              item.map(func)
            else
              Item::DecoratedCall.new(item, func, options.merge(call: true))
            end

          Memoizable.new(inner_item, options.merge(call: true))
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
