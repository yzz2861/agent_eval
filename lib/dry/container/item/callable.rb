# frozen_string_literal: true

require "dry/container/item"

module Dry
  class Container
    class Item
      # Callable class to returns a item call
      #
      # @api public
      #
      class Callable < Item
        # Returns the result of item call or item
        #
        # @param [Dry::Container::Mixin, nil] container
        #   The container performing the resolution, passed to factories
        #   that declare a single positional parameter
        #
        # @return [Mixed]
        def call(container = nil)
          callable? ? invoke(item, container) : item
        end

        # @private
        def map(func)
          if callable?
            Item::DecoratedCall.new(item, func, options.merge(call: true))
          else
            super
          end
        end
      end
    end
  end
end
