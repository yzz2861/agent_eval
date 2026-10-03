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
        # @param [Dry::Container::Mixin] container
        #   The container that is resolving the item
        #
        # @return [Mixed]
        def call(container = nil)
          callable? ? call_item(container) : item
        end

        # @private
        def containerized?
          callable? && Item.accepts_container?(item)
        end
      end
    end
  end
end
