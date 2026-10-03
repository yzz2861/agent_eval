# frozen_string_literal: true

require "dry/container/item/memoizable"
require "dry/container/item/callable"

module Dry
  class Container
    class Item
      # Factory for create an Item to register inside of container
      #
      # @api public
      class Factory
        # Creates an Item Memoizable or Callable
        # @param [Mixed] item
        # @param [Hash] options
        #
        # @raise [Dry::Container::Error]
        #
        # @return [Dry::Container::Item::Base]
        def call(item, options = {})
          options = normalize_options(item, options)
          options[:memoize] ? Memoizable.new(item, options) : Callable.new(item, options)
        end

        private

        # A memoized factory that declares a parameter is resolved with the
        # container that is resolving it, so it can depend on sibling keys
        def normalize_options(item, options)
          if options[:memoize] && Item.accepts_container?(item)
            options.merge(call: true)
          else
            options
          end
        end
      end
    end
  end
end
