# frozen_string_literal: true

require "dry/container/item/alias"

module Dry
  class Container
    # Default resolver for resolving items from container
    #
    # @api public
    class Resolver
      # Resolve an item from the container
      #
      # @param [Concurrent::Hash] container
      #   The container
      # @param [Mixed] key
      #   The key for the item you wish to resolve
      # @yield
      #   Fallback block to call when a key is missing. Its result will be returned
      # @yieldparam [Mixed] key Missing key
      #
      # @raise [KeyError]
      #   If the given key is not registered with the container (and no block provided)
      #
      #
      # @return [Mixed]
      #
      # @api public
      def call(container, key, stubs: nil, &block)
        resolve_alias(container, key.to_s, [], stubs, &block)
      end

      private def resolve_alias(container, key, chain, stubs, &block)
        key = key.to_s
        requested_key = chain.first || key

        return stubs[key] if stubs&.key?(key)

        if chain.include?(key)
          cycle = chain + [key]
          raise Error, "circular alias dependency detected: #{cycle.join(" -> ")}"
        end

        item = container.fetch(key) do
          if block_given?
            return yield(requested_key)
          else
            raise KeyError.new(
                    %(key not found: "#{requested_key}"),
                    key: requested_key,
                    receiver: container
                  )
          end
        end

        if item.is_a?(Item::Alias)
          value = resolve_alias(
            container,
            item.target,
            chain + [key],
            stubs,
            &block
          )

          item.decorators.reduce(value) { |result, decorator| decorator.call(result) }
        else
          item.call
        end
      end

      # Check whether an items is registered under the given key
      #
      # @param [Concurrent::Hash] container
      #   The container
      # @param [Mixed] key
      #   The key you wish to check for registration with
      #
      # @return [Bool]
      #
      # @api public
      def key?(container, key)
        container.key?(key.to_s)
      end

      # An array of registered names for the container
      #
      # @return [Array]
      #
      # @api public
      def keys(container)
        container.keys
      end

      # Calls block once for each key in container, passing the key as a parameter.
      #
      # If no block is given, an enumerator is returned instead.
      #
      # @return Hash
      #
      # @api public
      def each_key(container, &block)
        container.each_key(&block)
      end

      # Calls block once for each key in container, passing the key and
      # the registered item parameters.
      #
      # If no block is given, an enumerator is returned instead.
      #
      # @return Key, Value
      #
      # @api public
      # @note In discussions with other developers, it was felt that being able
      #       to iterate over not just the registered keys, but to see what was
      #       registered would be very helpful. This is a step toward doing that.
      def each(container, &block)
        container.map { |key, value|
          value = value.is_a?(Item::Alias) ? call(container, key) : value.call
          [key, value]
        }.each(&block)
      end
    end
  end
end
