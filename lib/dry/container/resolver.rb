# frozen_string_literal: true

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
      def call(container, key)
        item = container.fetch(key.to_s) do
          if block_given?
            return yield(key)
          else
            raise KeyError.new(%(key not found: "#{key}"), key: key.to_s, receiver: container)
          end
        end

        item.call
      end

      # Return key/item pairs bound to the given tag, ordered by priority and
      # then by registration sequence. Item factories are never called.
      #
      # @param [Concurrent::Hash] container
      #   The container
      # @param [Mixed] tag
      #   The tag to look up
      # @param [String, nil] prefix
      #   Optional key prefix used to scope the lookup to a namespace
      #
      # @return [Array<Array(String, Dry::Container::Item)>]
      #
      # @api public
      def tagged_entries(container, tag, prefix: nil)
        tag = tag.to_s

        entries = container.each_with_index.filter_map do |(key, item), position|
          next unless item.respond_to?(:tagged?) && item.tagged?(tag)
          next if prefix && !key.start_with?(prefix)

          [key, item, position]
        end

        entries.sort_by! { |_key, item, position| [item.priority, item.sequence, position] }
        entries.map { |key, item, _position| [key, item] }
      end

      # Return the keys bound to the given tag, ordered by priority and then
      # by registration sequence. Item factories are never called.
      #
      # @param [Concurrent::Hash] container
      #   The container
      # @param [Mixed] tag
      #   The tag to look up
      # @param [String, nil] prefix
      #   Optional key prefix used to scope the lookup to a namespace
      #
      # @return [Array<String>]
      #
      # @api public
      def tagged_keys(container, tag, prefix: nil)
        tagged_entries(container, tag, prefix: prefix).map(&:first)
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
        container.map { |key, value| [key, value.call] }.each(&block)
      end
    end
  end
end
