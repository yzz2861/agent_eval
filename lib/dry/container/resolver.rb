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

      # Resolve all items registered with the given tag
      #
      # The set of keys is snapshotted before any item is resolved, so items
      # registered while resolving (e.g. by a factory) are not part of this
      # round. Items are sorted by their :order option, then by registration
      # order.
      #
      # @param [Concurrent::Hash] container
      #   The container
      # @param [Mixed] tag
      #   The tag for the items you wish to resolve
      #
      # @raise [Dry::Container::Error]
      #   If resolving an item fails, naming the offending key
      #
      # @return [Array]
      #
      # @api public
      def resolve_all(container, tag)
        keys_for(container, tag).map do |key|
          container.fetch(key).call
        rescue ::StandardError => e
          raise ::Dry::Container::Error,
                "Failed to resolve #{key.inspect} (tagged #{tag.inspect}): #{e.message}"
        end
      end

      # An array of keys registered with the given tag, in resolution order
      #
      # This only inspects registration metadata and never resolves (calls)
      # the registered items.
      #
      # @param [Concurrent::Hash] container
      #   The container
      # @param [Mixed] tag
      #   The tag you wish to list keys for
      #
      # @return [Array<String>]
      #
      # @api public
      def keys_for(container, tag)
        tag = tag.to_s

        container.each_with_object([]) do |(key, item), entries|
          options = item.respond_to?(:options) ? item.options : {}
          tags = options[:tags]
          next unless tags && Array(tags).any? { |t| t.to_s == tag }

          entries << [key, options.fetch(:order, 0), options.fetch(:sequence, 0)]
        end.sort_by { |key, order, sequence| [order, sequence, key] }.map(&:first)
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
