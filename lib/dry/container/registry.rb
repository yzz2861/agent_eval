# frozen_string_literal: true

require "dry/container/item/factory"

module Dry
  class Container
    # Default registry for registering items with the container
    #
    # @api public
    class Registry
      # @private
      def initialize
        @_mutex = ::Mutex.new
      end

      # Register an item with the container to be resolved later
      #
      # @param [Concurrent::Hash] container
      #   The container
      # @param [Mixed] key
      #   The key to register the container item with (used to resolve)
      # @param [Mixed] item
      #   The item to register with the container
      # @param [Hash] options
      # @option options [Symbol] :call
      #   Whether the item should be called when resolved
      # @option options [Symbol, String, Array<Symbol, String>] :tags
      #   One or several tags the item should be bound to
      # @option options [Symbol, String] :tag
      #   A single tag the item should be bound to (alias of `:tags`)
      # @option options [Integer] :priority
      #   Resolution order within a tag, smaller values are resolved first (defaults to 0)
      #
      # @raise [Dry::Container::Error]
      #   If an item is already registered with the given key
      #
      # @return [Mixed]
      #
      # @api public
      def call(container, key, item, options)
        key = key.to_s.dup.freeze
        options = normalize_options(options)
        @_mutex.synchronize do
          if container.key?(key)
            raise Error, "There is already an item registered with the key #{key.inspect}"
          end

          options[:sequence] = next_sequence(container)
          container[key] = factory.call(item, options)
        end
      end

      def factory
        @factory ||= ::Dry::Container::Item::Factory.new
      end

      private

      # @api private
      def normalize_options(options)
        options = options.dup
        tags = options.fetch(:tags) { options[:tag] }
        options[:tags] = Array(tags).flatten.map { |tag| tag.to_s.dup.freeze }.freeze
        options.delete(:tag)
        options[:priority] ||= 0
        options
      end

      # @api private
      def next_sequence(container)
        container.each_value.map(&:sequence).max.to_i + 1
      end
    end
  end
end
