# frozen_string_literal: true

module Dry
  class Container
    # A read-only facade that exposes only an explicit set of container keys
    #
    # Create a view through {Dry::Container::Mixin#read_only_view}. Every read
    # entry point on the view, including {#[]}, uses the same authorization
    # check. A key outside the configured scope and a key that does not exist
    # are indistinguishable: {#key?} returns false and {#resolve} raises the
    # same generic KeyError (or calls the provided fallback block).
    #
    # This object is an interface boundary, not a Ruby sandbox. Resolved
    # objects are not duplicated or frozen. In particular, a registered
    # callable factory that already captured the original container can still
    # use that reference when it is called; restricting the view cannot isolate
    # arbitrary Ruby code running inside that factory.
    #
    # @api public
    class ReadOnlyView
      # @api private
      def initialize(container, keys:, namespaces:, namespace_separator:)
        separator = namespace_separator.to_s
        raise ArgumentError, "namespace separator must not be empty" if separator.empty?

        allowed_keys = Array(keys).map { |key| normalize_grant(key) }.uniq
        namespace_prefixes = Array(namespaces)
          .map { |namespace| namespace_prefix(namespace, separator) }
          .uniq

        if allowed_keys.empty? && namespace_prefixes.empty?
          raise ArgumentError, "a read-only view requires at least one key or namespace"
        end

        visible_key_predicate = lambda do |key|
          allowed_keys.include?(key) ||
            namespace_prefixes.any? { |prefix| key.start_with?(prefix) }
        end
        missing_item = Object.new.freeze

        define_singleton_method(:resolve) do |key, &fallback|
          normalized_key = key.to_s

          item = if visible_key_predicate.call(normalized_key)
                   container.resolve(normalized_key) { missing_item }
                 else
                   missing_item
                 end

          if item.equal?(missing_item)
            if fallback
              fallback.call(key)
            else
              raise KeyError.new(
                %(key not found: "#{key}"),
                key: normalized_key,
                receiver: self
              )
            end
          else
            item
          end
        end

        define_singleton_method(:[]) { |key| resolve(key) }

        define_singleton_method(:key?) do |key|
          visible_key_predicate.call(key.to_s) && container.key?(key.to_s)
        end

        define_singleton_method(:keys) do
          container.keys.select { |key| visible_key_predicate.call(key) }
        end

        define_singleton_method(:each_key) do |block = nil|
          visible_keys = self.keys

          if block
            visible_keys.each(&block)
            self
          else
            visible_keys.to_enum
          end
        end

        define_singleton_method(:each) do |block = nil|
          pairs = self.keys.map { |key| [key, container.resolve(key)] }
          pairs.each(&block)
        end

        freeze
      end

      private

      def normalize_grant(value)
        key = value.to_s
        raise ArgumentError, "keys and namespaces must not be empty" if key.empty?

        key
      end

      def namespace_prefix(namespace, separator)
        name = normalize_grant(namespace)
        name.end_with?(separator) ? name : name + separator
      end
    end
  end
end
