# frozen_string_literal: true

require "dry/system/constants"
require "dry/system/errors"

module Dry
  module System
    # Default importer implementation
    #
    # This is currently configured by default for every System::Container.
    # Importer objects are responsible for importing components from one
    # container to another. This is used in cases where an application is split
    # into multiple sub-systems.
    #
    # @api private
    class Importer
      # @api private
      class Item
        attr_reader :namespace, :container, :import_keys, :borrowed

        def initialize(namespace:, container:, import_keys:, borrowed: false)
          @namespace = namespace
          @container = container
          @import_keys = import_keys
          @borrowed = borrowed
        end

        # Returns true when this import only borrows references to components whose
        # lifecycle is owned by the source container.
        def borrowed?
          @borrowed
        end
      end

      attr_reader :container

      attr_reader :registry

      # @api private
      def initialize(container)
        @container = container
        @registry = {}
      end

      # @api private
      def register(namespace:, container:, keys: nil, borrow: false)
        ns = namespace_key(namespace)

        if borrow
          register_borrowed(namespace: ns, container: container, keys: keys)
        else
          # Two distinct imports cannot share a namespace (ownership would be ambiguous),
          # but local components may intentionally shadow ordinary imports, so only
          # duplicate import namespaces are rejected here.
          raise ImportNamespaceConflictError.new(ns) if registry.key?(ns)

          add_item(ns, namespace: namespace, container: container, import_keys: keys)
        end
      end

      # @api private
      def [](name)
        registry.fetch(namespace_key(name))
      end

      # @api private
      def key?(name)
        registry.key?(namespace_key(name))
      end
      alias_method :namespace?, :key?

      # @api private
      def finalize!
        registry.each { |ns, item| item.borrowed? ? register_borrowed_proxies(item) : import(ns) }
        self
      end

      # @api private
      def import(namespace, keys: Undefined)
        item = self[namespace]

        if item.borrowed?
          register_borrowed_proxies(item)
          return self
        end

        keys = Undefined.default(keys, item.import_keys)

        if keys
          import_keys(item.container, namespace, keys_to_import(keys, item))
        else
          import_all(item.container, namespace)
        end

        self
      end

      # Returns true if any of the registered imports are borrowed references
      #
      # @api private
      def borrowed?(namespace = nil)
        if namespace.nil?
          registry.each_value.any?(&:borrowed?)
        else
          (item = registry[namespace_key(namespace)]) && item.borrowed?
        end
      end

      # Registers proxy entries for all borrowed components in the target container.
      #
      # Safe to call multiple times; existing registrations are left untouched (which also
      # preserves stubbed components).
      #
      # @api private
      def register_borrowed_proxies(item = nil)
        items = item ? [item] : registry.each_value.select(&:borrowed?)

        items.each do |it|
          keys = it.import_keys || it.container.exports || []

          keys.each do |key|
            target_key = [it.namespace, key].compact.join(KEY_SEPARATOR)

            next if container.registered?(target_key)

            register_borrowed_proxy(target_key, source_key: key, source: it.container)
          end
        end

        self
      end

      private

      # Returns nil if given a nil (i.e. root) namespace. Otherwise, converts the namespace to a
      # string.
      #
      # This ensures imported components are found when either symbols or strings to given as the
      # namespace in {Container.import}.
      def namespace_key(namespace)
        return nil if namespace.nil?

        namespace.to_s
      end

      def register_borrowed(namespace:, container:, keys:)
        # Borrowing components into the root namespace would make ownership ambiguous and
        # bypass the explicit namespaced reference, so it is not supported.
        if namespace.nil?
          raise ArgumentError,
            "You must provide a non-nil `as:` namespace when borrowing components"
        end

        check_namespace_conflict!(namespace)

        exports = container.exports

        unless exports.is_a?(Array)
          source_name = container.config.name || container.inspect

          raise ArgumentError,
            "Cannot borrow from #{source_name.inspect}: it declares no " \
            "`config.exports`, so it offers no components for borrowing"
        end

        borrow_keys = keys ? Array(keys).map(&:to_s) : exports

        unknown = borrow_keys - exports

        unless unknown.empty?
          raise ComponentNotExportedError.new(key: unknown.first, source: container)
        end

        item = add_item(namespace, namespace: namespace, container: container,
          import_keys: borrow_keys, borrowed: true)

        # Register the borrowed references immediately so namespace conflicts and key
        # availability are known at configuration time and the target container cannot be
        # used to resolve arbitrary source keys.
        register_borrowed_proxies(item)
      end

      def register_borrowed_proxy(target_key, source_key:, source:)
        # Do not memoize at the target container: the reference must be re-validated
        # against the source container's lifecycle on every resolution so that a shut down
        # source always fails. Sharing of instances remains the responsibility of the
        # source container.
        container.register(target_key, imported: true, borrowed: true) do
          unless source.running?
            raise BorrowedComponentNotAvailableError.new(
              key: source_key,
              source: source,
              status: source.lifecycle_status
            )
          end

          source[source_key]
        end
      end

      def add_item(ns, **options)
        Item.new(**options).tap { |item| registry[ns] = item }
      end

      def check_namespace_conflict!(namespace)
        return if namespace.nil?

        if container.registered?(namespace) || registry.key?(namespace) ||
             container.component_key?(namespace)
          raise ImportNamespaceConflictError.new(namespace)
        end

        # Also detect conflicts with already registered nested keys, e.g. an existing
        # "ns.component" when importing under the "ns" namespace.
        prefix = "#{namespace}."

        if container._container.each_key.any? { |key| key.start_with?(prefix) }
          raise ImportNamespaceConflictError.new(namespace)
        end
      end

      def keys_to_import(keys, item)
        keys
          .then { (arr = item.import_keys) ? _1 & arr : _1 }
          .then { (arr = item.container.exports) ? _1 & arr : _1 }
      end

      def import_keys(other, namespace, keys)
        merge(container, build_merge_container(other, keys), namespace: namespace)
      end

      def import_all(other, namespace)
        merge_container =
          if other.exports
            build_merge_container(other, other.exports)
          else
            build_merge_container(other.finalize!, other.keys)
          end

        merge(container, merge_container, namespace: namespace)
      end

      # Merges `other` into `container`, favoring the container's existing registrations
      def merge(container, other, namespace:)
        container.merge(other, namespace: namespace) { |_key, old_item, new_item|
          old_item || new_item
        }
      end

      def build_merge_container(other, keys)
        keys.each_with_object(Core::Container.new) { |key, ic|
          next unless other.key?(key)

          # Access the other container's items directly so that we can preserve all their
          # options when we merge them with the target container (e.g. if a component in
          # the provider container was registered with a block, we want block registration
          # behavior to be exhibited when later resolving that component from the target
          # container). TODO: Make this part of dry-system's public API.
          item = other._container[key]

          # By default, we "protect" components that were themselves imported into the
          # other container from being implicitly exported; imported components are
          # considered "private" and must be explicitly included in `exports` to be
          # exported.
          next if item.options[:imported] && !other.exports

          if item.callable?
            ic.register(key, **item.options, imported: true, &item.item)
          else
            ic.register(key, item.item, **item.options, imported: true)
          end
        }
      end
    end
  end
end
