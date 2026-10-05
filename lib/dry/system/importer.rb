# frozen_string_literal: true

require "dry/system/constants"

module Dry
  module System
    # Default importer implementation
    #
    # This is currently configured by default for every System::Container.
    # Importer objects are responsible for importing components from one
    # container to another. This is used in cases where an application is split
    # into multiple sub-systems.
    #
    # Components can also be *borrowed* from a container: rather than copying the
    # component registrations into the target container, the target holds live,
    # delegating references to a fixed list of the source container's exported
    # keys. The source remains the lifecycle owner of any borrowed components, so
    # shutting down the target never stops the source's resources.
    #
    # @api private
    class Importer
      # @api private
      class Item
        attr_reader :namespace, :container, :import_keys, :borrow_keys

        def initialize(namespace:, container:, import_keys:, borrow_keys:)
          @namespace = namespace
          @container = container
          @import_keys = import_keys
          @borrow_keys = borrow_keys
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
        ns_key = namespace_key(namespace)

        raise ImportNamespaceConflictError, namespace if registry.key?(ns_key)

        borrow_keys = Array(keys).map(&:to_s) if borrow

        if borrow
          validate_borrow_keys(container, borrow_keys)
          register_borrows(container, namespace, borrow_keys)
        end

        registry[ns_key] = Item.new(
          namespace: namespace,
          container: container,
          import_keys: keys,
          borrow_keys: borrow ? borrow_keys : nil
        )
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
        registry.each_key { import(_1) }
        self
      end

      # @api private
      def import(namespace, keys: Undefined)
        item = self[namespace]

        return self if item.borrow_keys

        requested_keys = Undefined.default(keys, item.import_keys)

        if requested_keys
          import_keys(item.container, namespace, keys_to_import(requested_keys, item))
        else
          import_all(item.container, namespace)
        end

        self
      end

      private

      def validate_borrow_keys(source, keys)
        exports = source.config.exports

        keys.each do |key|
          allowed = Array(exports).map(&:to_s).include?(key)
          raise BorrowNotExportedError.new(key: key, source: source, exports: exports) unless allowed
        end
      end

      # Registers live, delegating references to the source container's exported
      # components. Unlike ordinary imports, the components are not copied: every
      # resolution is served by the source, which remains the lifecycle owner.
      def register_borrows(source, namespace, keys)
        keys.each do |key|
          namespaced_key = namespace ? "#{namespace}.#{key}" : key

          next if container.registered?(namespaced_key)

          container.register(namespaced_key, imported: true, borrowed: true) {
            container.resolve_borrowed(source, key)
          }
        end
      end

      # Returns nil if given a nil (i.e. root) namespace. Otherwise, converts the namespace to a
      # string.
      #
      # This ensures imported components are found when either symbols or strings to given as the
      # namespace in {Container.import}.
      def namespace_key(namespace)
        return nil if namespace.nil?

        namespace.to_s
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
