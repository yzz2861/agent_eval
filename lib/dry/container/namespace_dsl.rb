# frozen_string_literal: true

require "delegate"

module Dry
  class Container
    # @api private
    class NamespaceDSL < ::SimpleDelegator
      # DSL for defining namespaces
      #
      # @param [Dry::Container::Mixin] container
      #   The container
      # @param [String] namespace
      #   The namespace (name)
      # @param [String] namespace_separator
      #   The namespace separator
      # @yield
      #   The block to evaluate to define the namespace
      #
      # @return [Mixed]
      #
      # @api private
      def initialize(container, namespace, namespace_separator, &block)
        @namespace = namespace
        @namespace_separator = namespace_separator

        super(container)

        if block.arity.zero?
          instance_eval(&block)
        else
          yield self
        end
      end

      def register(key, *args, &block)
        super(namespaced(key), *args, &block)
      end

      def namespace(namespace, &block)
        super(namespaced(namespace), &block)
      end

      def import(namespace)
        namespace(namespace.name, &namespace.block)

        self
      end

      def resolve(key)
        super(namespaced(key))
      end

      def resolve_all(tag)
        root_container.resolve_all(tag, prefix: namespace_prefix)
      end

      def tagged_keys(tag)
        root_container.config.resolver.tagged_keys(root_container._container, tag,
                                                   prefix: namespace_prefix)
      end

      alias_method :keys_for_tag, :tagged_keys

      private

      def namespaced(key)
        [@namespace, key].join(@namespace_separator)
      end

      def root_container
        wrapped = __getobj__
        wrapped.is_a?(NamespaceDSL) ? wrapped.root_container : wrapped
      end

      def namespace_prefix
        wrapped = __getobj__
        if wrapped.is_a?(NamespaceDSL)
          [wrapped.namespace_prefix, @namespace].join
        else
          "#{@namespace}#{@namespace_separator}"
        end
      end
    end
  end
end
