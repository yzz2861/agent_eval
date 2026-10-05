# frozen_string_literal: true

require "monitor"

require "dry/core"

module Dry
  module System
    # A scoped set of substitute registrations, active for the duration of a
    # {Container.override} block
    #
    # Within its scope, the container returns the substitutes for the overridden keys
    # and rebuilds any other component it resolves, caching the rebuilt components for
    # the rest of the scope. This way, components depending (directly or transitively)
    # on the overridden keys are re-created on top of the substitutes, even if they
    # were already built and memoized before the scope began.
    #
    # The container's own registry is never mutated: its registered factories and
    # memoized components are left untouched and keep serving code running outside the
    # scope. Scopes are thread-local and can be nested; when a nested scope exits, the
    # enclosing scope's rebuilt graph is used again.
    #
    # @api private
    class OverrideScope
      # @api private
      THREAD_KEY = :__dry_system_override_scopes__

      class << self
        # Returns the innermost scope active for the container in the current thread
        #
        # @api private
        def current_for(container)
          Thread.current.thread_variable_get(THREAD_KEY)&.[](container)&.last
        end

        # @api private
        def push(container, scope)
          scopes = Thread.current.thread_variable_get(THREAD_KEY)

          unless scopes
            scopes = {}
            Thread.current.thread_variable_set(THREAD_KEY, scopes)
          end

          (scopes[container] ||= []) << scope

          scope
        end

        # @api private
        def pop(container)
          stack = Thread.current.thread_variable_get(THREAD_KEY)&.[](container)
          return unless stack

          stack.pop

          nil
        end
      end

      # @api private
      attr_reader :container

      # @api private
      attr_reader :substitutes

      # @api private
      attr_reader :parent

      def initialize(container, substitutes, parent: nil)
        @container = container
        @substitutes = substitutes.transform_keys(&:to_s).freeze
        @parent = parent
        @resolved = {}
        @monitor = ::Monitor.new
      end

      # Resolves a key within the scope
      #
      # Returns the innermost substitute when the key is overridden (by this or any
      # enclosing scope), otherwise builds the component fresh and caches it for the
      # rest of the scope
      #
      # @api private
      def resolve(key, &fallback)
        key = key.to_s

        substitute = substitute_for(key)
        return substitute unless substitute.equal?(Dry::Core::Constants::Undefined)

        resolve_owned(key, &fallback)
      end

      # Returns the substitute for a key, looking through enclosing scopes, or
      # Undefined when the key is not overridden
      #
      # @api private
      def substitute_for(key)
        if substitutes.key?(key)
          substitutes[key]
        elsif parent
          parent.substitute_for(key)
        else
          Dry::Core::Constants::Undefined
        end
      end

      private

      def resolve_owned(key, &fallback)
        @monitor.synchronize do
          return @resolved[key] if @resolved.key?(key)

          container.send(:load_component, key) unless container.finalized?

          item = container._container.fetch(key) do
            return fallback.call(key) if fallback

            raise Dry::Core::Container::KeyError.new(
              %(key not found: "#{key}"), key: key, receiver: container._container
            )
          end

          # Only scope-owned state is touched here: if building the component fails,
          # nothing is cached and the container's own registry is left as it was
          @resolved[key] = build_fresh(item)
        end
      end

      # Builds a fresh component from its registered item, bypassing (and preserving)
      # the container's own memoized value
      def build_fresh(item)
        if item.is_a?(Dry::Core::Container::Item::Memoizable)
          item.item.call
        else
          item.call
        end
      end
    end
  end
end
