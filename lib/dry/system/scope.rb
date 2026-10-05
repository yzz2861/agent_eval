# frozen_string_literal: true

require "dry/system/errors"

module Dry
  module System
    # A Scope holds the instances of `scoped`-lifecycle components for the
    # duration of a single unit of work, such as a web request or a background
    # job.
    #
    # Scopes are opened via {Container.scoped}, which disposes the scope (and
    # every component instance it owns) when the given block exits, even when
    # it raises.
    #
    # ## Nesting and inheritance
    #
    # A scope opened while another scope is active becomes a child of that
    # scope, and the following rules apply:
    #
    # - When a scoped component is resolved, the innermost scope is checked
    #   first, then each of its ancestors in turn. An instance already created
    #   in an ancestor scope is inherited (shared) by all descendant scopes.
    # - When no ancestor scope holds an instance, the component is built and
    #   stored in the innermost scope, which becomes its owner.
    # - When a scope ends, it disposes only the instances it owns, in reverse
    #   order of their creation. Instances inherited from ancestor scopes are
    #   left untouched and are disposed when their owning scope ends.
    #
    # Scopes are isolated between fibers and threads: a scope opened in one
    # fiber or thread is not visible in any other. Wrap each unit of work in
    # its own {Container.scoped} block instead of sharing scopes across
    # fibers or threads.
    #
    # @api public
    class Scope
      # @!attribute [r] parent
      #   @return [Scope, nil] the parent scope, if this scope was opened
      #     inside another scope
      attr_reader :parent

      # @api private
      def initialize(parent: nil)
        @parent = parent
        @instances = {}
        @mutex = Mutex.new
        @disposed = false
      end

      # Returns true if the scope has ended and its owned instances disposed
      #
      # @return [Boolean]
      #
      # @api public
      def disposed?
        @mutex.synchronize { @disposed }
      end

      # Returns true if an instance for the given key is held by this scope or
      # any of its ancestors
      #
      # @param key [String] the component key
      #
      # @return [Boolean]
      #
      # @api public
      def key?(key)
        @mutex.synchronize { !lookup(key).nil? }
      end

      # Fetches the instance for the given key from this scope or its nearest
      # ancestor holding one, building and storing it in this scope otherwise
      #
      # @api private
      def fetch(key)
        @mutex.synchronize do
          raise ScopeDisposedError if @disposed

          if (instance = lookup(key))
            return instance
          end
        end

        instance = yield

        @mutex.synchronize { @instances[key] = instance }

        instance
      end

      # Disposes all component instances owned by this scope, in reverse order
      # of their creation.
      #
      # Every owned instance responding to `#close` is closed. All instances
      # are disposed even if some fail; the first error is raised afterwards.
      #
      # @return [self]
      #
      # @api private
      def dispose!
        owned = @mutex.synchronize do
          @disposed = true
          @instances.values.tap { @instances.clear }
        end

        first_error = nil

        owned.reverse_each do |instance|
          next unless instance.respond_to?(:close)

          begin
            instance.close
          rescue => e
            first_error ||= e
          end
        end

        raise first_error if first_error

        self
      end

      protected

      # @api private
      attr_reader :instances

      private

      # Looks up the key in this scope and its ancestors, returning the
      # inherited instance from the nearest scope holding one
      #
      # @api private
      def lookup(key)
        scope = self

        while scope
          return scope.instances[key] if scope.instances.key?(key)

          scope = scope.parent
        end

        nil
      end
    end
  end
end
