# frozen_string_literal: true

module Dry
  module System
    # A scope provides lifetime and sharing boundaries for +scoped+ components.
    #
    # Open a scope with {Dry::System::Container.scope}. While the scope is open,
    # resolving a +scoped+ component returns the same instance throughout the
    # scope. When the scope block finishes (even by raising), the components
    # owned by the scope are released in the reverse order of their creation.
    #
    # == Isolation
    #
    # Scopes are tracked in thread-local storage. A new +Thread+ (or a +Fiber+
    # other than the one that opened the scope) starts with no scope, so scoped
    # components are never shared across threads or independent fibers. To carry
    # a scope into a +Fiber+ you start yourself, run the fiber's work inside
    # {#activate}.
    #
    # == Nesting and inheritance
    #
    # Scopes opened from within a scope block are nested. A nested scope shares
    # the enclosing scope chain: resolving a +scoped+ component first returns an
    # instance already created by any enclosing scope. When no enclosing scope
    # has created one, the instance is created by and belongs to the innermost
    # scope and released when that scope closes; a later resolution in an outer
    # scope then creates a fresh instance owned by that outer scope.
    #
    # == Releasing components
    #
    # Components are released in the reverse order in which they were created.
    # If the component responds to +#close+, that method is called. Components
    # registered with a +release:+ option invoke that callable (or named method)
    # instead. Additional cleanup can be registered with {#on_release}.
    #
    # @see Dry::System::Container.scope
    #
    # @api public
    class Scope
      # @!attribute [r] container
      #   @return [Dry::System::Container] the container this scope belongs to
      #   @api public
      attr_reader :container

      # @!attribute [r] parent
      #   @return [Scope, nil] the immediately enclosing scope, if any
      #   @api public
      attr_reader :parent

      # @api private
      def initialize(container:, parent: nil)
        @container = container
        @parent = parent
        @instances = {}
        @owned = []
        @release_callbacks = []
      end

      # Returns the nesting depth of this scope; the first scope opened on a
      # thread is at depth 0.
      #
      # @return [Integer]
      #
      # @api public
      def depth
        parent ? parent.depth + 1 : 0
      end

      # Returns true when this scope has no enclosing scope
      #
      # @return [Boolean]
      #
      # @api public
      def root?
        parent.nil?
      end

      # Returns the existing scoped instance for the key, searching this scope
      # and all enclosing scopes outwards. Returns nil when no scope in the chain
      # has created the instance yet.
      #
      # @return [Object, nil]
      #
      # @api private
      def find(key)
        scope = self

        while scope
          return scope.instances[key] if scope.instances.key?(key)
          scope = scope.parent
        end

        nil
      end

      # Stores an instance created by this scope and takes ownership of its
      # release.
      #
      # @api private
      def store(key, instance, release)
        return instance if @instances.key?(key)

        @instances[key] = instance
        @owned << [key, instance, release]
        instance
      end

      # Registers a block to run when the scope is released. Callbacks run in
      # the reverse order of registration, after all owned components have been
      # released.
      #
      # @example
      #   MyApp.scope do |scope|
      #     scope.on_release { connection.rollback! }
      #   end
      #
      # @return [self]
      #
      # @api public
      def on_release(&block)
        @release_callbacks << block
        self
      end

      # Activates this scope on the current thread for the duration of the block.
      #
      # This is used to carry an already-open scope into a fiber that you start
      # yourself. Scopes are otherwise isolated per thread/fiber.
      #
      # @example
      #   MyApp.scope do |scope|
      #     Fiber.new do
      #       scope.activate { work_that_needs_scoped_components }
      #     end.resume
      #   end
      #
      # @return [Object] the return value of the block
      #
      # @api public
      def activate(&block)
        container.__send__(:_with_scope, self, &block)
      end

      # Releases every owned component and release callback, in reverse creation
      # order. Every release is attempted even if an earlier one raises; the
      # first release error is re-raised after all releases have run.
      #
      # @return [void]
      #
      # @api private
      def release!
        first_error = nil

        @owned.reverse_each do |key, instance, release|
          begin
            invoke_release(instance, release)
          rescue Exception => error # rubocop:disable Lint/RescueException
            first_error ||= error
          end
        ensure
          @instances.delete(key)
        end

        @release_callbacks.reverse_each do |callback|
          begin
            callback.call
          rescue Exception => error # rubocop:disable Lint/RescueException
            first_error ||= error
          end
        end

        @owned.clear
        @release_callbacks.clear

        raise first_error if first_error
      end

      protected

      attr_reader :instances

      private

      def invoke_release(instance, release)
        case release
        when nil
          instance.close if instance.respond_to?(:close)
        when Symbol, String
          instance.public_send(release) if instance.respond_to?(release)
        else
          release.call(instance)
        end
      end
    end
  end
end
