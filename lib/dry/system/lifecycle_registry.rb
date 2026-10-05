# frozen_string_literal: true

require "thread"

module Dry
  module System
    # @api private
    #
    # Manages component lifecycles for a container: it records the lifecycle
    # (and release hook) of every registered component, resolves singleton and
    # scoped instances with the appropriate sharing rules, enforces the captive
    # dependency rule during construction, and releases instances when scopes
    # close or the container shuts down.
    class LifecycleRegistry
      # Fiber-/thread-local key holding the stack of component constructions in
      # progress. Each frame is a Hash with +:container+, +:key+ and
      # +:lifecycle+. A process-wide stack (rather than a per-container one)
      # lets the captive dependency check see chains spanning imported
      # containers while filtering frames to the container that owns the
      # component currently being built.
      FRAME_STACK_KEY = :__dry_system_lifecycle_frames__

      attr_reader :container

      def initialize(container)
        @container = container
        @lifecycle_options = {}
        @singletons = {}
        @singleton_mutex = Mutex.new
        @singleton_key_mutexes = {}
      end

      # @api private
      def initialize_copy(source)
        super

        source_options = source.instance_variable_get(:@lifecycle_options)
        source_singletons = source.instance_variable_get(:@singletons)

        @lifecycle_options = source_options.dup
        @singletons = source_singletons.dup
        @singleton_mutex = Mutex.new
        @singleton_key_mutexes = {}
      end

      # Records the lifecycle for a key at registration time
      #
      # @return [Lifecycle]
      def register(key, lifecycle: Lifecycle::TRANSIENT, release: nil)
        lifecycle = Lifecycle[lifecycle]
        @lifecycle_options[key.to_s] = {lifecycle: lifecycle, release: release}
        lifecycle
      end

      # @return [Lifecycle, nil]
      def lifecycle_for(key)
        options = @lifecycle_options[key.to_s]
        options && options.fetch(:lifecycle)
      end

      # @return [Hash, nil]
      def options_for(key)
        @lifecycle_options[key.to_s]
      end

      # @return [Boolean]
      def managed?(key)
        @lifecycle_options.key?(key.to_s)
      end

      # Resolves a managed component, applying singleton/scoped sharing and the
      # captive dependency rule.
      #
      # @param key [String, Symbol]
      # @param build [#call] a block returning a freshly built instance
      def resolve(key, &build)
        options = @lifecycle_options.fetch(key.to_s)
        lifecycle = options.fetch(:lifecycle)
        key = key.to_s

        check_capture!(key, lifecycle)

        case lifecycle
        when Lifecycle::SINGLETON
          resolve_singleton(key, &build)
        when Lifecycle::SCOPED
          resolve_scoped(key, options.fetch(:release), &build)
        else
          build_with_frame(key, lifecycle, &build)
        end
      end

      # Releases all singleton instances, in reverse order of creation.
      def shutdown!
        first_error = nil

        @singleton_mutex.synchronize do
          @singletons.reverse_each do |key, entry|
            begin
              invoke_release(entry[:instance], entry[:release])
            rescue Exception => error # rubocop:disable Lint/RescueException
              first_error ||= error
            end
          end

          @singletons.clear
        end

        raise first_error if first_error
      end

      # Runs a block with +scope+ as the active scope for this container on the
      # current thread/fiber.
      def with_scope(scope)
        scope_stack << scope

        begin
          yield(scope)
        ensure
          pop_scope(scope)
        end
      end

      # @return [Scope, nil] the innermost currently active scope
      def current_scope
        scope_stack.last
      end

      private

      def resolve_singleton(key, &build)
        entry = @singletons[key]
        return entry.fetch(:instance) if entry

        singleton_key_mutex(key).synchronize do
          entry = @singletons[key]
          next entry.fetch(:instance) if entry

          instance = build_with_frame(key, Lifecycle::SINGLETON, &build)
          store_singleton(key, instance)
          instance
        end
      end

      def singleton_key_mutex(key)
        @singleton_mutex.synchronize do
          @singleton_key_mutexes[key] ||= Mutex.new
        end
      end

      def store_singleton(key, instance)
        @singletons[key] = {
          instance: instance,
          release: @lifecycle_options.fetch(key).fetch(:release)
        }
      end

      def resolve_scoped(key, release, &build)
        scope = current_scope
        check_capture!(key, Lifecycle::SCOPED)

        unless scope
          raise ScopedComponentWithoutScopeError.new(key)
        end

        if (instance = scope.find(key))
          instance
        else
          instance = build_with_frame(key, Lifecycle::SCOPED, &build)
          scope.store(key, instance, release)
        end
      end

      # Builds an instance while the component is present on the construction
      # stack, so that any dependencies it resolves can detect a captive
      # dependency.
      def build_with_frame(key, lifecycle)
        frame_stack << {container: container, key: key, lifecycle: lifecycle}

        begin
          yield
        ensure
          frame_stack.pop
        end
      end

      # Raises when a component being constructed by a frame on this container
      # would capture a shorter-lived dependency. The full construction stack
      # (which may span imported containers) forms the dependency chain.
      def check_capture!(key, dependency_lifecycle)
        origin = frame_stack.index {
          !_1.fetch(:lifecycle).can_depend_on?(dependency_lifecycle)
        }

        return unless origin

        chain = frame_stack[origin..].map {
          [_1.fetch(:key), _1.fetch(:lifecycle).to_s]
        } << [key, dependency_lifecycle.to_s]

        raise CaptiveDependencyError.new(chain)
      end

      # @return [Array<Hash>]
      def frame_stack
        Thread.current[FRAME_STACK_KEY] ||= []
      end

      # @return [Array<Scope>]
      def scope_stack
        Thread.current[scope_stack_key] ||= []
      end

      def scope_stack_key
        @scope_stack_key ||= "__dry_system_scope_stack_#{container.object_id}__".to_sym
      end

      def pop_scope(scope)
        scope_stack.pop
        scope.release!
      end

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
