# frozen_string_literal: true

require "concurrent/promise"

module Dry
  module Monads
    # Lazy is a twin of Task which is always executed on the current thread.
    # The underlying mechanism provided by concurrent-ruby ensures the given
    # computation is evaluated not more than once (compare with the built-in
    # lazy assignement ||= which does not guarantee this).
    class Lazy < Task
      extend ::Dry::Core::Deprecations[:"dry-monads"]

      # Raised when forcing a lazy value depends on itself.
      class CircularDependencyError < ::StandardError
        attr_reader :chain

        def initialize(chain)
          @chain = chain.dup.freeze
          super("circular dependency detected: #{@chain.map { label(_1) }.join(" -> ")}")
        end

        private

        def label(lazy)
          "#<Dry::Monads::Lazy:0x#{(lazy.object_id << 1).to_s(16).rjust(16, "0")}>"
        end
      end

      # @api private
      class Dependency
        def initialize
          @mutex = ::Mutex.new
          @condition = ::ConditionVariable.new
          @active = ::Hash.new { |hash, thread| hash[thread] = [] }
          @waiting = {}
          @interruptions = {}
        end

        def track(lazy)
          thread = ::Thread.current
          @mutex.synchronize do
            @active[thread].push(lazy)
            @waiting.delete(thread)
          end
          yield
        ensure
          @mutex.synchronize do
            stack = @active[thread]
            index = stack.rindex(lazy)
            stack.delete_at(index) if index
            @active.delete(thread) if stack.empty?
          end
        end

        def wait(lazy, promise)
          thread = ::Thread.current
          observer = proc { @mutex.synchronize { @condition.broadcast } }
          promise.add_observer(&observer)

          begin
            error = nil

            @mutex.synchronize do
              loop do
                return if promise.complete?

                @waiting[thread] = lazy
                error = @interruptions[thread] || circular_dependency_error(thread, lazy)
                break if error
                return if promise.complete?

                @condition.wait(@mutex)
              end
            end

            raise error
          ensure
            @mutex.synchronize do
              @waiting.delete(thread) if @waiting[thread].equal?(lazy)
              @interruptions.delete(thread)
              @condition.broadcast
            end
            promise.delete_observer(observer)
          end
        end

        private

        def circular_dependency_error(thread, lazy)
          chain = []
          visited = {}
          interrupted_threads = []
          current_lazy = lazy
          return unless @active.key?(thread)

          while current_lazy
            if visited.key?(current_lazy)
              chain << current_lazy
              error = CircularDependencyError.new(chain)
              interrupted_threads.uniq.each { @interruptions[_1] ||= error }
              @condition.broadcast
              return error
            end

            visited[current_lazy] = true
            chain << current_lazy

            owner_thread, owner_stack = active_owner(current_lazy)
            return unless owner_stack

            interrupted_threads << owner_thread
            index = owner_stack.rindex(current_lazy)
            current_lazy = owner_stack[index + 1] || @waiting[owner_thread]
          end

          nil
        end

        def active_owner(lazy)
          @active.each do |owner_thread, owner_stack|
            return [owner_thread, owner_stack] if owner_stack.include?(lazy)
          end

          nil
        end
      end

      DEPENDENCIES = Dependency.new

      class << self
        # @private
        def new(promise = nil, &)
          if promise
            super(promise)
          else
            lazy = allocate
            computation = proc { DEPENDENCIES.track(lazy, &) }
            lazy.send(:initialize, Concurrent::Promise.new(executor: :immediate, &computation))
            lazy
          end
        end

        private :[]
      end

      # Forces the compution and returns its value.
      #
      # @return [Object]
      def value!
        @promise.execute
        DEPENDENCIES.wait(self, @promise)

        if @promise.fulfilled?
          @promise.value
        else
          raise @promise.reason
        end
      end
      alias_method :force!, :value!

      # Forces the computation. Note that if the computation
      # thrown an error it won't be re-raised as opposed to value!/force!.
      #
      # @return [Lazy]
      def force
        @promise.execute
        self
      end

      # @return [Boolean]
      def evaluated? = @promise.complete?
      deprecate :complete?, :evaluated?

      undef_method :wait

      # Lifts a block over the Lazy monad.
      #
      # @return [Lazy]
      def fmap(&block)
        lazy = build_lazy
        mapped = promise.then do |value|
          DEPENDENCIES.track(lazy) { block.call(value) }
        end
        lazy.send(:initialize, mapped)
        lazy
      end

      # Composes two lazy computations.
      #
      # @return [Lazy]
      def bind(&block)
        lazy = build_lazy
        mapped = promise.flat_map do |value|
          DEPENDENCIES.track(lazy) do
            inner = block.call(value)
            inner.promise
          end
        end
        lazy.send(:initialize, mapped)
        lazy
      end

      # @return [Lazy]
      def or_fmap(&block)
        lazy = build_lazy
        mapped = promise.rescue do |reason|
          DEPENDENCIES.track(lazy) { block.call(reason) }
        end
        lazy.send(:initialize, mapped)
        lazy
      end

      # @return [Lazy]
      def or(&block)
        lazy = build_lazy
        child = Concurrent::Promise.new(
          parent: promise,
          executor: Concurrent::ImmediateExecutor.new
        )

        promise.on_error do |reason|
          DEPENDENCIES.track(lazy) do
            inner = block.call(reason)
            inner.promise.execute
            inner.promise.on_success { child.on_fulfill(_1) }
            inner.promise.on_error { child.on_reject(_1) }
          end
        rescue StandardError => exception
          child.on_reject(exception)
        end
        promise.on_success { child.on_fulfill(_1) }

        lazy.send(:initialize, child)
        lazy
      end

      # @return [String]
      def to_s
        state =
          case promise.state
          when :fulfilled
            value!.inspect
          when :rejected
            "!#{promise.reason.inspect}"
          else
            "?"
          end

        "Lazy(#{state})"
      end
      alias_method :inspect, :to_s

      private

      def build_lazy(promise = nil)
        lazy = self.class.allocate
        lazy.send(:initialize, promise) if promise
        lazy
      end

      # Lazy constructors
      #
      module Mixin
        # @see Dry::Monads::Lazy
        Lazy = Lazy

        # @see Dry::Monads::Unit
        Unit = Unit

        # Lazy constructors
        module Constructors
          # Lazy computation contructor
          #
          # @param block [Proc]
          # @return [Lazy]
          def Lazy(&) = Lazy.new(&)
        end

        include Constructors
      end
    end

    require "dry/monads/registry"
    register_mixin(:lazy, Lazy::Mixin)
  end
end
