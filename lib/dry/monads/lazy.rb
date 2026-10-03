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

      # Raised when forcing a lazy computation would block forever because
      # of a cyclic dependency between lazy computations.
      #
      # @api public
      class CyclicDependencyError < ::StandardError
        # The dependency chain closing the cycle. The first and the last
        # elements are the same lazy computation.
        #
        # @return [Array<Lazy>]
        attr_reader :chain

        def initialize(chain)
          @chain = chain.freeze

          super("cyclic dependency detected: #{chain.map { describe(_1) }.join(' -> ')}")
        end

        private

        def describe(lazy) = "#{lazy.inspect}##{lazy.object_id}"
      end

      # Tracks which thread computes each lazy and which lazy each thread is
      # blocked on, so that circular waits get detected before they turn into
      # deadlocks.
      #
      # @private
      class WaitGraph
        def initialize
          @mutex = Mutex.new
          @owners = {}
          @waiting = {}
          @computing = {}
        end

        # Marks the current thread as the one computing the lazy
        def own(lazy)
          @mutex.synchronize do
            @owners[lazy] = Thread.current
            (@computing[Thread.current] ||= []).push(lazy)
          end
        end

        # Removes the marks left by #own
        def release(lazy)
          @mutex.synchronize do
            @owners.delete(lazy)

            stack = @computing[Thread.current]
            if stack
              index = stack.rindex { _1.equal?(lazy) }
              stack.delete_at(index) if index
              @computing.delete(Thread.current) if stack.empty?
            end
          end
        end

        # Registers that the current thread is about to block on the lazy
        #
        # @raises [CyclicDependencyError] if waiting would close a cycle
        def wait_on(lazy)
          @mutex.synchronize do
            @waiting[Thread.current] = lazy

            if (cycle = detect_cycle(lazy))
              @waiting.delete(Thread.current)
              raise CyclicDependencyError, cycle
            end
          end
        end

        # Unregisters the current thread's wait
        def stop_waiting
          @mutex.synchronize { @waiting.delete(Thread.current) }
        end

        private

        # Walks the wait-for graph starting from the lazy the current thread
        # is about to wait on. Returns the chain of lazies closing the cycle
        # or nil if waiting is safe.
        def detect_cycle(lazy)
          chain = [lazy]
          visited = {lazy => true}
          node = lazy

          loop do
            owner = @owners[node]
            return if owner.nil?
            return close_cycle(chain, node) if owner.equal?(Thread.current)

            node = @waiting[owner]
            return if node.nil? || visited[node]

            visited[node] = true
            chain << node
          end
        end

        def close_cycle(chain, node)
          if chain.size == 1 && (stack = @computing[Thread.current])
            index = stack.rindex { _1.equal?(node) }
            return stack[index..] + [node] if index
          end

          chain + [chain.first]
        end
      end

      # @private
      WAIT_GRAPH = WaitGraph.new
      private_constant :WAIT_GRAPH

      class << self
        # @private
        def new(promise = nil, &block)
          if promise
            super(promise)
          else
            lazy = nil
            tracked = proc do
              WAIT_GRAPH.own(lazy)
              begin
                block.call
              ensure
                WAIT_GRAPH.release(lazy)
              end
            end
            lazy = super(Concurrent::Promise.new(executor: :immediate, &tracked))
          end
        end

        private :[]
      end

      # Forces the compution and returns its value.
      #
      # @raises [CyclicDependencyError] if forcing would block forever
      #   because of a cyclic dependency between lazy computations
      #
      # @return [Object]
      def value!
        @promise.execute

        if @promise.complete?
          @promise.value!
        else
          WAIT_GRAPH.wait_on(self)
          begin
            @promise.value!
          ensure
            WAIT_GRAPH.stop_waiting
          end
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
