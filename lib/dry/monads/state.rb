# frozen_string_literal: true

module Dry
  module Monads
    # State represents a state-dependent computation: given an initial
    # state, it produces a value along with a new state. It is typically
    # used for modeling state transitions (ledgers, counters, carts,
    # inventories) in a pure, composable way.
    #
    # Composing computations with #fmap/#bind/#bind_result builds a
    # description of the computation only — nothing is executed until
    # you call #run, #eval_state, or #exec_state with an initial state.
    #
    # The state is threaded through the computation by value: the library
    # never mutates the state you pass in, so running the same computation
    # twice with the same initial state is safe and gives equal results.
    # Functions you pass to .modify/.step are expected to return a new
    # state rather than mutate the one they receive.
    #
    # @api public
    class State
      class << self
        # Lifts a value into a computation that leaves the state untouched.
        #
        # @param value [Object]
        # @return [State]
        def pure(value)
          new(Pure.new(value))
        end

        # A computation whose value is the current state.
        # The state itself is left unchanged.
        #
        # @return [State]
        def get
          new(Get.new)
        end

        # Replaces the state with the given one. The value is Unit.
        #
        # @param new_state [Object]
        # @return [State]
        def put(new_state)
          new(Put.new(new_state))
        end

        # Updates the state with a function. The value is Unit.
        # The function should return a new state instead of mutating
        # the one it receives.
        #
        # @param fn [#call] state -> new_state
        # @param block [Proc] state -> new_state
        # @return [State]
        def modify(fn = Undefined, &block)
          new(Modify.new(Undefined.default(fn, block)))
        end

        # Derives a value from the current state without changing it.
        #
        # @param fn [#call] state -> value
        # @param block [Proc] state -> value
        # @return [State]
        def gets(fn = Undefined, &block)
          get.fmap(Undefined.default(fn, block))
        end

        # Builds a computation from a raw step function taking the
        # current state and returning a [value, new_state] tuple.
        #
        # @param fn [#call] state -> [value, new_state]
        # @param block [Proc] state -> [value, new_state]
        # @return [State]
        def step(fn = Undefined, &block)
          new(Step.new(Undefined.default(fn, block)))
        end

        # Lifts a Result into a state computation. On Success the
        # computation continues with the unwrapped value, on Failure
        # it halts: #run returns the Failure along with the state
        # reached at that point (no rollback is performed).
        #
        # @param result [Result::Success, Result::Failure]
        # @return [State]
        def from_result(result)
          if result.success?
            pure(result.value!)
          else
            new(Failed.new(result))
          end
        end
      end

      # @api private
      def initialize(node)
        super()
        @node = node
      end

      # Returns self.
      #
      # @return [State]
      def to_monad = self

      # Returns the State monad.
      #
      # @return [Monad]
      def monad = State

      # Maps a function over the value of the computation,
      # leaving the state transitions untouched.
      #
      # @param fn [#call]
      # @param block [Proc]
      # @return [State]
      def fmap(fn = Undefined, &block)
        f = Undefined.default(fn, block)
        bind { |value| State.pure(f.call(value)) }
      end

      # Sequences two computations, threading the state through.
      # The function receives the value of the current computation
      # and must return the next State computation.
      #
      # @param fn [#call]
      # @param block [Proc]
      # @return [State]
      def bind(fn = Undefined, &block)
        State.new(Bind.new(@node, Undefined.default(fn, block)))
      end

      # Sequences a step that produces a Result. On Success the
      # computation continues with the unwrapped value. On Failure
      # the computation halts and #run returns the Failure together
      # with the state at the point of failure — changes made before
      # the failure are kept, the library never rolls the state back
      # to its initial value.
      #
      # @param fn [#call] value -> Result
      # @param block [Proc] value -> Result
      # @return [State]
      def bind_result(fn = Undefined, &block)
        f = Undefined.default(fn, block)
        bind { |value| State.from_result(f.call(value)) }
      end

      # Runs the computation against the initial state.
      #
      # @param initial_state [Object]
      # @return [Array(Object, Object)] the [value, state] pair. If the
      #   computation was halted by a failing Result (see #bind_result),
      #   the value is the Failure and the state is the one reached at
      #   the point of failure.
      def run(initial_state)
        node = @node
        state = initial_state
        stack = []

        loop do
          while node.is_a?(Bind)
            stack.push(node.fn)
            node = node.source
          end

          value =
            case node
            when Pure
              node.value
            when Get
              state
            when Put
              state = node.new_state
              Unit
            when Modify
              state = node.fn.call(state)
              Unit
            when Step
              pair = node.fn.call(state)
              state = pair[1]
              pair[0]
            when Failed
              return [node.result, state]
            end

          return [value, state] if stack.empty?

          node = stack.pop.call(value).node
        end
      end

      # Runs the computation and returns the final value.
      #
      # @param initial_state [Object]
      # @return [Object]
      def eval_state(initial_state)
        run(initial_state)[0]
      end

      # Runs the computation and returns the final state.
      #
      # @param initial_state [Object]
      # @return [Object]
      def exec_state(initial_state)
        run(initial_state)[1]
      end

      # @return [String]
      def to_s = "State(?)"
      alias_method :inspect, :to_s

      # @api private
      class Pure
        attr_reader :value

        def initialize(value)
          @value = value
        end
      end

      # @api private
      class Get
      end

      # @api private
      class Put
        attr_reader :new_state

        def initialize(new_state)
          @new_state = new_state
        end
      end

      # @api private
      class Modify
        attr_reader :fn

        def initialize(fn)
          @fn = fn
        end
      end

      # @api private
      class Step
        attr_reader :fn

        def initialize(fn)
          @fn = fn
        end
      end

      # @api private
      class Bind
        attr_reader :source, :fn

        def initialize(source, fn)
          @source = source
          @fn = fn
        end
      end

      # @api private
      class Failed
        attr_reader :result

        def initialize(result)
          @result = result
        end
      end

      protected

      # @api private
      attr_reader :node

      public

      # A module that can be included for easier access to State monads.
      #
      # @api public
      module Mixin
        # @see Dry::Monads::State
        State = State

        # @see Dry::Monads::Unit
        Unit = Unit

        # State constructors
        module Constructors
          # State computation constructor
          #
          # @overload State(value)
          #   Lifts a value, see State.pure
          #   @param value [Object]
          #   @return [State]
          #
          # @overload State(&block)
          #   Builds a computation from a step function, see State.step
          #   @param block [Proc] state -> [value, new_state]
          #   @return [State]
          def State(value = Undefined, &block)
            if block
              State.step(&block)
            else
              State.pure(Undefined.default(value, Unit))
            end
          end
        end

        include Constructors
      end
    end

    require "dry/monads/registry"
    register_mixin(:state, State::Mixin)
  end
end
