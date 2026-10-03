# frozen_string_literal: true

module Dry
  module Monads
    # State represents a computation that produces a value and updates a state.
    #
    # Composing methods such as {#fmap} and {#bind} build the computation but do
    # not run it. Call {#run}, {#run_value}, or {#run_state} to execute it.
    # The built-in constructors never mutate the state passed in; functions are
    # expected to return the next state instead of changing it in place.
    #
    # @example basic stateful computation
    #   computation =
    #     State.get.bind do |initial|
    #       State.put(initial + 1).fmap { :done }
    #     end
    #
    #   computation.run(0) # => [:done, 1]
    #
    # @example combining with Result
    #   reserve = ->(item, quantity) {
    #     State.get.bind do |inventory|
    #       if inventory[item] < quantity
    #         State.pure(Failure(:insufficient_stock))
    #       else
    #         State.put(inventory.merge(item => inventory[item] - quantity)).fmap do
    #           Success(quantity)
    #         end
    #       end
    #     end
    #   }
    #
    #   program = reserve[:widgets, 1].bind_result do
    #     reserve[:gadgets, 1].bind_result { State.pure(Success(:reserved)) }
    #   end
    #
    #   program.run(widgets: 1, gadgets: 1)
    #   # => [Success(:reserved), {:widgets=>0, :gadgets=>0}]
    #   program.run(widgets: 1, gadgets: 0)
    #   # => [Failure(:insufficient_stock), {:widgets=>0, :gadgets=>0}]
    #
    # @api public
    class State
      Node = ::Data.define(:kind, :operand, :continuation)

      Frame = ::Data.define(:kind, :function)

      private_constant :Node, :Frame

      class << self
        # Creates a computation from a state-transition function.
        #
        # The function receives the current state and must return a two-element
        # array containing the value and the next state.
        #
        # @param function [#call] state-transition function
        # @param block [Proc] state-transition block
        # @return [State]
        def new(function = Undefined, &block)
          function = Undefined.default(function, block)

          unless function.respond_to?(:call)
            raise ::TypeError, "a callable state transition is required"
          end

          build(Node.new(:lift, function, nil))
        end

        # Lifts a value without changing the state.
        #
        # @param value [Object]
        # @param block [Proc]
        # @return [State]
        def pure(value = Undefined, &block)
          build(Node.new(:pure, Undefined.default(value, block || Unit), nil))
        end

        # Returns the current state as the value without changing it.
        #
        # @return [State]
        def get
          build(Node.new(:get, Unit, nil))
        end

        # Replaces the current state and returns Unit.
        #
        # @param state [Object]
        # @return [State]
        def put(state)
          build(Node.new(:put, state, nil))
        end

        # Replaces the state with the result of the given function.
        #
        # @param function [#call]
        # @param block [Proc]
        # @return [State]
        def modify(function = Undefined, &block)
          function = Undefined.default(function, block)

          unless function.respond_to?(:call)
            raise ::TypeError, "a callable state modification is required"
          end

          build(Node.new(:modify, function, nil))
        end

        private

        def build(node)
          allocate.tap { |state| state.instance_variable_set(:@node, node) }.freeze
        end
      end

      # @return [State]
      def to_monad = self

      # @return [State]
      def monad = State

      # Transforms the computed value without touching the state.
      #
      # @param function [#call]
      # @param block [Proc]
      # @return [State]
      def fmap(function = Undefined, &block)
        function = Undefined.default(function, block)
        rebuild(Node.new(:fmap, function, @node))
      end

      # Composes this computation with another State computation.
      #
      # @param function [#call] receives the computed value and returns a State
      # @param block [Proc]
      # @return [State]
      def bind(function = Undefined, &block)
        function = Undefined.default(function, block)
        rebuild(Node.new(:bind, function, @node))
      end

      # Composes this computation with a State computation whose value is a
      # {Result}.
      #
      # On Success the block is called with its value and must return a State.
      # On Failure the remaining computation is skipped and the state present
      # at that point is retained. There is no implicit rollback: state changes
      # made by earlier successful steps remain visible. A failure produced via
      # State.put(next_state).fmap { Failure(...) } also retains next_state.
      #
      # @param function [#call] receives a Success value and returns a State
      # @param block [Proc]
      # @return [State]
      def bind_result(function = Undefined, &block)
        function = Undefined.default(function, block)
        rebuild(Node.new(:bind_result, function, @node))
      end

      # Executes the computation.
      #
      # @param initial_state [Object]
      # @return [Array(Object, Object)] the final value and final state
      def run(initial_state)
        frames = []
        node = @node
        current_state = initial_state

        loop do
          case node.kind
          when :pure
            value = node.operand

            if frames.empty?
              return [value, current_state]
            end

            frame = frames.pop

            case frame.kind
            when :fmap
              node = pure_node(call_function(frame.function, value))
            when :bind
              frames.push(Frame.new(:state_boundary, nil))
              node = state_from(frame.function, value).node
            when :bind_result
              if Result::Failure === value
                boundary = frames.rindex { |candidate| state_boundary?(candidate) }
                frames = frames[0..boundary] if boundary
                node = pure_node(value)
              else
                unless Result === value
                  raise ::TypeError, "expected Result, got #{value.inspect}"
                end

                frames.push(Frame.new(:result_boundary, nil))
                node = state_from(frame.function, value.success).node
              end
            when :state_boundary
              node = pure_node(value)
            when :result_boundary
              unless Result === value
                raise ::TypeError, "expected Result, got #{value.inspect}"
              end

              if Result::Failure === value
                boundary = frames.rindex { |candidate| state_boundary?(candidate) }
                frames = boundary ? frames[0..boundary] : []
              end

              node = pure_node(value)
            end
          when :lift
            transition = node.operand.call(current_state)

            unless transition.is_a?(::Array) && transition.length.equal?(2)
              raise ::TypeError, "state transition must return [value, state], got #{transition.inspect}"
            end

            value, next_state = transition
            current_state = next_state
            node = pure_node(value)
          when :get
            node = node.continuation || pure_node(current_state)
          when :put
            current_state = node.operand
            node = node.continuation || pure_node(Unit)
          when :modify
            current_state = call_function(node.operand, current_state)
            node = node.continuation || pure_node(Unit)
          when :fmap, :bind, :bind_result
            frames.push(Frame.new(node.kind, node.operand))
            node = node.continuation
          else
            raise "Unknown State node #{node.kind.inspect}"
          end
        end
      end

      # Executes the computation and returns only the final value.
      #
      # @param initial_state [Object]
      # @return [Object]
      def run_value(initial_state)
        run(initial_state).first
      end

      # Executes the computation and returns only the final state.
      #
      # @param initial_state [Object]
      # @return [Object]
      def run_state(initial_state)
        run(initial_state).last
      end

      # @return [String]
      def to_s = "State(?)"
      alias_method :inspect, :to_s

      protected

      attr_reader :node

      private

      def rebuild(node)
        self.class.send(:build, node)
      end

      def pure_node(value)
        Node.new(:pure, value, nil)
      end

      def state_boundary?(frame)
        frame.kind.equal?(:state_boundary) || frame.kind.equal?(:result_boundary)
      end

      def call_function(function, *args)
        function.call(*args)
      end

      def state_from(function, value)
        result = call_function(function, value)

        unless result.is_a?(State)
          raise ::TypeError, "expected State, got #{result.inspect}"
        end

        result
      end

      # Constructors for the State monad.
      module Mixin
        # @see Dry::Monads::State
        State = State

        # @see Dry::Monads::Unit
        Unit = Unit

        module Constructors
          # State computation constructor
          #
          # @param function [#call]
          # @param block [Proc]
          # @return [State]
          def State(function = Undefined, &block) = State.new(function, &block)
        end

        include Constructors
      end
    end

    extend State::Mixin::Constructors

    require "dry/monads/registry"
    register_mixin(:state, State::Mixin)
  end
end
