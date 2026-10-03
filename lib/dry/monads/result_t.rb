# frozen_string_literal: true

module Dry
  module Monads
    # Lifts Result values over asynchronous Tasks.
    #
    # A ResultT wraps a Task which fulfills with either Success or Failure.
    # Failure values short-circuit subsequent ResultT steps. A rejected Task
    # keeps using the exception channel and is never converted to Failure.
    #
    # @api public
    class ResultT
      class << self
        # Creates a ResultT from a Result, Task, or ResultT.
        #
        # @param value [Result, Task, ResultT]
        # @return [ResultT]
        def new(value)
          self[value]
        end

        # Lifts a Result, Task, or ResultT.
        #
        # @param value [Result, Task, ResultT]
        # @return [ResultT]
        def [](value)
          case value
          when ResultT
            value
          when Task
            from_task(value)
          when Result
            from_result(value)
          else
            raise(
              TypeError,
              "Expected Result, Task, or ResultT, got #{value.class}: #{value.inspect}"
            )
          end
        end
        alias_method :call, :[]
        alias_method :lift, :[]

        # Lifts a plain Result into an already fulfilled Task.
        #
        # @param result [Result]
        # @return [ResultT]
        def from_result(result)
          assert_result!(result, "Expected a Result")
          wrap(Task.pure(result))
        end

        # Lifts a Task which fulfills with a Result.
        #
        # @param task [Task]
        # @return [ResultT]
        def from_task(task)
          unless task.is_a?(Task)
            raise TypeError, "Expected a Task, got #{task.class}: #{task.inspect}"
          end

          validated_task = task.fmap do |value|
            assert_result!(
              value,
              "Expected the Task wrapped by ResultT to fulfill with a Result"
            )
          end

          wrap(validated_task)
        end

        # Returns a ResultT containing Success(value).
        #
        # @param value [Object]
        # @return [ResultT]
        def pure(value = Undefined, &block)
          from_result(Result::Success.new(Undefined.default(value, block)))
        end
        alias_method :success, :pure

        # Returns a ResultT containing Failure(error).
        #
        # @param error [Object]
        # @return [ResultT]
        def failure(error = Undefined, &block)
          from_result(Result::Failure.new(Undefined.default(error, block)))
        end

        private

        def wrap(task)
          allocate.tap do |result_t|
            result_t.send(:initialize, task)
          end
        end

        def assert_result!(value, prefix)
          return value if value.is_a?(Result)

          raise TypeError, "#{prefix}, got #{value.class}: #{value.inspect}"
        end
      end

      # @return [Task] the wrapped Task that fulfills with a Result
      attr_reader :task

      # Maps the value wrapped by Success. Failure and rejected Tasks are kept.
      #
      # @param block [#call]
      # @return [ResultT]
      def fmap(callable = Undefined, &block)
        function = Undefined.default(callable, block)

        mapped_task = task.fmap do |result|
          result.fmap { |value| function.(value) }
        end

        self.class.send(:wrap, mapped_task)
      end

      # Composes another asynchronous Result computation on Success.
      #
      # The block may return ResultT, Task<Result>, or a plain Result.
      # Failure and rejected Tasks skip later blocks.
      #
      # @param block [#call]
      # @return [ResultT]
      def bind(callable = Undefined, &block)
        function = Undefined.default(callable, block)

        bound_task = task.bind do |result|
          next Task.pure(result) if result.failure?

          nested = function.(result.success)

          case nested
          when ResultT
            nested.task
          when Result
            Task.pure(nested)
          when Task
            nested.fmap do |value|
              next value if value.is_a?(Result)

              raise(
                TypeError,
                "ResultT#bind block returned a Task that must fulfill with a Result, " \
                "got #{value.class}: #{value.inspect}"
              )
            end
          else
            raise(
              TypeError,
              "ResultT#bind block must return a Result, Task, or ResultT, " \
              "got #{nested.class}: #{nested.inspect}"
            )
          end
        end

        self.class.send(:wrap, bound_task)
      end

      # Waits for the computation and returns its Result.
      # Rejects the Task by raising the original exception.
      #
      # @return [Result]
      def value!
        task.value!
      end
      alias_method :result!, :value!

      # Blocks until the wrapped Task completes.
      #
      # @return [ResultT]
      def wait(timeout = nil)
        task.wait(timeout)
        self
      end

      # @return [Boolean]
      def complete?
        task.complete?
      end

      # @return [ResultT]
      def to_monad
        self
      end

      # @return [Class]
      def monad
        ResultT
      end

      # @return [String]
      def to_s
        "ResultT(#{task})"
      end
      alias_method :inspect, :to_s

      # @param other [Object]
      # @return [Boolean]
      def ==(other)
        other.is_a?(ResultT) && task == other.task
      end

      private

      def initialize(task)
        @task = task
      end

      # Constructors for mixing ResultT into host objects.
      #
      # @api public
      module Mixin
        # @see Dry::Monads::ResultT
        ResultT = Monads::ResultT

        # ResultT constructors
        module Constructors
          # Builds a ResultT from a Result, Task, ResultT, or an async block
          # that returns a Result.
          #
          # @param value [Result, Task, ResultT]
          # @return [ResultT]
          def ResultT(value = Undefined, &block)
            if block
              unless Undefined.equal?(value)
                raise ArgumentError, "cannot pass both a value and a block to ResultT"
              end

              Monads::ResultT.from_task(Task.new(&block))
            else
              Monads::ResultT[Undefined.default(value, Unit)]
            end
          end
        end

        include Constructors
      end
    end

    require "dry/monads/registry"
    register_mixin(:result_t, ResultT::Mixin)
  end
end
