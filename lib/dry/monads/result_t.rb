# frozen_string_literal: true

module Dry
  module Monads
    # Asynchronous Result monad transformer.
    #
    # Wraps a Task whose fulfilled value is a Result. Business rejections stay
    # on the Result channel, while a rejected Task keeps its exception channel.
    #
    # @api public
    class ResultT
      class << self
        # Lifts a Result or a Task wrapping a Result.
        #
        # @param value [Result, Task, ResultT]
        # @return [ResultT]
        def [](value)
          case value
          when ResultT then value
          when Task then from_task(value)
          when Result then from_result(value)
          else
            raise(
              TypeError,
              "expected a Dry::Monads::Result or a Dry::Monads::Task<Result>, " \
              "got #{value.class}"
            )
          end
        end
        alias_method :lift, :[]
        alias_method :coerce, :[]

        # Lifts a plain Result into an already fulfilled Task.
        #
        # @param result [Result]
        # @return [ResultT]
        def from_result(result)
          unless result.is_a?(Result)
            raise(
              TypeError,
              "expected a Dry::Monads::Result (Success or Failure), " \
              "got #{result.class}; use .from_task to lift a Task<Result>"
            )
          end

          new(Task.pure(result))
        end
        alias_method :lift_result, :from_result

        # Lifts a Task wrapping a Result. The task is not waited for.
        #
        # @param task [Task<Result>]
        # @return [ResultT]
        def from_task(task)
          unless task.is_a?(Task)
            raise(
              TypeError,
              "expected a Dry::Monads::Task<Result>, got #{task.class}; " \
              "use .from_result to lift a Result"
            )
          end

          new(task)
        end
        alias_method :lift_task, :from_task

        # Creates a ResultT containing Success(value).
        #
        # @param value [Object]
        # @return [ResultT]
        def pure(value = Undefined, &block)
          from_result(Result.pure(value, &block))
        end
      end

      # @return [Task] underlying asynchronous computation
      attr_reader :task
      alias_method :to_task, :task

      # @api private
      def initialize(value)
        @task =
          case value
          when Task then value.fmap { ensure_result(_1) }
          when Result then Task.pure(value)
          else
            raise(
              TypeError,
              "expected a Dry::Monads::Result or a Dry::Monads::Task<Result>, " \
              "got #{value.class}"
            )
          end
      end

      # Returns the fulfilled Result or raises the Task's rejection reason.
      #
      # @return [Result]
      def value! = task.value!

      # Maps a successful business value. A Failure short-circuits the block.
      #
      # @return [ResultT]
      def fmap(&block)
        raise ArgumentError, "a block is required" unless block

        mapped = task.fmap do |result|
          next result if result.failure?

          value = block.call(result.success)
          ensure_fmapped_value(value)
          Result::Success.new(value)
        end

        self.class.new(mapped)
      end

      # Composes another asynchronous or synchronous Result computation.
      # A business Failure short-circuits the block; a Task rejection remains
      # a Task rejection.
      #
      # @return [ResultT]
      def bind(&block)
        raise ArgumentError, "a block is required" unless block

        bound = task.bind do |result|
          next Task.pure(result) if result.failure?

          lift_nested(block.call(result.success))
        end

        self.class.new(bound)
      end

      # Blocks until the underlying Task completes.
      #
      # @return [ResultT]
      def wait(...) = tap { task.wait(...) }

      # @return [Boolean]
      def complete? = task.complete?

      # @return [Class]
      def monad = ResultT

      # @return [ResultT]
      def to_monad = self

      # @return [String]
      def to_s = "ResultT(#{task})"
      alias_method :inspect, :to_s

      # @param other [Object]
      # @return [Boolean]
      def ==(other)
        other.is_a?(ResultT) && task == other.task
      end

      # ResultT constructors.
      #
      # @api public
      module Mixin
        # @private
        ResultT = ResultT

        module Constructors
          # Lifts a Result, Task<Result>, or ResultT.
          #
          # @return [ResultT]
          def ResultT(value = Undefined, &block)
            if value.equal?(Undefined)
              raise ArgumentError, "a value or a block is required" unless block

              ResultT.from_task(Task.new(&block))
            else
              ResultT[value]
            end
          end
        end

        include Constructors
      end

      private

      def ensure_result(result)
        return result if result.is_a?(Result)

        raise(
          TypeError,
          "expected the Task to fulfill with a Dry::Monads::Result " \
          "(Success or Failure), got #{result.class}"
        )
      end

      def ensure_fmapped_value(value)
        return unless value.is_a?(Result) || value.is_a?(Task) || value.is_a?(ResultT)

        raise(
          TypeError,
          "the block passed to ResultT#fmap returned #{value.inspect} (#{value.class}); " \
          "it must return a plain Success value. Use #bind for Result, Task<Result>, or ResultT"
        )
      end

      def lift_nested(value)
        case value
        when ResultT then value.task
        when Task then value.fmap { ensure_result(_1) }
        when Result then Task.pure(value)
        else
          raise(
            TypeError,
            "the block passed to ResultT#bind returned #{value.inspect} (#{value.class}); " \
            "expected Result, Task<Result>, or ResultT"
          )
        end
      end
    end

    require "dry/monads/registry"
    register_mixin(:result_t, ResultT::Mixin)
  end
end
