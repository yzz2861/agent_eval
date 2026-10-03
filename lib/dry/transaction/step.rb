# frozen_string_literal: true

require "dry/transaction/step_failure"
require "dry/transaction/step_adapter"

module Dry
  module Transaction
    # @api private
    class Step
      UNDEFINED = Object.new.freeze
      RETURN = -> x { x }

      include Dry::Events::Publisher[name || object_id]
      include Dry::Monads[:result]

      register_event(:step)
      register_event(:step_succeeded)
      register_event(:step_failed)

      attr_reader :adapter
      attr_reader :name
      attr_reader :operation_name
      attr_reader :call_args
      attr_reader :recoveries

      # rubocop:disable Metrics/ParameterLists
      def initialize(adapter:, name:, operation_name:, options:, operation: nil,
        call_args: [], recoveries: [])
        @adapter = StepAdapter[adapter, operation,
          {**options, step_name: name, operation_name: operation_name}]
        @name = name
        @operation_name = operation_name
        @call_args = call_args
        @recoveries = recoveries
      end
      # rubocop:enable Metrics/ParameterLists

      def with(operation: UNDEFINED, call_args: UNDEFINED, recoveries: UNDEFINED)
        if operation == UNDEFINED && call_args == UNDEFINED && recoveries == UNDEFINED
          return self
        end

        new_operation = operation == UNDEFINED ? adapter.operation : operation
        new_call_args = call_args == UNDEFINED ? self.call_args : Array(call_args)
        new_recoveries = recoveries == UNDEFINED ? @recoveries : recoveries

        self.class.new(
          adapter: adapter,
          name: name,
          operation_name: operation_name,
          operation: new_operation,
          options: adapter.options,
          call_args: new_call_args,
          recoveries: new_recoveries
        )
      end

      def call(input, continue = RETURN)
        args = [input, *call_args]

        if adapter.yields?
          continued = false
          result = with_broadcast(args) do
            adapter.(args) do |monad|
              monad.bind do |value|
                continued = true
                continue.(Success(value))
              end
            end
          end

          return result if continued || result.success?
          recover(result, input) || result
        else
          result = with_broadcast(args) { adapter.(args) }

          if result.success?
            continue.(result)
          else
            recover(result, input) || result
          end
        end
      end

      def with_broadcast(args)
        publish(:step, step_name: name, args: args)

        yield.fmap { |value|
          publish(:step_succeeded, step_name: name, args: args, value: value)
          value
        }.or { |value|
          Failure(
            StepFailure.(self, value) {
              publish(:step_failed, step_name: name, args: args, value: value)
            }
          )
        }
      end

      def internal?
        !external?
      end

      def external?
        !!operation_name
      end

      def arity
        adapter.operation.arity
      end

      def operation
        adapter.operation
      end

      private

      def recover(result, input)
        step_failure = result.failure
        return unless step_failure.is_a?(StepFailure) && step_failure.step.equal?(self)

        recovery = @recoveries.find { |candidate| candidate.matches?(step_failure.value) }
        recovery&.call(step_failure, input)
      end
    end
  end
end
