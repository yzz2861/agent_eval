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
      attr_reader :branch_names

      def initialize(adapter:, name:, operation_name:, options:, operation: nil, call_args: [], branch_names: [])
        @adapter = StepAdapter[adapter, operation,
          {**options, step_name: name, operation_name: operation_name}]
        @name = name
        @operation_name = operation_name
        @call_args = call_args
        @branch_names = branch_names
      end
      # rubocop:enable Metrics/ParameterLists

      def with(operation: UNDEFINED, call_args: UNDEFINED, branch_names: UNDEFINED)
        return self if operation == UNDEFINED && call_args == UNDEFINED && branch_names == UNDEFINED

        new_operation = operation == UNDEFINED ? adapter.operation : operation
        new_call_args = call_args == UNDEFINED ? self.call_args : Array(call_args)
        new_branch_names = branch_names == UNDEFINED ? self.branch_names : branch_names

        self.class.new(
          adapter: adapter,
          name: name,
          operation_name: operation_name,
          operation: new_operation,
          options: adapter.options,
          call_args: new_call_args,
          branch_names: new_branch_names
        )
      end

      def call(input, continue = RETURN)
        args = [input, *call_args]

        if branch?
          call_branch(args, continue)
        elsif adapter.yields?
          with_broadcast(args) { adapter.(args, &continue) }
        else
          continue.(with_broadcast(args) { adapter.(args) })
        end
      end

      def with_broadcast(args)
        publish_step_event(:step, args)

        result = yield

        publish_result(result, args)
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

      def branch_runner
        adapter.operation if branch?
      end

      def branch?
        adapter.options.key?(:branches)
      end

      private

      def call_branch(args, continue)
        publish_step_event(:step, args)

        adapter.(args).fmap do |outcome|
          publish_step_event(:step_succeeded, args,
            value: outcome.value,
            branch_name: outcome.name,
            branch_names: branch_names + [outcome.name]
          )
          outcome.value
        end.or do |outcome|
          return Failure(branch_failure(outcome, args))
        end.bind do |value|
          continue.call(Success(value))
        end
      end

      def branch_failure(outcome, args)
        if outcome.is_a?(Branch::NoMatch)
          publish_step_event(:step_failed, args,
            value: outcome.input,
            branch_name: nil,
            original_step_name: nil
          )
          return StepFailure.new(self, outcome.input)
        end

        failure = StepFailure.new(
          self,
          outcome.step_failure.value,
          branch_name: outcome.name,
          original_failure: outcome.step_failure
        )

        publish_step_event(:step_failed, args,
          value: failure.value,
          branch_name: outcome.name,
          branch_names: branch_names + [outcome.name],
          original_step_name: outcome.step_failure.step.name
        )
        failure
      end

      def publish_result(result, args)
        result.fmap { |value|
          publish_step_event(:step_succeeded, args,
            value: value,
            branch_name: nil
          )
          value
        }.or { |value|
          Failure(
            StepFailure.(self, value) {
              publish_step_event(:step_failed, args,
                value: value,
                branch_name: nil,
                original_step_name: nil
              )
            }
          )
        }
      end

      def publish_step_event(event, args, **payload)
        publish(event, step_name: name, args: args, branch_names: branch_names, **payload)
      end
    end
  end
end
