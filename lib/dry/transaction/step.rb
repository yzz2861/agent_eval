# frozen_string_literal: true

require "dry/transaction/step_failure"
require "dry/transaction/step_adapter"
require "dry/transaction/branch_failure"

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
      attr_reader :branches
      attr_reader :child_step_args
      attr_reader :nested_listeners
      attr_reader :parent_step
      attr_reader :branch_name

      def initialize(
        adapter:,
        name:,
        operation_name:,
        options:,
        operation: nil,
        call_args: [],
        branches: nil,
        child_step_args: nil,
        nested_listeners: nil,
        parent_step: nil,
        branch_name: nil
      )
        @adapter = StepAdapter[adapter, operation,
          {**options, step_name: name, operation_name: operation_name}]
        @name = name
        @operation_name = operation_name
        @call_args = call_args
        @branches = branches || options.fetch(:branches, [])
        @child_step_args = child_step_args || options.fetch(:child_step_args, {})
        @nested_listeners = nested_listeners || Hash.new { |hash, key| hash[key] = [] }
        @parent_step = parent_step
        @branch_name = branch_name
      end
      # rubocop:enable Metrics/ParameterLists

      def with(
        operation: UNDEFINED,
        call_args: UNDEFINED,
        branches: UNDEFINED,
        child_step_args: UNDEFINED,
        nested_listeners: UNDEFINED,
        parent_step: UNDEFINED,
        branch_name: UNDEFINED
      )
        return self if [operation, call_args, branches, child_step_args,
          nested_listeners, parent_step, branch_name].all?(UNDEFINED)

        new_operation = operation == UNDEFINED ? adapter.operation : operation
        new_call_args = call_args == UNDEFINED ? self.call_args : Array(call_args)
        new_branches = branches == UNDEFINED ? self.branches : branches
        new_child_step_args = child_step_args == UNDEFINED ? self.child_step_args : child_step_args
        new_nested_listeners = nested_listeners == UNDEFINED ? self.nested_listeners : nested_listeners
        new_parent_step = parent_step == UNDEFINED ? self.parent_step : parent_step
        new_branch_name = branch_name == UNDEFINED ? self.branch_name : branch_name

        self.class.new(
          adapter: adapter,
          name: name,
          operation_name: operation_name,
          operation: new_operation,
          options: adapter.options,
          call_args: new_call_args,
          branches: new_branches,
          child_step_args: new_child_step_args,
          nested_listeners: new_nested_listeners,
          parent_step: new_parent_step,
          branch_name: new_branch_name
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

      def branch?
        !branches.empty?
      end

      def add_nested_listener(name, listener)
        nested_listeners[name] << listener
      end

      def named_descendants(step_name)
        return enum_for(:named_descendants, step_name) unless block_given?

        branches.each do |branch|
          yield(branch.steps.first, branch) if branch.name == step_name && branch.steps.any?
          branch.steps.each do |step|
            yield(step, branch) if step.name == step_name
            step.named_descendants(step_name) { |descendant, descendant_branch| yield(descendant, descendant_branch) }
          end
        end
      end

      def has_named_descendant?(step_name)
        named_descendants(step_name).any?
      end

      def with_broadcast(args)
        publish(:step, step_name: name, args: args, **event_options)

        yield.fmap { |value|
          publish(:step_succeeded, step_name: name, args: args, value: value, **event_options)
          value
        }.or { |value|
          Failure(
            StepFailure.(self, value) {
              publish(:step_failed, step_name: name, args: args, value: value, **event_options)
            }
          )
        }
      end

      def event_options
        branch_name ? {branch_name: branch_name} : {}
      end

      def call_branch(args, continue)
        publish(:step, step_name: name, args: args)

        outcome = adapter.(args)
        continued = continue.(broadcast_branch_result(outcome.result, args, outcome.name))
        unwrap_continuation_result(continued)
      end

      def unwrap_continuation_result(result)
        result.is_a?(Dry::Monads::Result::Success) && result.value!.is_a?(Dry::Monads::Result) ? result.value! : result
      end

      def broadcast_branch_result(result, args, branch_name)
        result.fmap { |value|
          publish(:step_succeeded,
            step_name: name,
            args: args,
            value: value,
            branch_name: branch_name)
          value
        }.or { |value|
          Failure(
            if value.is_a?(StepFailure)
              publish(:step_failed,
                step_name: name,
                args: args,
                value: value,
                branch_name: branch_name)
              BranchFailure.new(self, value, branch_name)
            else
              StepFailure.(self, value) {
                publish(:step_failed,
                  step_name: name,
                  args: args,
                  value: value,
                  branch_name: branch_name)
              }
            end
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
    end
  end
end
