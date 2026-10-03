# frozen_string_literal: true

require "dry/transaction/stack"
require "dry/transaction/branch_definition"

module Dry
  module Transaction
    # @api private
    class BranchOperation
      include Dry::Monads[:result]

      BranchOutcome = Data.define(:name, :result)

      attr_reader :branches

      def initialize(step:, transaction:, operations:)
        @step = step
        @transaction = transaction
        @operations = operations
        @branches = step.branches
      end

      def call(input)
        branch = select_branch(input)
        steps = branch.steps.map { |child_step| build_step(child_step, branch) }
        assert_step_arity(steps)

        result = Stack.new(steps).call(Success(input))
        BranchOutcome.new(branch.name, result)
      end

      private

      def select_branch(input)
        branches.each do |branch|
          next if branch.fallback?

          condition = resolve_condition(branch)
          result = condition.call(input)
          return branch if result == true || result.respond_to?(:success?) && result.success?
        end

        branches.detect(&:fallback?) || raise(NoBranchMatchedError, @step.name)
      end

      def resolve_condition(branch)
        condition = branch.condition

        return condition if condition.respond_to?(:call)
        return @transaction.method(condition) if @transaction.respond_to?(condition, true)

        operation = @operations[branch.name]
        return operation if operation.respond_to?(:call)

        operation_name = branch.operation_name || condition
        container = @transaction.operations_container
        if container&.key?(operation_name)
          return container[operation_name]
        end

        raise MissingStepError, branch.name
      end

      def build_step(child_step, branch)
        operation = resolve_step_operation(child_step)
        call_args = child_step.call_args + Array(@step.child_step_args[child_step.name])

        resolved_step = child_step.with(
          operation: operation,
          call_args: call_args,
          parent_step: @step,
          branch_name: branch.name
        )

        attach_listeners(resolved_step, branch)
        resolved_step
      end

      def attach_listeners(step, branch)
        listeners = []

        @step.nested_listeners.fetch(:*, []).each do |listener|
          listeners << ForwardingListener.new(@step, listener)
        end
        listeners.concat(@step.nested_listeners.fetch(step.name, []))
        listeners.concat(@step.nested_listeners.fetch(branch.name, []))

        listeners.uniq { |listener| listener.is_a?(ForwardingListener) ? listener.listener_object : listener }.each do |listener|
          step.subscribe(listener)
        end
      end

      def resolve_step_operation(step)
        if step.internal? && @operations[step.name]
          @operations[step.name]
        elsif @operations[step.name].respond_to?(:call)
          @operations[step.name]
        elsif @transaction.respond_to?(step.name, true)
          @transaction.method(step.name)
        elsif step.operation_name && @transaction.operations_container&.key?(step.operation_name)
          @transaction.operations_container[step.operation_name]
        elsif @operations[step.name]
          raise InvalidStepError, step.name
        else
          raise MissingStepError, step.name
        end
      end

      class ForwardingListener
        attr_reader :listener_object

        def initialize(step, listener = nil)
          @step = step
          @listener = listener_object = listener
        end

        def on_step(event)
          @step.publish(:step, **event.to_h)
          @listener&.on_step(event)
        end

        def on_step_succeeded(event)
          @step.publish(:step_succeeded, **event.to_h)
          @listener&.on_step_succeeded(event)
        end

        def on_step_failed(event)
          @step.publish(:step_failed, **event.to_h)
          @listener&.on_step_failed(event)
        end
      end

      def assert_step_arity(steps)
        steps.each do |step|
          required = step.arity >= 0 ? step.arity : ~step.arity
          supplied = step.call_args.length + 1

          if required > supplied
            raise ArgumentError, "not enough arguments supplied for step +#{step.name}+"
          end
        end
      end
    end
  end
end
