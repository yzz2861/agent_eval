# frozen_string_literal: true

require "dry/transaction/result_matcher"
require "dry/transaction/stack"
require "dry/transaction/branch_operation"

module Dry
  module Transaction
    module InstanceMethods
      include Dry::Monads[:result]

      attr_reader :steps
      attr_reader :operations
      attr_reader :listeners
      attr_reader :stack

      def initialize(steps: self.class.steps, listeners: nil, **operations)
        @steps = steps.map { |step|
          operation = resolve_operation(step, **operations)
          step.with(operation: operation)
        }
        @operations = operations
        @stack = Stack.new(@steps)
        subscribe(listeners) unless listeners.nil?
      end

      def operations_container
        self.class.operations_container
      end

      def call(input = nil, &block)
        assert_step_arity

        result = stack.(Success(input))

        if block
          ResultMatcher.(result, &block)
        else
          result.or { |failure|
            # Unwrap the value from the StepFailure and return it directly
            Failure(failure.is_a?(StepFailure) ? unwrap_step_failure(failure) : failure)
          }
        end
      end

      def subscribe(listeners)
        @listeners = listeners

        if listeners.is_a?(Hash)
          listeners.each do |step_name, listener|
            step = steps.detect { |candidate| candidate.name == step_name }

            if step
              step.subscribe(listener)
            else
              branch_step = steps.detect { |candidate| candidate.has_named_descendant?(step_name) }
              branch_step.add_nested_listener(step_name, listener) if branch_step
            end
          end
        else
          steps.each do |step|
            step.subscribe(listeners)
            step.add_nested_listener(:*, listeners) if step.branch?
          end
        end
      end

      def with_step_args(**step_args)
        assert_valid_step_args(step_args)

        new_steps = steps.map { |step|
          if step_args[step.name]
            preserve_listeners(step, apply_step_args(step, step_args.fetch(step.name)))
          elsif (nested_args = nested_step_args(step, step_args)).any?
            preserve_listeners(step, apply_step_args(step, nested_args, false))
          else
            step
          end
        }

        self.class.new(steps: new_steps, listeners: listeners, **operations)
      end

      private

      def preserve_listeners(original_step, new_step)
        return new_step unless original_step.branch?

        new_step.with(nested_listeners: original_step.nested_listeners.dup)
      end

      def unwrap_step_failure(failure)
        value = failure.value
        value.is_a?(StepFailure) ? unwrap_step_failure(value) : value
      end

      def respond_to_missing?(name, _include_private = false)
        steps.any? { |step| step.name == name }
      end

      def method_missing(name, *args, &block)
        step = steps.detect { |s| s.name == name }
        super unless step

        operation = operations[step.name]
        unless operation
          raise NotImplementedError,
            "no operation +#{step.operation_name}+ defined for step +#{step.name}+"
        end

        operation.(*args, &block)
      end

      def resolve_operation(step, **operations)
        if step.branch?
          return BranchOperation.new(step: step, transaction: self, operations: operations)
        end

        if step.internal? && operations[step.name]
          operations[step.name]
        elsif methods.include?(step.name) || private_methods.include?(step.name)
          method(step.name)
        elsif operations[step.name].respond_to?(:call)
          operations[step.name]
        elsif operations[step.name]
          raise InvalidStepError, step.name
        else
          raise MissingStepError, step.name
        end
      end

      def apply_step_args(step, args, scoped = true)
        unless args.is_a?(Hash)
          return step.with(call_args: args)
        end

        scoped_args = scoped ? validate_scoped_args(step, args) : {}
        assert_valid_scoped_step_args(step, scoped_args)

        child_step_args = {}
        step.branches.each do |branch|
          branch.steps.each do |child_step|
            values = []
            values.concat(Array(args[child_step.name]))
            values.concat(Array(scoped_args.dig(branch.name, child_step.name)))
            child_step_args[child_step.name] = values unless values.empty?
          end
        end

        step.with(child_step_args: child_step_args)
      end

      def validate_scoped_args(step, args)
        args.each_with_object({}) do |(branch_name, branch_args), memo|
          unless step.branches.any? { |branch| branch.name == branch_name }
            raise ArgumentError, "+#{branch_name}+ is not a valid branch name"
          end

          memo[branch_name] = branch_args
        end
      end

      def assert_valid_scoped_step_args(step, scoped_args)
        scoped_args.each do |branch_name, branch_args|
          branch = step.branches.detect { |candidate| candidate.name == branch_name }

          branch_args.each_key do |step_name|
            unless branch.steps.any? { |child_step| child_step.name == step_name }
              raise ArgumentError, "+#{step_name}+ is not a valid step name"
            end
          end
        end
      end

      def nested_step_args(step, step_args)
        step_args.each_with_object({}) do |(step_name, values), memo|
          next if step.name == step_name
          memo[step_name] = values if step.has_named_descendant?(step_name)
        end
      end

      def assert_valid_step_args(step_args)
        step_args.each_key do |step_name|
          step = steps.detect { |candidate| candidate.name == step_name }
          next if step

          unless steps.any? { |candidate| candidate.has_named_descendant?(step_name) }
            raise ArgumentError, "+#{step_name}+ is not a valid step name"
          end
        end
      end

      def assert_step_arity
        steps.each do |step|
          num_args_required = step.arity >= 0 ? step.arity : ~step.arity
          num_args_supplied = step.call_args.length + 1 # add 1 for main `input`

          if num_args_required > num_args_supplied
            raise ArgumentError, "not enough arguments supplied for step +#{step.name}+"
          end
        end
      end
    end
  end
end
