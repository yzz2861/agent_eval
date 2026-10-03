# frozen_string_literal: true

require "dry/transaction/result_matcher"
require "dry/transaction/stack"

module Dry
  module Transaction
    module InstanceMethods
      include Dry::Monads[:result]

      attr_reader :steps
      attr_reader :operations
      attr_reader :listeners
      attr_reader :stack

      def initialize(steps: self.class.steps, listeners: nil, container: nil, **operations)
        @container = container
        @operations = operations
        @steps = steps.map { |step|
          operation = step.branch? ? build_branch(step, **operations) : resolve_operation(step, **operations)
          step.with(operation: operation)
        }
        @operations = operations
        @stack = Stack.new(@steps)
        subscribe(listeners) unless listeners.nil?
      end

      def call(input = nil, &block)
        assert_step_arity

        result = stack.(Success(input))

        if block
          ResultMatcher.(result, &block)
        else
          result.or { |step_failure|
            # Unwrap the value from the StepFailure and return it directly
            Failure(step_failure.value)
          }
        end
      end

      def subscribe(listeners)
        @listeners = listeners

        if listeners.is_a?(Hash)
          listeners.each do |step_name, listener|
            step = steps.detect { |candidate| candidate.name == step_name }
            if step&.branch? && listener.is_a?(Hash)
              subscribe_branch(step.branch_runner, listener)
            else
              step&.subscribe(listener)
            end
          end
        else
          steps.each do |step|
            step.branch_runner.listeners = listeners if step.branch?
            step.subscribe(listeners)
          end
        end
      end

      def with_step_args(**step_args)
        assert_valid_step_args(step_args)

        new_steps = steps.map { |step|
          if step.branch?
            operation = step.branch_runner.dup
            operation.step_args = step_args[step.name] || {}
            operation.listeners = listeners
            step.with(operation: operation)
          elsif step_args[step.name]
            step.with(call_args: step_args[step.name])
          else
            step
          end
        }

        self.class.new(steps: new_steps, listeners: listeners, **operations)
      end

      private

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

      def build_branch(step, **operations)
        return duplicate_branch_runner(step) if step.branch_runner.is_a?(Branch)

        definitions = step.adapter.options.fetch(:branches)

        Branch.new(
          definitions: definitions,
          step_args: step_args_for_branch(step),
          resolve_step: method(:resolve_nested_step),
          resolve_condition: method(:resolve_branch_condition),
          validate_steps: method(:assert_nested_step_arity)
        )
      end

      def duplicate_branch_runner(step)
        operation = step.branch_runner.dup
        operation.listeners = nil
        operation
      end

      def resolve_nested_step(step, **_operations)
        return step.with(operation: build_branch(step)) if step.branch?

        if step.external?
          resolve_nested_external_step(step)
        else
          step.with(operation: resolve_operation(step, **@operations))
        end
      end

      def resolve_nested_external_step(step)
        operation_name = step.operation_name

        if @operations[step.name]&.respond_to?(:call)
          step.with(operation: @operations[step.name])
        elsif @operations.key?(step.name)
          raise InvalidStepError, step.name
        elsif container_key?(operation_name)
          operation = @container[operation_name]
          raise InvalidStepError, step.name unless operation.respond_to?(:call)

          step.with(operation: operation)
        else
          raise MissingStepError, step.name
        end
      end

      def resolve_branch_condition(condition)
        callable = if condition.respond_to?(:call)
                     condition
                   elsif container_key?(condition)
                     @container[condition]
                   else
                     method(condition)
                   end

        raise InvalidStepError, condition unless callable.respond_to?(:call)

        Callable[callable]
      end

      def step_args_for_branch(_step)
        {}
      end

      def assert_nested_step_arity(steps)
        steps.each do |step|
          required = step.arity >= 0 ? step.arity : ~step.arity
          supplied = step.call_args.length + 1

          raise ArgumentError, "not enough arguments supplied for step +#{step.name}+" if required > supplied
        end
      end

      def container_key?(name)
        return false if @container.nil?
        if @container.respond_to?(:key?)
          @container.key?(name)
        elsif @container.is_a?(Hash)
          @container.key?(name)
        else
          true
        end
      end

      def subscribe_branch(branch, listeners)
        branch.listeners = listeners
      end

      def assert_valid_step_args(step_args)
        step_args.each_key do |step_name|
          known_step = steps.detect { |step| step.name == step_name }

          unless known_step
            raise ArgumentError, "+#{step_name}+ is not a valid step name"
          end

          if known_step.branch? && !step_args[step_name].is_a?(Hash)
            raise ArgumentError, "+#{step_name}+ is a branch step and accepts nested step arguments as a Hash"
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
