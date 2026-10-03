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
      attr_reader :recoveries

      def initialize(steps: self.class.steps, listeners: nil, **operations)
        recovery_definitions = self.class.respond_to?(:recoveries) ? self.class.recoveries : []
        assert_valid_recoveries(steps, recovery_definitions)

        @recoveries = recovery_definitions.map do |recovery|
          recovery.with(
            operation: resolve_operation(recovery, **operations),
            context: self
          )
        end

        resolved_steps = steps.map { |step|
          step.with(operation: resolve_operation(step, **operations))
        }
        @steps = Array.new(resolved_steps.length)

        resolved_steps.each_with_index do |step, index|
          step_recoveries = @recoveries.select { |recovery| recovery.step_name == step.name }

          @steps[index] = step.with(
            recoveries: build_step_recoveries(step_recoveries, index, resolved_steps.length - index - 1)
          )
        end
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
            operation_callables.detect { |callable| callable.name == step_name }&.subscribe(listener)
          end
        else
          operation_callables.each { |callable| callable.subscribe(listeners) }
        end
      end

      def with_step_args(**step_args)
        assert_valid_step_args(step_args)

        new_steps = steps.map { |step|
          if step_args[step.name]
            step.with(
              call_args: step_args[step.name],
              recoveries: step.recoveries
            )
          else
            step
          end
        }

        self.class.new(steps: new_steps, listeners: listeners, **operations)
      end

      private

      def operation_callables
        steps + recoveries
      end

      def build_step_recoveries(recoveries, index, suffix_size)
        suffix_start = index + 1

        recoveries.map do |recovery|
          recovery.with(continue: -> result {
            suffix = steps[suffix_start, suffix_size]
            Stack.continue(suffix).(result)
          })
        end
      end

      def assert_valid_recoveries(steps, definitions)
        step_names = steps.map(&:name)

        definitions.each do |recovery|
          unless step_names.include?(recovery.step_name)
            raise ArgumentError, "+:#{recovery.step_name}+ is not a valid step name"
          end
        end

        used_names = (step_names + definitions.map(&:name)).tally.select { |_, count| count > 1 }.keys
        unless used_names.empty?
          raise ArgumentError, "+#{used_names.first}+ is already used by a step"
        end
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
        if step.is_a?(Recovery) && step.operation
          step.operation
        elsif operations[step.name] && step.internal?
          operations[step.name]
        elsif step.respond_to?(:operation) && step.operation
          step.operation
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

      def assert_valid_step_args(step_args)
        step_args.each_key do |step_name|
          unless steps.any? { |step| step.name == step_name }
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
