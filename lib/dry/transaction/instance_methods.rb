# frozen_string_literal: true

require "dry/transaction/result_matcher"
require "dry/transaction/stack"

module Dry
  module Transaction
    module InstanceMethods
      # @api private
      NESTING_DEPTH_KEY = :__dry_transaction_nesting_depth__

      # Returns true when called from within another transaction's execution,
      # i.e. the transaction is being used as a nested (sub-)transaction.
      #
      # @api private
      def self.nested_call?
        Thread.current[NESTING_DEPTH_KEY].to_i.positive?
      end

      # Tracks transaction execution so nested transactions can be detected.
      #
      # @api private
      def self.track_nesting
        Thread.current[NESTING_DEPTH_KEY] = Thread.current[NESTING_DEPTH_KEY].to_i + 1
        yield
      ensure
        Thread.current[NESTING_DEPTH_KEY] = Thread.current[NESTING_DEPTH_KEY].to_i - 1
      end

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

      def call(input = nil, &block)
        assert_step_arity

        top_level = !InstanceMethods.nested_call?
        result = InstanceMethods.track_nesting { stack.(Success(input)) }

        if block
          ResultMatcher.(result, &block)
        elsif top_level
          result.or { |step_failure|
            # Unwrap the value from the StepFailure and return it directly
            Failure(step_failure.value)
          }
        else
          result.or { |step_failure|
            # Keep the StepFailure (with its step path) so the enclosing
            # transaction's step can attribute the failure to its full path
            Failure(step_failure.nested)
          }
        end
      end

      def subscribe(listeners)
        @listeners = listeners

        if listeners.is_a?(Hash)
          listeners.each do |step_name, listener|
            steps.detect { |step| step.name == step_name }.subscribe(listener)
          end
        else
          steps.each do |step|
            step.subscribe(listeners)
          end
        end
      end

      def with_step_args(**step_args)
        assert_valid_step_args(step_args)

        new_steps = steps.map { |step|
          if step_args[step.name]
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
