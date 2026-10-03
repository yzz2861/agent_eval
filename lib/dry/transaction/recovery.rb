# frozen_string_literal: true

require "dry/events"
require "dry/monads"
require "dry/transaction/callable"
require "dry/transaction/errors"
require "dry/transaction/step_failure"
require "dry/transaction/recovery_failure"

module Dry
  module Transaction
    # @api private
    class Recovery
      MATCH_ALL = Object.new.freeze
      UNDEFINED = Object.new.freeze

      include Dry::Events::Publisher["dry.transaction.recovery.#{object_id}"]
      include Dry::Monads[:result]

      register_event(:step)
      register_event(:step_succeeded)
      register_event(:step_failed)

      attr_reader :step_name
      attr_reader :name
      attr_reader :operation_name
      attr_reader :failure
      attr_reader :operation

      def initialize(step_name:, name: nil, operation_name: nil, failure: MATCH_ALL,
        operation: nil, continue: nil, context: nil, listener_holder: nil)
        @step_name = step_name
        @name = name || "recover_#{step_name}".to_sym
        @operation_name = operation_name
        @failure = failure
        @operation = Callable[operation]
        @continue = continue || -> result { result }
        @context = context
        @listener_holder = listener_holder || {}
      end

      def with(operation: UNDEFINED, continue: UNDEFINED, context: UNDEFINED)
        return self if operation == UNDEFINED && continue == UNDEFINED && context == UNDEFINED

        self.class.new(
          step_name: step_name,
          name: name,
          operation_name: operation_name,
          failure: failure,
          operation: operation == UNDEFINED ? @operation : operation,
          continue: continue == UNDEFINED ? @continue : continue,
          context: context == UNDEFINED ? @context : context,
          listener_holder: @listener_holder
        ).tap { |copy|
          copy.instance_variable_set(:@__bus__, __bus__)
        }
      end

      def subscribe(listener)
        @listener = listener
        @listener_holder[:listener] = listener
        super
      end

      def call(step_failure, input, continue = @continue)
        return Failure(step_failure) unless matches?(step_failure.value)

        args = [step_failure.value, input]
        publish(:step, step_name: name, args: args)

        result = call_operation(step_failure.value, input, recovery_listener)
        unless result.is_a?(Dry::Monads::Result)
          raise InvalidResultError, name
        end

        if result.success?
          value = result.value!
          publish(:step_succeeded, step_name: name, args: args, value: value)
          continue.(Success(value))
        else
          value = RecoveryFailure.new(step_failure.value, result.failure)
          Failure(
            StepFailure.new(self, value).tap {
              publish(:step_failed, step_name: name, args: args, value: value)
            }
          )
        end
      end

      def matches?(value)
        return true if failure.equal?(MATCH_ALL)

        matchers = failure.is_a?(Array) ? failure : [failure]
        matchers.any? { |matcher| matches_value?(matcher, value) }
      end

      def internal?
        !external?
      end

      def external?
        !!operation_name
      end

      def arity
        operation.arity
      end

      private

      def recovery_listener
        @listener_holder[:listener] || @listener
      end

      def call_operation(failure_value, input, listener = nil)
        if transaction_operation?
          transaction = transaction_operation
          transaction.steps.each { |step| step.subscribe(listener) } if listener
          begin
            transaction.call([failure_value, input])
          ensure
            transaction.steps.each { |step| step.unsubscribe(listener) } if listener
          end
        else
          operation.operation.call(failure_value, input)
        end
      end

      def transaction_operation?
        !transaction_operation.nil?
      end

      def transaction_operation
        target = operation.respond_to?(:operation) ? operation.operation : operation
        target = target.receiver if target.is_a?(Method) && target.owner == InstanceMethods
        return unless target.is_a?(InstanceMethods)
        return if @context && target.equal?(@context)

        target
      end

      def matches_value?(matcher, value)
        return matcher === value if matcher.is_a?(Module)

        matcher == value || case_matches?(matcher, value)
      end

      def case_matches?(matcher, value)
        matcher === value
      end
    end
  end
end
