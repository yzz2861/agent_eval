# frozen_string_literal: true

require "dry/monads"
require "dry/transaction/errors"
require "dry/transaction/recovery_failure"

module Dry
  module Transaction
    # @api private
    class Recovery
      UNDEFINED = Object.new.freeze

      include Dry::Monads[:result]

      attr_reader :name
      attr_reader :step_name
      attr_reader :operation_name
      attr_reader :failure_matcher

      def initialize(name:, step_name:, operation_name:, failure_matcher:, operation: nil)
        @name = name
        @step_name = step_name
        @operation_name = operation_name
        @failure_matcher = failure_matcher
        @operation = operation
      end

      def with(operation:)
        self.class.new(
          name: name,
          step_name: step_name,
          operation_name: operation_name,
          failure_matcher: failure_matcher,
          operation: operation
        )
      end

      def match?(value)
        if failure_matcher.is_a?(Array)
          failure_matcher.any? { |matcher| matcher === value }
        elsif failure_matcher.is_a?(Proc)
          failure_matcher.call(value)
        else
          failure_matcher === value
        end
      end

      def call(step_failure, step_input)
        result = call_operation(step_failure.value, step_input)

        unless result.is_a?(Dry::Monads::Result)
          raise InvalidResultError, name
        end

        result.or do |recovery_value|
          Failure(
            RecoveryFailure.new(
              step: step_failure.step,
              recovery: self,
              value: step_failure.value,
              recovery_value: recovery_value
            )
          )
        end
      end

      def internal?
        !external?
      end

      def external?
        !!operation_name
      end

      private

      def call_operation(failure, input)
        payload = {failure: failure, input: input}

        if transaction_operation?
          @operation.call(payload)
        elsif accepts_keywords?
          @operation.call(**keyword_arguments(payload))
        elsif single_positional_parameter?
          @operation.call(payload)
        else
          @operation.call(failure, input)
        end
      end

      def transaction_operation?
        @operation.respond_to?(:steps) && @operation.respond_to?(:call)
      end

      def accepts_keywords?
        keyword_names.any?
      end

      def keyword_arguments(payload)
        if keyword_names.sort == %i[failure input]
          payload
        else
          payload.select { |key, _| keyword_names.include?(key) }
        end
      end

      def keyword_names
        operation_target.parameters.filter_map { |type, name|
          name if type == :key || type == :keyreq
        }
      end

      def single_positional_parameter?
        positional_parameters = operation_target.parameters.reject { |type,| type == :block }

        positional_parameters.size == 1 && %i[req opt].include?(positional_parameters.first.first)
      end

      def operation_target
        if @operation.respond_to?(:parameters)
          @operation
        else
          @operation.method(:call)
        end
      end
    end
  end
end
