# frozen_string_literal: true

require "dry/transaction/step_failure"

module Dry
  module Transaction
    # @api public
    class RecoveryFailure < StepFailure
      attr_reader :recovery_failure
      attr_reader :recovery_operation

      alias_method :original_failure, :value
      alias_method :recovery_value, :recovery_failure
      alias_method :recovery, :recovery_operation

      def initialize(step:, recovery:, value:, recovery_value:)
        super(step, value)
        @recovery_operation = recovery
        @recovery_failure = recovery_value
      end

      def to_h
        {original_failure: value, recovery_failure: recovery_failure}
      end

      def to_a
        [value, recovery_failure]
      end

      def deconstruct
        to_a
      end

      def deconstruct_keys(keys)
        to_h.slice(*Array(keys))
      end
    end
  end
end
