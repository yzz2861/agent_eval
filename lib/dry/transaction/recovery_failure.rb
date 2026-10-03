# frozen_string_literal: true

module Dry
  module Transaction
    # Stores the original failure and the failure from an attempted recovery.
    class RecoveryFailure < Array
      attr_reader :cause
      attr_reader :value

      def initialize(cause, value)
        super(2)
        @cause = cause
        @value = value
        replace([cause, value])
      end

      def original_failure
        cause
      end

      def recovery_failure
        value
      end

      def original_value
        cause
      end

      def recovery_value
        value
      end

      def deconstruct_keys(keys)
        {cause: cause, value: value}.slice(*keys)
      end

      def to_s
        value.to_s
      end
    end
  end
end
