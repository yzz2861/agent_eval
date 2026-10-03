# frozen_string_literal: true

module Dry
  module Transaction
    # A wrapper for storing together the step that failed
    # and value describing the failure.
    #
    # When a failure propagates out of nested transactions, #path holds the
    # full chain of step names (outermost first) leading to the failure, while
    # #step remains the innermost step that actually failed and #value remains
    # the failure value exactly as the operation returned it.
    class StepFailure
      attr_reader :step
      attr_reader :value
      attr_reader :path

      # @api private
      def self.call(step, value)
        # rubocop:disable Style/CaseEquality
        if self === value
          if value.nested?
            yield value.value
            value.prepend(step)
          else
            value
          end
        else
          yield value
          new(step, value)
        end
        # rubocop:enable Style/CaseEquality
      end

      def initialize(step, value, path: [step.name], nested: false)
        @step = step
        @value = value
        @path = path.freeze
        @nested = nested
      end

      # Returns a copy to be propagated across a nested transaction's
      # boundary, so the enclosing transaction's step can attribute the
      # failure to its full step path.
      #
      # @api private
      def nested
        self.class.new(step, value, path: path, nested: true)
      end

      # @api private
      def nested?
        @nested
      end

      # Returns a copy with the given enclosing step prepended to the path.
      # The source step and failure value are preserved.
      #
      # @api private
      def prepend(step)
        self.class.new(self.step, value, path: [step.name, *path])
      end
    end
  end
end
