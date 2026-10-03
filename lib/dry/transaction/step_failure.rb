# frozen_string_literal: true

module Dry
  module Transaction
    # A wrapper for storing together the step that failed
    # and value describing the failure.
    class StepFailure
      attr_reader :step
      attr_reader :value

      # The full path of step names leading to the failure, ordered from
      # the outermost step down to the step that actually failed.
      #
      # For failures raised within nested transactions, the path contains
      # one entry per level of nesting, e.g. +[:process, :validate]+.
      attr_reader :path

      # @api private
      def self.call(step, value)
        # rubocop:disable Style/CaseEquality
        if self === value
          value.prepend(step)
        else
          yield
          new(step, value)
        end
        # rubocop:enable Style/CaseEquality
      end

      def initialize(step, value, path = nil)
        @step = step
        @value = value
        @path = path || [step.name]
      end

      # Returns a new StepFailure for the same failure, with the given
      # step added to the front of the path. The original (innermost) step
      # and the failure value are preserved as-is.
      #
      # @api private
      def prepend(step)
        self.class.new(self.step, value, [step.name, *path])
      end
    end
  end
end
