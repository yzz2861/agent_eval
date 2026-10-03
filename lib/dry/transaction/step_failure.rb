# frozen_string_literal: true

module Dry
  module Transaction
    # A wrapper for storing together the step that failed
    # and value describing the failure.
    class StepFailure
      attr_reader :step
      attr_reader :value
      attr_reader :branch_name
      attr_reader :original_failure

      # @api private
      def self.call(step, value)
        # rubocop:disable Style/CaseEquality
        if self === value
          value
        else
          yield
          new(step, value)
        end
        # rubocop:enable Style/CaseEquality
      end

      def initialize(step, value, branch_name: nil, original_failure: nil)
        @step = step
        @value = value
        @branch_name = branch_name
        @original_failure = original_failure || self
      end

      def branch_failure?
        !branch_name.nil?
      end

      def original_step
        failure = self
        failure = failure.original_failure while failure.original_failure != failure
        failure.step
      end
      alias_method :failure_step, :original_step

      def branch_names
        names = []
        failure = self

        while failure.branch_failure?
          names.unshift(failure.branch_name)
          failure = failure.original_failure
        end

        names
      end

      def respond_to_missing?(name, include_private = false)
        original_failure.respond_to?(name, include_private) || super
      end

      def method_missing(name, *args, &block)
        if original_failure.respond_to?(name)
          original_failure.public_send(name, *args, &block)
        else
          super
        end
      end
    end
  end
end
