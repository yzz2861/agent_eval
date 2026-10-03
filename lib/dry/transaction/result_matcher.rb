# frozen_string_literal: true

require "dry/matcher"

module Dry
  module Transaction
    ResultMatcher = Dry::Matcher.new(
      success: Dry::Matcher::Case.new(
        match: -> result { result.success? },
        resolve: -> result { result.value! }
      ),
      failure: Dry::Matcher::Case.new(
        match: -> result, step_name = nil {
          if step_name
            result.failure? && matching_failure?(result.failure, step_name)
          else
            result.failure?
          end
        },
        resolve: -> result { failure_value(result.failure) }
      )
    )

    class << self
      private

      def matching_failure?(failure, step_name)
        return false unless failure.is_a?(StepFailure)

        failure.step.name == step_name ||
          failure.is_a?(BranchFailure) && failure.branch_name == step_name ||
          matching_failure?(failure.value, step_name)
      end

      def failure_value(failure)
        value = failure.value
        value.is_a?(StepFailure) ? failure_value(value) : value
      end
    end
  end
end
