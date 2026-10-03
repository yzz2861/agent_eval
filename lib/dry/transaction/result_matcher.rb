# frozen_string_literal: true

require "dry/matcher"

module Dry
  module Transaction
    module ResultMatching
      module_function

      def failure_chain(failure)
        chain = [failure]

        while failure.respond_to?(:original_failure) && failure.original_failure != failure
          failure = failure.original_failure
          chain << failure
        end

        chain
      end
    end

    ResultMatcher = Dry::Matcher.new(
      success: Dry::Matcher::Case.new(
        match: -> result { result.success? },
        resolve: -> result { result.value! }
      ),
      failure: Dry::Matcher::Case.new(
        match: -> result, step_name = nil {
          if step_name
            result.failure? &&
              result.failure.is_a?(StepFailure) &&
              ResultMatching.failure_chain(result.failure).any? { |failure|
                failure.step.name == step_name
              }
          else
            result.failure?
          end
        },
        resolve: -> result { result.failure.value }
      )
    )
  end
end
