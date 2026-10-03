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
        match: -> result, step_name_or_path = nil {
          if step_name_or_path.is_a?(Array)
            # Match the exact step path, e.g. [:process, :validate]
            result.failure? && result.failure.path == step_name_or_path
          elsif step_name_or_path
            # Match a step name at any level of the step path
            result.failure? && result.failure.path.include?(step_name_or_path)
          else
            result.failure?
          end
        },
        resolve: -> result { result.failure.value }
      )
    )
  end
end
