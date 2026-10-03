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
        match: -> result, step = nil {
          case step
          when nil
            result.failure?
          when Array
            # Match the full path of steps leading to the failure, e.g.
            # [:process, :validate] for a :validate step failing inside a
            # nested transaction run by the :process step
            result.failure? && result.failure.path == step
          else
            # Match any step in the failure's path. For failures from a
            # single-level transaction, this is the failing step itself.
            result.failure? && result.failure.path.include?(step)
          end
        },
        resolve: -> result { result.failure.value }
      )
    )
  end
end
