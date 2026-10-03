# frozen_string_literal: true

module Dry
  module Transaction
    class InvalidStepError < ArgumentError
      def initialize(step_name)
        super("step +`#{step_name}`+ must respond to `#call`")
      end
    end

    class MissingStepError < ArgumentError
      def initialize(step_name)
        super("Definition for step +`#{step_name}`+ is missing")
      end
    end

    class InvalidResultError < ArgumentError
      def initialize(step_name)
        super("step +#{step_name}+ must return a Result object")
      end
    end

    class MissingCatchListError < ArgumentError
      def initialize(step_name)
        super("step +#{step_name}+ requires one or more exception classes provided via +catch:+")
      end
    end

    class InvalidBranchError < ArgumentError
      def initialize(step_name, message)
        super("branch step +#{step_name}+ #{message}")
      end
    end

    class NoBranchMatchedError < ArgumentError
      def initialize(step_name)
        super("no branch matched for branch step +#{step_name}+ and no fallback branch was defined")
      end
    end
  end
end
