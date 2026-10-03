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

    # Base error for checkpoint-related problems.
    class CheckpointError < StandardError; end

    # Raised when caller-persisted checkpoint data fails validation.
    class CorruptedCheckpointError < CheckpointError
      def initialize(detail)
        super("checkpoint data is corrupted: #{detail}")
      end
    end

    # Raised when a checkpoint references a step that is missing from the
    # transaction definition or was not declared resumable.
    class UnresumableCheckpointError < CheckpointError
      def initialize(step_name)
        super("checkpoint references step +#{step_name}+, which is missing or not declared resumable")
      end
    end
  end
end
