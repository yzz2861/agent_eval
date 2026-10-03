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

    # Base class for checkpoint/resume errors
    class CheckpointError < ArgumentError; end

    # Raised when persisted checkpoint data is malformed or its recorded
    # input no longer matches its integrity digest
    class CorruptCheckpointError < CheckpointError; end

    # Raised when a checkpoint was recorded against a different version of
    # the transaction definition
    class DefinitionVersionMismatchError < CheckpointError
      def initialize
        super("checkpoint was recorded against a different transaction definition version")
      end
    end

    # Raised when a checkpoint refers to a step that does not exist in the
    # current transaction definition
    class UnknownCheckpointStepError < CheckpointError
      def initialize(step_name)
        super("checkpoint refers to unknown step +#{step_name}+")
      end
    end

    # Raised when attempting to resume from a step that was not declared
    # resumable
    class NonResumableStepError < CheckpointError
      def initialize(step_name)
        super("step +#{step_name}+ is not declared resumable")
      end
    end
  end
end
