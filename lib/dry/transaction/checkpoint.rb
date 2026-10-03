# frozen_string_literal: true

require "digest"
require "json"

module Dry
  module Transaction
    # A Checkpoint captures everything a caller needs to persist (as plain
    # data) in order to resume a transaction after the process exits: the
    # identity of the step to resume at, the version of the transaction
    # definition it was recorded against, and the input for that step.
    #
    # The caller is responsible for persisting the checkpoint (e.g. via
    # +#to_h+ serialized to JSON) and for passing it back to
    # +InstanceMethods#resume+.
    class Checkpoint
      attr_reader :step_name
      attr_reader :version
      attr_reader :input

      def initialize(step_name:, version:, input:)
        @step_name = step_name.to_sym
        @version = version
        @input = input
      end

      # Returns the checkpoint as plain, serializable data.
      def to_h
        {
          "step" => step_name.to_s,
          "version" => version,
          "input" => input,
          "input_digest" => self.class.input_digest(input)
        }
      end

      # Rebuilds a checkpoint from persisted plain data, verifying its
      # structure and the integrity of the recorded input.
      #
      # @raise [CorruptCheckpointError] if the data is malformed or the input
      #   does not match its recorded digest
      def self.from_h(data)
        unless data.is_a?(Hash)
          raise CorruptCheckpointError, "checkpoint must be a Hash, got #{data.class}"
        end

        data = data.transform_keys(&:to_s)

        missing = %w[step version input input_digest].reject { |key| data.key?(key) }
        unless missing.empty?
          raise CorruptCheckpointError, "checkpoint is missing keys: #{missing.join(", ")}"
        end

        unless data["version"].is_a?(String) && data["input_digest"].is_a?(String)
          raise CorruptCheckpointError, "checkpoint version and input digest must be Strings"
        end

        unless data["input_digest"] == input_digest(data["input"])
          raise CorruptCheckpointError, "checkpoint input does not match its recorded digest"
        end

        new(step_name: data["step"], version: data["version"], input: data["input"])
      end

      # @api private
      def self.input_digest(input)
        Digest::SHA256.hexdigest(JSON.generate(input))
      end
    end

    # The outcome of resuming a transaction from a checkpoint.
    #
    # The step recorded in the checkpoint was never confirmed complete, so it
    # may already have produced external side effects before the process
    # exited. A ResumeResult therefore always requires adjudication by the
    # caller: it never claims the resumed step ran exactly once.
    class ResumeResult
      # The underlying transaction result (a dry-monads Result)
      attr_reader :result

      # The name of the unconfirmed step the transaction resumed from
      attr_reader :resumed_step

      def initialize(result, resumed_step:)
        @result = result
        @resumed_step = resumed_step
      end

      # Always true: the caller must decide how to reconcile any external
      # side effects the resumed step may already have caused.
      def requires_adjudication?
        true
      end

      def success?
        result.success?
      end

      def failure?
        result.failure?
      end
    end

    # Wraps a resumable step so a checkpoint is emitted (with the step's
    # input) immediately before the step runs.
    #
    # @api private
    class CheckpointEmitter
      def initialize(step, emit)
        @step = step
        @emit = emit
      end

      def call(input, continue)
        @emit.(input)
        @step.(input, continue)
      end
    end
  end
end
