# frozen_string_literal: true

require "digest"
require "json"
require "dry/transaction/errors"

module Dry
  module Transaction
    # Optional checkpointing support for long-running transactions.
    #
    # When a transaction is called with a checkpointer (any object responding
    # to +#save(hash)+), steps declared with +resumable: true+ emit plain-data
    # checkpoint records. The caller is responsible for persisting these
    # records (e.g. in a database) and for passing the latest record back to
    # {InstanceMethods#resume} after a restart.
    #
    # A record captures the *identity* of the step (its name), the version of
    # the transaction definition, and the input for the next step to run, so a
    # resumed transaction never relies on positional guesses.
    module Checkpoint
      # Computes a stable fingerprint for a list of step definitions. Any
      # change to the steps (names, adapters, options) changes the version, so
      # checkpoints written by a previous definition can be detected.
      #
      # @api private
      def self.definition_version(steps)
        definitions = steps.map { |step|
          [step.name, adapter_identity(step.adapter), step.operation_name, step.adapter.options]
        }

        Digest::SHA256.hexdigest(definitions.inspect)
      end

      # @api private
      def self.adapter_identity(step_adapter)
        raw_adapter = step_adapter.adapter

        if raw_adapter.respond_to?(:receiver)
          raw_adapter.receiver.class.name
        else
          raw_adapter.class.name
        end
      end

      # A plain-data checkpoint record. Records serialize to a Hash with
      # string keys (see {#to_h}) so callers can persist them as JSON or any
      # other format, and are validated on load (see {.load}).
      class Record
        STATUSES = %w[started completed].freeze

        attr_reader :step_name
        attr_reader :version
        attr_reader :status
        attr_reader :input

        # Builds a record for persistence. +input+ is the input for the next
        # step to run (for a "completed" record) or the input of the step
        # itself (for a "started" record).
        #
        # @api private
        def self.build(step_name:, version:, status:, input:)
          new(step_name: step_name.to_s, version: version, status: status.to_s, input: input)
        end

        # Validates and loads a record from caller-persisted plain data.
        #
        # @raise [CorruptedCheckpointError] if the data is malformed or the
        #   input fails its integrity check
        def self.load(data)
          unless data.is_a?(Hash)
            raise CorruptedCheckpointError, "checkpoint data must be a Hash"
          end

          data = data.each_with_object({}) { |(key, value), hash| hash[key.to_s] = value }

          step_name = data["step"]
          version = data["version"]
          status = data["status"]
          input = data["input"]
          input_digest = data["input_digest"]

          unless (step_name.is_a?(String) || step_name.is_a?(Symbol)) && !step_name.to_s.empty?
            raise CorruptedCheckpointError, "missing or invalid step identity"
          end

          unless version.is_a?(String) && !version.empty?
            raise CorruptedCheckpointError, "missing or invalid definition version"
          end

          unless STATUSES.include?(status.to_s)
            raise CorruptedCheckpointError, "missing or invalid status"
          end

          unless input_digest.is_a?(String) && input_digest == digest(input)
            raise CorruptedCheckpointError, "input failed its integrity check"
          end

          new(step_name: step_name.to_s, version: version, status: status.to_s, input: input)
        end

        # Integrity digest for the record's input. Uses a canonical JSON
        # serialization so the digest stays valid when callers persist
        # records as JSON (or keep them as Ruby hashes).
        #
        # @api private
        def self.digest(input)
          Digest::SHA256.hexdigest(JSON.generate(input))
        end

        def initialize(step_name:, version:, status:, input:)
          @step_name = step_name
          @version = version
          @status = status
          @input = input
        end

        # A "started" record means the step began but its completion was never
        # confirmed: it may already have produced external side effects.
        def started?
          status == "started"
        end

        def completed?
          status == "completed"
        end

        # @return [Hash] plain data with string keys, safe to persist as JSON
        def to_h
          {
            "step" => step_name,
            "version" => version,
            "status" => status,
            "input" => input,
            "input_digest" => self.class.digest(input)
          }
        end
      end

      # Outcome of {InstanceMethods#resume} when the transaction continued
      # from a confirmed checkpoint and ran to completion.
      class Resumed
        # @return [Dry::Monads::Result] the result of the continued run
        attr_reader :result

        def initialize(result)
          @result = result
        end

        def success?
          result.success?
        end

        def failure?
          result.failure?
        end
      end

      # Outcome of {InstanceMethods#resume} when the checkpointed step started
      # but its completion was never confirmed. The step may already have
      # produced external side effects, so exactly-once execution cannot be
      # claimed: the caller must adjudicate (retry, skip, or abort).
      class Ambiguous
        # @return [Symbol] name of the step with unconfirmed completion
        attr_reader :step_name

        # @return [Object] the input the step was started with
        attr_reader :input

        def initialize(step_name:, input:)
          @step_name = step_name
          @input = input
        end
      end

      # Outcome of {InstanceMethods#resume} when the checkpoint was written by
      # a different version of the transaction definition.
      class VersionMismatch
        # @return [String] version stored in the checkpoint
        attr_reader :checkpoint_version

        # @return [String] version of the current transaction definition
        attr_reader :current_version

        def initialize(checkpoint_version:, current_version:)
          @checkpoint_version = checkpoint_version
          @current_version = current_version
        end
      end
    end
  end
end
