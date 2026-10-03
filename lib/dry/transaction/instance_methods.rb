# frozen_string_literal: true

require "dry/transaction/result_matcher"
require "dry/transaction/stack"

module Dry
  module Transaction
    module InstanceMethods
      include Dry::Monads[:result]

      attr_reader :steps
      attr_reader :operations
      attr_reader :listeners
      attr_reader :stack

      def initialize(steps: self.class.steps, listeners: nil, **operations)
        @steps = steps.map { |step|
          operation = resolve_operation(step, **operations)
          step.with(operation: operation)
        }
        @operations = operations
        @stack = Stack.new(@steps)
        subscribe(listeners) unless listeners.nil?
      end

      def call(input = nil, &block)
        assert_step_arity

        match_result(stack.(Success(input)), &block)
      end

      # Runs the transaction, emitting checkpoints for resumable steps.
      #
      # @param input the transaction input
      # @param on_checkpoint [#call] callback invoked with a Checkpoint
      #   immediately before each resumable step runs. The caller is
      #   responsible for persisting the checkpoint's plain data
      #   (Checkpoint#to_h) so the transaction can later be resumed. On
      #   overall success the caller should discard any stored checkpoint.
      def call_with_checkpoints(input = nil, on_checkpoint:, &block)
        assert_step_arity

        match_result(
          run_steps(steps, Success(input), on_checkpoint: on_checkpoint),
          &block
        )
      end

      # Resumes a transaction from a previously persisted checkpoint.
      #
      # The checkpoint's definition version and input integrity are verified
      # before anything runs, and the step it names must still exist and be
      # declared resumable --- the resume position is never guessed from a
      # step's position in the definition.
      #
      # @param checkpoint_data [Hash] plain data previously obtained from
      #   Checkpoint#to_h
      # @param on_checkpoint [#call, nil] optional callback for checkpoints
      #   formed while running the remaining steps
      #
      # @return [ResumeResult] wraps the transaction result. The resumed-from
      #   step was never confirmed complete and may already have produced
      #   external side effects, so the caller must adjudicate the outcome
      #   (see ResumeResult#requires_adjudication?).
      #
      # @raise [CorruptCheckpointError] if the data is malformed or tampered
      # @raise [DefinitionVersionMismatchError] if the transaction definition
      #   changed since the checkpoint was recorded
      # @raise [UnknownCheckpointStepError] if the named step does not exist
      # @raise [NonResumableStepError] if the named step is not resumable
      def resume(checkpoint_data, on_checkpoint: nil)
        checkpoint = Checkpoint.from_h(checkpoint_data)

        unless checkpoint.version == definition_version
          raise DefinitionVersionMismatchError
        end

        resume_index = steps.index { |step| step.name == checkpoint.step_name }
        raise UnknownCheckpointStepError, checkpoint.step_name unless resume_index

        resume_step = steps[resume_index]
        raise NonResumableStepError, checkpoint.step_name unless resume_step.resumable?

        assert_step_arity

        result = run_steps(steps[resume_index..], Success(checkpoint.input),
          on_checkpoint: on_checkpoint)

        ResumeResult.new(
          result.or { |step_failure| Failure(step_failure.value) },
          resumed_step: resume_step.name
        )
      end

      # A fingerprint of the transaction definition (step names, operation
      # names and resumable declarations). Recorded in every checkpoint and
      # verified on resume.
      def definition_version
        @definition_version ||= Digest::SHA256.hexdigest(
          steps.map { |step|
            "#{step.name}:#{step.operation_name}:#{step.resumable?}"
          }.join("|")
        )[0, 16]
      end

      def subscribe(listeners)
        @listeners = listeners

        if listeners.is_a?(Hash)
          listeners.each do |step_name, listener|
            steps.detect { |step| step.name == step_name }.subscribe(listener)
          end
        else
          steps.each do |step|
            step.subscribe(listeners)
          end
        end
      end

      def with_step_args(**step_args)
        assert_valid_step_args(step_args)

        new_steps = steps.map { |step|
          if step_args[step.name]
            step.with(call_args: step_args[step.name])
          else
            step
          end
        }

        self.class.new(steps: new_steps, listeners: listeners, **operations)
      end

      private

      def match_result(result, &block)
        if block
          ResultMatcher.(result, &block)
        else
          result.or { |step_failure|
            # Unwrap the value from the StepFailure and return it directly
            Failure(step_failure.value)
          }
        end
      end

      def run_steps(steps, input, on_checkpoint: nil)
        if on_checkpoint
          Stack.new(with_checkpoints(steps, on_checkpoint)).(input)
        elsif steps.equal?(self.steps)
          stack.(input)
        else
          Stack.new(steps).(input)
        end
      end

      # Emits a checkpoint on entry to each resumable step (except the first
      # step of the run, whose input the caller already holds).
      def with_checkpoints(steps, on_checkpoint)
        steps.each_with_index.map { |step, index|
          if index > 0 && step.resumable?
            CheckpointEmitter.new(step, ->(value) {
              on_checkpoint.(Checkpoint.new(
                step_name: step.name,
                version: definition_version,
                input: value
              ))
            })
          else
            step
          end
        }
      end

      def respond_to_missing?(name, _include_private = false)
        steps.any? { |step| step.name == name }
      end

      def method_missing(name, *args, &block)
        step = steps.detect { |s| s.name == name }
        super unless step

        operation = operations[step.name]
        unless operation
          raise NotImplementedError,
            "no operation +#{step.operation_name}+ defined for step +#{step.name}+"
        end

        operation.(*args, &block)
      end

      def resolve_operation(step, **operations)
        if step.internal? && operations[step.name]
          operations[step.name]
        elsif methods.include?(step.name) || private_methods.include?(step.name)
          method(step.name)
        elsif operations[step.name].respond_to?(:call)
          operations[step.name]
        elsif operations[step.name]
          raise InvalidStepError, step.name
        else
          raise MissingStepError, step.name
        end
      end

      def assert_valid_step_args(step_args)
        step_args.each_key do |step_name|
          unless steps.any? { |step| step.name == step_name }
            raise ArgumentError, "+#{step_name}+ is not a valid step name"
          end
        end
      end

      def assert_step_arity
        steps.each do |step|
          num_args_required = step.arity >= 0 ? step.arity : ~step.arity
          num_args_supplied = step.call_args.length + 1 # add 1 for main `input`

          if num_args_required > num_args_supplied
            raise ArgumentError, "not enough arguments supplied for step +#{step.name}+"
          end
        end
      end
    end
  end
end
