# frozen_string_literal: true

require "dry/transaction/checkpoint"

module Dry
  module Transaction
    # @api private
    class Stack
      RETURN = -> x { x }

      def initialize(steps, checkpointer: nil, version: nil)
        @stack = compile(steps, checkpointer, version)
      end

      def call(m)
        @stack.(m)
      end

      private

      def compile(steps, checkpointer, version)
        steps.reverse.reduce(RETURN) do |next_step, step|
          proc { |m|
            m.bind { |value|
              if checkpointer && step.resumable?
                run_resumable(step, value, next_step, checkpointer, version)
              else
                step.(value, next_step)
              end
            }
          }
        end
      end

      # Wraps a resumable step with checkpoint writes: a "started" record
      # before the step runs, and a "completed" record (carrying the input for
      # the next step) once it has succeeded.
      def run_resumable(step, value, next_step, checkpointer, version)
        checkpointer.save(
          Checkpoint::Record.build(
            step_name: step.name, version: version, status: :started, input: value
          ).to_h
        )

        continuation = proc { |result|
          result.fmap { |output|
            checkpointer.save(
              Checkpoint::Record.build(
                step_name: step.name, version: version, status: :completed, input: output
              ).to_h
            )
          }

          next_step.(result)
        }

        step.(value, continuation)
      end
    end
  end
end
