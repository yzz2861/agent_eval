# frozen_string_literal: true

require "dry/transaction/step_failure"

module Dry
  module Transaction
    # @api private
    class Stack
      include Dry::Monads[:result]

      RETURN = -> x { x }

      def initialize(steps, recoveries = [])
        @recoveries = recoveries
        @stack = compile(steps)
      end

      def call(m)
        @stack.(m)
      end

      private

      def compile(steps)
        steps.reverse.reduce(RETURN) do |next_step, step|
          proc { |m| m.bind { |value| invoke_step(step, value, next_step) } }
        end
      end

      def invoke_step(step, input, next_step)
        if step.adapter.yields?
          invoke_yielding_step(step, input, next_step)
        else
          invoke_plain_step(step, input, next_step)
        end
      end

      def invoke_plain_step(step, input, next_step)
        continuation = -> result {
          continue_after_step(result, input, next_step)
        }

        step.(input, continuation)
      end

      def invoke_yielding_step(step, input, next_step)
        recovered_result = nil
        continuation = -> result {
          recovery = recovery_for(result)

          if recovery
            recovered_result = recovery.call(result.failure, input)
            recovered_result.bind { |value| next_step.(Success(value)) }
          else
            next_step.(result)
          end
        }

        result = step.(input, continuation)

        if recovered_result && result.failure? && result.failure.equal?(recovered_result.failure)
          recovered_result.bind { |value| next_step.(Success(value)) }
        elsif recovered_result || result.success?
          result
        else
          recovery = recovery_for(result)

          if recovery
            recovery.call(result.failure, input).bind { |value| next_step.(Success(value)) }
          else
            result
          end
        end
      end

      def continue_after_step(result, input, next_step)
        recovery = recovery_for(result)

        if recovery
          recovery.call(result.failure, input).bind { |value| next_step.(Success(value)) }
        else
          next_step.(result)
        end
      end

      def recovery_for(result)
        return unless result.failure?

        step_failure = result.failure
        return unless step_failure.is_a?(StepFailure)

        @recoveries.find {
          _1.step_name == step_failure.step.name && _1.match?(step_failure.value)
        }
      end
    end
  end
end
