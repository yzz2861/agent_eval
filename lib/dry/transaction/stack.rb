# frozen_string_literal: true

require "dry/monads"

module Dry
  module Transaction
    # @api private
    class Stack
      RETURN = -> x { x }
      def initialize(steps)
        @stack = compile(steps)
      end

      def call(m)
        @stack.(m)
      end

      private

      def compile(steps)
        steps.reverse.reduce(RETURN) do |next_step, step|
          continuation = branch_continuation(step, next_step)
          proc { |m| m.bind { |value| step.(value, continuation) } }
        end
      end

      def branch_continuation(step, next_step)
        return next_step unless step.respond_to?(:branch?) && step.branch?

        -> result {
          case result
          when Dry::Monads::Result::Success then next_step.(result)
          when Dry::Monads::Result::Failure then result
          else next_step.(Dry::Monads.Success(result))
          end
        }
      end
    end
  end
end
