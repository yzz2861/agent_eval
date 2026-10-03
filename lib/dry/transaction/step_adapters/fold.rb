# frozen_string_literal: true

require "dry/transaction/errors"

module Dry
  module Transaction
    class StepAdapters
      # @api private
      class Fold
        include Dry::Monads[:result]

        def input_arity
          1
        end

        def call(operation, options, args)
          source, initial = Array(args)
          accumulator = options.fetch(:initial, initial)

          enumerator, owned = enumerator_for(source)

          enumerator.each_with_index do |element, index|
            result = operation.(accumulator, element, index)

            unless result.is_a?(Dry::Monads::Result)
              raise InvalidResultError, options[:step_name]
            end

            return Failure([accumulator, index]) if result.failure?

            accumulator = result.value!
          end

          Success(accumulator)
        ensure
          close_source(source, owned)
        end

        private

        def enumerator_for(source)
          if source.is_a?(Enumerator)
            [source, false]
          else
            [source.to_enum, true]
          end
        end

        def close_source(source, owned)
          source.close if owned && source.respond_to?(:close)
        end
      end

      register :fold, Fold.new
    end
  end
end
