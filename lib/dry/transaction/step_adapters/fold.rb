# frozen_string_literal: true

module Dry
  module Transaction
    class StepAdapters
      # Folds a lazily consumed input stream into a single accumulated value.
      #
      # The input is pulled element by element (it is never converted to an
      # array) and the operation is called for each element with the
      # accumulated value so far, the element itself and its zero-based
      # index. Pulling stops at the first Failure, and the returned Failure
      # carries the accumulated value completed so far along with the
      # failing index. An empty input folds to the initial value.
      #
      # @api private
      class Fold
        include Dry::Monads[:result]

        # State of the fold at the point of failure
        #
        # @api private
        FailureState = Struct.new(:accumulator, :index)

        # Number of arguments passed to the operation for each element:
        # the accumulated value, the element and its index
        #
        # @api private
        def call_arity
          3
        end

        def call(operation, options, args)
          source = args[0]
          accumulator = options.fetch(:initial)
          index = 0

          begin
            source.each do |element|
              result = operation.(accumulator, element, index, *args[1..])

              if result.is_a?(Success)
                accumulator = result.value!
                index += 1
              else
                return Failure(FailureState.new(accumulator, index))
              end
            end
          ensure
            source.close if options[:owns_source] && source.respond_to?(:close)
          end

          Success(accumulator)
        end
      end

      register :fold, Fold.new
    end
  end
end
