# frozen_string_literal: true

module Dry
  module Transaction
    class StepAdapters
      # @api private
      class Branch
        def call(operation, _options, args)
          operation.call(args[0])
        end
      end

      register :branch, Branch.new
    end
  end
end
