# frozen_string_literal: true

require "dry/transaction/branch"

module Dry
  module Transaction
    class StepAdapters
      class BranchAdapter
        def call(operation, _options, args)
          operation.(*args)
        end
      end

      register :branch, BranchAdapter.new
    end
  end
end
