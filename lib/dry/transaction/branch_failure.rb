# frozen_string_literal: true

require "dry/transaction/step_failure"

module Dry
  module Transaction
    # @api private
    class BranchFailure < StepFailure
      attr_reader :branch_name

      def initialize(step, value, branch_name)
        super(step, value)
        @branch_name = branch_name
      end
    end
  end
end
