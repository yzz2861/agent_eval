# frozen_string_literal: true

module Dry
  module Transaction
    # @api private
    class BranchDefinition
      UNDEFINED = Object.new.freeze

      attr_reader :name
      attr_reader :condition
      attr_reader :operation_name
      attr_reader :steps

      def initialize(name:, condition: UNDEFINED, operation_name: nil, steps: [], fallback: false)
        @name = name
        @condition = condition
        @operation_name = operation_name
        @steps = steps
        @fallback = fallback
      end

      def fallback?
        @fallback
      end
    end
  end
end
