# frozen_string_literal: true

require "dry/transaction/branch"

module Dry
  module Transaction
    class DSL < Module
      def initialize(step_adapters:)
        super()
        @step_adapters = step_adapters

        define_steps
        define_dsl
      end

      def inspect
        "Dry::Transaction::DSL(#{@step_adapters.keys.sort.join(", ")})"
      end

      private

      def define_steps
        module_eval do
          define_method(:steps) do
            @steps ||= []
          end
        end
      end

      def define_dsl
        module_exec(@step_adapters) do |step_adapters|
          define_method(:branch) do |step_name, &block|
            definitions = Branch::DSL.call(step_adapters, &block)
            branch_options = {branches: definitions}
            steps << Step.new(
              adapter: step_adapters[:branch],
              name: step_name,
              operation_name: nil,
              operation: nil,
              options: branch_options
            )
          end

          step_adapters.each do |adapter_name, adapter|
            next if adapter_name.to_sym == :branch

            original_verbosity = $VERBOSE
            $VERBOSE = nil

            define_method(adapter_name) do |step_name, with: nil, **options|
              steps << Step.new(
                adapter: adapter,
                name: step_name,
                operation_name: with,
                operation: nil,
                options: options
              )
            end
          ensure
            $VERBOSE = original_verbosity
          end
        end
      end
    end
  end
end
