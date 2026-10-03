# frozen_string_literal: true

require "dry/transaction/branch_dsl"

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
          step_adapters.each do |adapter_name, adapter|
            define_method(adapter_name) do |step_name, with: nil, **options, &block|
              if adapter_name.to_sym == :branch
                raise ArgumentError, "+branch:+ step +#{step_name}+ requires a block" unless block

                options = {**options, branches: BranchDSL.new(step_adapters: step_adapters).build(step_name, &block)}
              end

              steps << Step.new(
                adapter: adapter,
                name: step_name,
                operation_name: with,
                operation: nil, # operations are resolved only when transactions are instantiated
                options: options
              )
            end
          end
        end
      end
    end
  end
end
