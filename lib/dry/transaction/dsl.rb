# frozen_string_literal: true

require "dry/transaction/recovery"

module Dry
  module Transaction
    class DSL < Module
      def initialize(step_adapters:)
        super()
        @step_adapters = step_adapters

        define_steps
        define_dsl
        define_recovery_dsl
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

          define_method(:recoveries) do
            @recoveries ||= []
          end
        end
      end

      def define_dsl
        module_exec(@step_adapters) do |step_adapters|
          step_adapters.each do |adapter_name, adapter|
            define_method(adapter_name) do |step_name, with: nil, **options|
              operation_name = with

              steps << Step.new(
                adapter: adapter,
                name: step_name,
                operation_name: operation_name,
                operation: nil, # operations are resolved only when transactions are instantiated
                options: options
              )
            end
          end
        end
      end

      def define_recovery_dsl
        module_eval do
          define_method(:recover) do |name = Dry::Transaction::Recovery::UNDEFINED,
            step: Dry::Transaction::Recovery::UNDEFINED,
            from: step,
            with: nil,
            failure: Dry::Transaction::Recovery::UNDEFINED,
            on: failure, **options|

            if name == Dry::Transaction::Recovery::UNDEFINED && from == Dry::Transaction::Recovery::UNDEFINED
              raise ArgumentError, "recovery must reference a step"
            end

            if name == Dry::Transaction::Recovery::UNDEFINED
              recovery_name = :"#{from}_recovery"
              step_name = from
            elsif from != Dry::Transaction::Recovery::UNDEFINED
              recovery_name = name
              step_name = from
            else
              recovery_name = :"#{name}_recovery"
              step_name = name
            end

            if on == Dry::Transaction::Recovery::UNDEFINED
              raise ArgumentError, "recovery +#{recovery_name}+ must specify a failure"
            end

            recoveries << Dry::Transaction::Recovery.new(
              name: recovery_name,
              step_name: step_name,
              operation_name: with,
              failure_matcher: on,
              **options
            )
          end
        end
      end
    end
  end
end
