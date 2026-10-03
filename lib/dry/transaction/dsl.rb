# frozen_string_literal: true

module Dry
  module Transaction
    class DSL < Module
      def initialize(step_adapters:)
        super()
        @step_adapters = step_adapters

        define_steps
        define_recoveries
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

      def define_recoveries
        module_eval do
          define_method(:recoveries) do
            @recoveries ||= []
          end

          define_method(:operation_definitions) do
            steps + recoveries
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

          define_method(:recover) do |name_or_step, with: nil, as: nil,
            failure: Recovery::UNDEFINED, catch: Recovery::UNDEFINED,
            step: nil, from: nil, on: nil|

            target_step = step || from || on
            target_step ||= name_or_step

            recovery_name = if target_step == name_or_step
                              as || unique_recovery_name(target_step)
                            else
                              name_or_step
                            end
            matcher = if failure != Recovery::UNDEFINED
                        failure
                      elsif catch != Recovery::UNDEFINED
                        catch
                      else
                        Recovery::MATCH_ALL
                      end

            recoveries << Recovery.new(
              step_name: target_step,
              name: recovery_name,
              operation_name: with,
              failure: matcher
            )
          end

          define_method(:unique_recovery_name) do |target_step|
            default_name = "recover_#{target_step}".to_sym
            existing_names = recoveries.map(&:name)
            return default_name unless existing_names.include?(default_name)

            2.upto(Float::INFINITY) do |index|
              name = "recover_#{target_step}_#{index}".to_sym
              return name unless existing_names.include?(name)
            end
          end
          private :unique_recovery_name
        end
      end
    end
  end
end
