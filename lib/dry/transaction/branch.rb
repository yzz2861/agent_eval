# frozen_string_literal: true

require "dry/transaction/callable"
require "dry/transaction/stack"

module Dry
  module Transaction
    class Branch
      include Dry::Monads[:result]

      Successful = Struct.new(:name, :value)
      Failed = Struct.new(:name, :step_failure)
      NoMatch = Struct.new(:input)

      Definition = Struct.new(:name, :condition, :block, :step_adapters) do
        def initialize_copy(source)
          super
          @steps = nil
        end

        def fallback?
          condition.nil?
        end

        def steps!
          @steps ||= StepsDSL.new(step_adapters).call(&block)
        end
      end

      class DSL
        attr_reader :branches

        def self.call(step_adapters, &block)
          new(step_adapters).call(&block)
        end

        def initialize(step_adapters)
          @step_adapters = step_adapters
          @branches = []
        end

        def call(&block)
          if block.arity.zero?
            instance_exec(&block)
          else
            block.call(self)
          end

          branches
        end

        def on(name, condition = nil, **options, &block)
          predicate = condition || options[:if] || options[:condition]
          raise ArgumentError, "branch +#{name}+ requires a condition" if predicate.nil?
          raise ArgumentError, "branch +#{name}+ requires steps" if block.nil?

          add_branch(name, predicate, block)
        end

        def fallback(name = :fallback, &block)
          raise ArgumentError, "fallback branch +#{name}+ requires steps" if block.nil?

          add_branch(name, nil, block)
        end
        alias_method :otherwise, :fallback

        private

        def add_branch(name, condition, block)
          if branches.any?(&:fallback?)
            raise ArgumentError, "cannot define branch +#{name}+ after a fallback branch"
          end

          branches << Definition.new(name, condition, block, @step_adapters)
        end
      end

      class StepsDSL
        attr_reader :steps

        def initialize(step_adapters)
          @step_adapters = step_adapters
          @steps = []

          step_adapters.each do |adapter_name, _adapter|
            next if adapter_name.to_sym == :branch

            define_singleton_method(adapter_name) do |step_name, with: nil, **options|
              add_step(adapter_name, step_name, with, options)
            end
          end
        end

        def call(&block)
          if block.arity.zero?
            instance_exec(&block)
          else
            block.call(self)
          end

          steps
        end

        def branch(name, &block)
          definitions = Branch::DSL.call(@step_adapters, &block)
          steps << Step.new(
            adapter: @step_adapters[:branch],
            name: name,
            operation_name: nil,
            operation: nil,
            options: {branches: definitions}
          )
        end

        private

        def add_step(adapter_name, name, operation_name, options)
          steps << Step.new(
            adapter: @step_adapters[adapter_name.to_sym],
            name: name,
            operation_name: operation_name,
            operation: nil,
            options: options
          )
        end
      end

      attr_reader :definitions, :resolve_step, :resolve_condition, :validate_steps
      attr_accessor :listeners, :step_args, :branch_names

      def arity
        1
      end

      def initialize(definitions:, resolve_step:, resolve_condition:, validate_steps:, step_args: {}, branch_names: [])
        @definitions = definitions
        @resolve_step = resolve_step
        @resolve_condition = resolve_condition
        @validate_steps = validate_steps
        @step_args = step_args
        @branch_names = branch_names
      end

      def call(input)
        selected_definition = select(input)
        definition = selected_definition.dup if selected_definition
        return Failure(NoMatch.new(input)) unless definition

        steps = prepare_steps(definition)
        validate_steps.call(steps)

        Stack.new(steps).call(Success(input)).fmap { |value|
          Successful.new(definition.name, value)
        }.or { |step_failure|
          Failure(Failed.new(definition.name, step_failure))
        }
      end

      private

      def select(input)
        definitions.find do |definition|
          next true if definition.fallback?

          result = resolve_condition.call(definition.condition).call(input)
          result.respond_to?(:success?) ? result.success? : !!result
        end
      end

      def prepare_steps(definition)
        direct_names = definition.steps!.map(&:name)
        steps = definition.steps!.map do |step|
          prepared = resolve_step.call(step)
          selected_path = branch_names + [definition.name]

          if prepared.branch?
            prepared = configure_nested_branch(prepared, direct_names, selected_path)
          elsif step_args.key?(prepared.name)
            prepared = prepared.with(call_args: step_args[prepared.name])
          end

          prepared = prepared.with(branch_names: selected_path)
          subscribe_step(prepared)
          prepared
        end

        assert_step_args(steps)
        steps
      end

      def configure_nested_branch(step, sibling_names, selected_path)
        operation = step.branch_runner.dup
        nested_args = step_args[step.name] if step_args[step.name].is_a?(Hash)
        operation.step_args = step_args.except(*sibling_names).merge(nested_args || {})
        operation.listeners = listeners
        operation.branch_names = selected_path
        step.with(operation: operation)
      end

      def assert_step_args(steps)
        step_args.each do |name, value|
          step = steps.detect { |candidate| candidate.name == name }

          if step&.branch? && !value.is_a?(Hash)
            raise ArgumentError, "+#{name}+ is a branch step and accepts nested step arguments as a Hash"
          end
        end
      end

      def subscribe_step(step)
        case listeners
        when nil
          nil
        when Hash
          value = listeners[step.name]

          if value
            if step.branch? && value.is_a?(Hash)
              step.branch_runner.listeners = value
            else
              step.subscribe(value)
            end
          end
        else
          step.subscribe(listeners)
        end
      end
    end
  end
end
