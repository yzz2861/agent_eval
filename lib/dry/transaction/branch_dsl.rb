# frozen_string_literal: true

require "dry/transaction/branch_definition"

module Dry
  module Transaction
    # @api private
    class BranchDSL
      UNDEFINED = BranchDefinition::UNDEFINED

      attr_reader :branches
      attr_reader :steps

      def initialize(step_adapters:)
        @step_adapters = step_adapters
        @branches = []
        @steps = []
      end

      def build(name, &block)
        if block.arity.zero?
          instance_exec(&block)
        else
          block.call(self)
        end
        validate!(name)
        branches
      end

      def on(name, condition = UNDEFINED, if: UNDEFINED, with: nil, &block)
        resolved_condition = condition == UNDEFINED ? binding.local_variable_get(:if) : condition

        if condition != UNDEFINED && binding.local_variable_get(:if) != UNDEFINED
          raise ArgumentError, "+branch:+ provide either a positional condition or `if:`, not both"
        end

        add_branch(name, resolved_condition, with, false, &block)
      end
      alias_method :condition, :on

      def fallback(name = :fallback, &block)
        add_branch(name, UNDEFINED, nil, true, &block)
      end
      alias_method :otherwise, :fallback
      alias_method :default, :fallback

      private

      def add_branch(name, condition, operation_name, fallback, &block)
        raise ArgumentError, "+branch:+ branch +#{name}+ requires a block" unless block

        unless fallback || condition.respond_to?(:call) || condition.is_a?(Symbol)
          raise ArgumentError, "+branch:+ condition for +#{name}+ must be callable or a Symbol"
        end

        builder = self.class.new(step_adapters: @step_adapters)
        @step_adapters.each_key do |adapter_name|
          next if adapter_name.to_sym == :branch

          builder.send(:define_adapter, adapter_name)
        end
        builder.instance_exec(&block)

        branches << BranchDefinition.new(
          name: name,
          condition: fallback ? UNDEFINED : condition,
          operation_name: operation_name,
          steps: builder.steps,
          fallback: fallback
        )
      end

      def validate!(branch_step_name)
        raise InvalidBranchError.new(branch_step_name, "must contain at least one branch") if branches.empty?

        names = branches.map(&:name)
        duplicates = names.select { |name| names.count(name) > 1 }.uniq
        unless duplicates.empty?
          raise InvalidBranchError.new(branch_step_name, "contains duplicate branch names: #{duplicates.join(", ")}")
        end

        fallbacks = branches.select(&:fallback?)
        if fallbacks.length > 1
          raise InvalidBranchError.new(branch_step_name, "contains multiple fallback branches")
        end

        if fallbacks.one? && branches.last != fallbacks.first
          raise InvalidBranchError.new(branch_step_name, "fallback branch must be last")
        end

        if branches.any? { |branch| branch.steps.empty? }
          raise InvalidBranchError.new(branch_step_name, "contains an empty branch")
        end
      end

      def define_adapter(adapter_name)
        adapter = @step_adapters[adapter_name]

        define_singleton_method(adapter_name) do |step_name, with: nil, **options|
          steps << Step.new(
            adapter: adapter,
            name: step_name,
            operation_name: with,
            operation: nil,
            options: options
          )
        end
      end

    end
  end
end
