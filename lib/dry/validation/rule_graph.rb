# frozen_string_literal: true

require "tsort"

require "dry/validation/constants"

module Dry
  module Validation
    # Ordered graph of contract rules built from their dependency declarations
    #
    # The graph is built once, when a contract is instantiated, so that
    # references to missing rules and dependency cycles are raised before a
    # contract is ever called.
    #
    # @api private
    class RuleGraph
      include ::TSort

      # @!attribute [r] rules
      #   @return [Array<Rule>] Rules in definition order
      #   @api private
      attr_reader :rules

      # @api private
      def initialize(rules)
        @rules = rules
        @by_name = {}
        build_index!
        verify_dependencies!
        verify_acyclic!
      end

      # Return rules ordered so that every prerequisite comes before the rules
      # that depend on it. Unrelated rules keep their relative definition order.
      #
      # @return [Array<Rule>]
      #
      # @api private
      def call
        tsort
      end

      # Return the rule registered under the given name
      #
      # @return [Rule, nil]
      #
      # @api private
      def [](name)
        @by_name[name.to_sym]
      end

      private

      # @api private
      def tsort_each_node(&)
        rules.each(&)
      end

      # @api private
      def tsort_each_child(rule, &)
        rule.depends_on.each { |name| yield(@by_name[name]) }
      end

      # @api private
      def build_index!
        rules.each do |rule|
          next if rule.name.nil?

          unless (existing = @by_name[rule.name]).nil?
            raise DuplicateRuleNameError,
                  "rule name #{rule.name.inspect} is used by both #{label(existing)} and #{label(rule)}"
          end

          @by_name[rule.name] = rule
        end
      end

      # @api private
      def verify_dependencies!
        rules.each do |rule|
          rule.depends_on.each do |dep|
            next if @by_name.key?(dep)

            dependent = rule.name ? rule.name.inspect : label(rule)
            raise MissingRuleError.new(dep, dependent)
          end
        end
      end

      # @api private
      def verify_acyclic!
        cycle = find_cycle

        return if cycle.nil?

        raise CircularDependencyError,
              "rules form a circular dependency: #{cycle.map(&:inspect).join(" -> ")}"
      end

      # Depth-first search that returns the first detected cycle as an ordered
      # list of rule names, e.g. +[:a, :b, :c, :a]+
      #
      # @return [Array<Symbol>, nil]
      #
      # @api private
      def find_cycle
        state = ::Hash.new(:unvisited)
        stack = []

        @by_name.keys.each do |name|
          next unless state[name].equal?(:unvisited)

          cycle = visit(name, state, stack)
          return cycle unless cycle.nil?
        end

        nil
      end

      # @api private
      def visit(name, state, stack)
        state[name] = :visiting
        stack << name

        @by_name[name].depends_on.each do |dep|
          next unless @by_name.key?(dep)

          if state[dep].equal?(:visiting)
            index = stack.index(dep)
            return [*stack[index..], dep]
          elsif state[dep].equal?(:unvisited) && (cycle = visit(dep, state, stack))
            return cycle
          end
        end

        stack.pop
        state[name] = :visited
        nil
      end

      # @api private
      def label(rule)
        "rule(#{rule.keys.map(&:inspect).join(", ")})"
      end
    end
  end
end
