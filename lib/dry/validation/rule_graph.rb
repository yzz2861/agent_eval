# frozen_string_literal: true

require "dry/validation/constants"

module Dry
  module Validation
    # Validates rule dependencies and orders rules for execution
    #
    # Rules are returned in an order where every rule appears after the rules
    # it depends on, preserving the definition order wherever possible.
    # Definition errors (duplicate names, unknown dependencies, cycles) are
    # raised before any rule is executed.
    #
    # @api private
    class RuleGraph
      # @api private
      attr_reader :rules

      # @api private
      def initialize(rules)
        @rules = rules
      end

      # Return rules sorted so that dependencies run before their dependents
      #
      # @raise [DuplicateRuleNameError] when a name is used by more than one rule
      # @raise [UnknownRuleDependencyError] when a dependency name is not defined
      # @raise [CyclicRuleDependencyError] when dependencies form a cycle
      #
      # @return [Array<Rule>]
      #
      # @api private
      def sort
        named = index_by_name
        validate_dependencies!(named)
        sort_rules(named)
      end

      private

      # @api private
      def index_by_name
        rules.each_with_object({}) do |rule, named|
          next unless rule.name

          if named.key?(rule.name)
            raise DuplicateRuleNameError,
                  "Rule name #{rule.name.inspect} is used by more than one rule"
          end

          named[rule.name] = rule
        end
      end

      # @api private
      def validate_dependencies!(named)
        rules.each do |rule|
          rule.depends_on.each do |dependency|
            next if named.key?(dependency)

            label = rule.name ? rule.name.inspect : "with keys #{rule.keys.inspect}"

            raise UnknownRuleDependencyError,
                  "Rule #{label} depends on unknown rule #{dependency.inspect}"
          end
        end
      end

      # @api private
      def sort_rules(named)
        states = {}
        sorted = []

        visit = lambda do |rule, path|
          case states[rule]
          when :done
            next
          when :visiting
            cycle = (path[path.index(rule)..] + [rule]).map(&:name).join(" -> ")
            raise CyclicRuleDependencyError,
                  "Rule dependencies form a cycle: #{cycle}"
          end

          states[rule] = :visiting
          rule.depends_on.each { |dependency| visit.call(named[dependency], path + [rule]) }
          states[rule] = :done
          sorted << rule
        end

        rules.each { |rule| visit.call(rule, []) }

        sorted
      end
    end
  end
end
