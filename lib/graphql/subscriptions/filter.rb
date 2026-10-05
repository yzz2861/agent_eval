# frozen_string_literal: true
module GraphQL
  class Subscriptions
    # Explicit filtering conditions used to decide whether a triggered event
    # should be delivered to a subscription.
    #
    # Supported leaf conditions:
    # - attribute equality: {Filter.eq}
    # - set membership: {Filter.in}
    # - numeric ranges: {Filter.gt}, {Filter.gte}, {Filter.lt}, {Filter.lte}, {Filter.between}
    #
    # Conditions compose with {Filter.and} and {Filter.or}. Anything that can't
    # be represented by the supported conditions is built as an {Filter.unknown}
    # condition: it is always kept as a candidate ("conservative fallback") and
    # then checked with the full predicate, so matching subscriptions are never
    # dropped by the index.
    #
    # Conditions can be built programmatically or parsed from a plain data
    # structure (for example, JSON arguments) with {Filter.build}.
    #
    # @example Programmatic conditions
    #   filter = GraphQL::Subscriptions::Filter.and(
    #     GraphQL::Subscriptions::Filter.eq("tenantId", "acme"),
    #     GraphQL::Subscriptions::Filter.or(
    #       GraphQL::Subscriptions::Filter.in("region", ["us-east", "eu-west"]),
    #       GraphQL::Subscriptions::Filter.between("amount", min: 100, max: 500),
    #     ),
    #   )
    #   filter.match?("tenantId" => "acme", "region" => "eu-west", "amount" => 250) # => true
    #
    # @example Parsing a JSON-like structure
    #   GraphQL::Subscriptions::Filter.build(
    #     "and" => [
    #       { "field" => "tenantId", "op" => "eq", "value" => "acme" },
    #       { "field" => "amount", "op" => "gte", "value" => 100 },
    #     ],
    #   )
    module Filter
      # The base class for all condition nodes.
      class Node
        # Evaluate the complete, exact predicate against event attributes.
        # @param attributes [Hash{#to_s => Object}]
        # @return [Boolean]
        def match?(attributes)
          raise GraphQL::RequiredImplementationMissingError
        end

        # An indexable expression describing this condition, or +:unknown+ when
        # no safe over-approximation can be built from indexes alone.
        #
        # The expression is a plain hash tree consumed by FilteredRegistry:
        # - { t: :eq, f: field, v: value }
        # - { t: :in, f: field, vs: [values] }
        # - { t: :cmp, f: field, op: :gt|:gte|:lt|:lte, b: bound }
        # - { t: :and, c: [...] }, { t: :or, c: [...] }
        # @return [Symbol, Hash]
        def index_expr
          raise GraphQL::RequiredImplementationMissingError
        end

        # @return [Node]
        def and(other)
          Filter.and(self, other)
        end

        # @return [Node]
        def or(other)
          Filter.or(self, other)
        end
      end

      # An attribute equals a value.
      class Eq < Node
        def initialize(field, value)
          @field = field.to_s
          @value = value
        end

        attr_reader :field, :value

        def match?(attributes)
          Filter.present?(attributes, @field) && Filter.read(attributes, @field) == @value
        end

        def index_expr
          { t: :eq, f: @field, v: @value }
        end
      end

      # An attribute is a member of a fixed set of values.
      class In < Node
        def initialize(field, values)
          @field = field.to_s
          @values = values.to_a.uniq
        end

        attr_reader :field, :values

        def match?(attributes)
          Filter.present?(attributes, @field) && @values.include?(Filter.read(attributes, @field))
        end

        def index_expr
          { t: :in, f: @field, vs: @values }
        end
      end

      # An attribute is compared numerically to a bound.
      class Compare < Node
        OPS = [:gt, :gte, :lt, :lte].freeze

        def initialize(field, op, bound)
          raise GraphQL::Error, "Unknown comparison: " + op.inspect unless OPS.include?(op)
          @field = field.to_s
          @op = op
          @bound = bound
        end

        attr_reader :field, :op, :bound

        def match?(attributes)
          return false unless Filter.present?(attributes, @field)
          value = Filter.read(attributes, @field)
          comparison = begin
            value <=> @bound
          rescue ArgumentError
            nil
          end
          return false if comparison.nil?
          case @op
          when :gt then comparison > 0
          when :gte then comparison >= 0
          when :lt then comparison < 0
          when :lte then comparison <= 0
          end
        end

        # Only numeric bounds are indexed. A non-numeric (for example, temporal)
        # bound still evaluates correctly through #match?, it just can't narrow
        # the candidate set, so the subscription falls back to a full check.
        def index_expr
          return :unknown unless @bound.is_a?(Numeric)
          { t: :cmp, f: @field, op: @op, b: @bound }
        end
      end

      # All children must match.
      class And < Node
        def initialize(children)
          @children = Filter.flatten(children, And)
        end

        attr_reader :children

        def match?(attributes)
          @children.all? { |child| child.match?(attributes) }
        end

        def index_expr
          expressions = []
          @children.each do |child|
            expr = child.index_expr
            return :unknown if expr == :unknown
            expressions << expr
          end
          # An empty conjunction matches everything; that can't narrow anything.
          return :unknown if expressions.empty?
          { t: :and, c: expressions }
        end
      end

      # At least one child must match.
      class Or < Node
        def initialize(children)
          @children = Filter.flatten(children, Or)
        end

        attr_reader :children

        def match?(attributes)
          @children.any? { |child| child.match?(attributes) }
        end

        def index_expr
          expressions = []
          @children.each do |child|
            expr = child.index_expr
            # A union can't over-approximate an unindexable child any more
            # tightly than "every subscription", so fall back conservatively.
            return :unknown if expr == :unknown
            expressions << expr
          end
          { t: :or, c: expressions }
        end
      end

      # A condition the index can't reason about. The subscription is always
      # kept as a candidate and the wrapped predicate (if any) decides the
      # final result. A raised or +nil+ predicate result is treated as a match
      # so that failures can't silently drop a subscription.
      class Unknown < Node
        def initialize(&predicate)
          @predicate = predicate
        end

        def match?(attributes)
          return true if @predicate.nil?
          result = @predicate.call(attributes)
          result.nil? ? true : !!result
        rescue StandardError
          true
        end

        def index_expr
          :unknown
        end
      end

      class << self
        # @!group Factories

        # @param field [String, Symbol]
        # @param value [Object]
        # @return [Eq]
        def eq(field, value)
          Eq.new(field, value)
        end

        # @param field [String, Symbol]
        # @param values [Enumerable<Object>]
        # @return [In]
        def in(field, values)
          In.new(field, values)
        end

        # @return [Compare]
        def gt(field, bound)
          Compare.new(field, :gt, bound)
        end

        # @return [Compare]
        def gte(field, bound)
          Compare.new(field, :gte, bound)
        end

        # @return [Compare]
        def lt(field, bound)
          Compare.new(field, :lt, bound)
        end

        # @return [Compare]
        def lte(field, bound)
          Compare.new(field, :lte, bound)
        end

        # Inclusive numeric interval.
        # @param min [Object, nil] lower bound (inclusive), if any
        # @param max [Object, nil] upper bound (inclusive), if any
        # @return [Node]
        def between(field, min: nil, max: nil)
          build_between(field, min, max, true, true)
        end

        # Numeric interval with configurable bounds.
        # @param min_inclusive [Boolean]
        # @param max_inclusive [Boolean]
        # @return [Node]
        def range(field, min: nil, max: nil, min_inclusive: true, max_inclusive: true)
          build_between(field, min, max, min_inclusive, max_inclusive)
        end

        # @param children [Array<Node, nil>] +nil+ children are treated as unindexable conditions.
        # @return [And]
        def and(*children)
          And.new(children)
        end

        # @param children [Array<Node, nil>] +nil+ children are treated as unindexable conditions.
        # @return [Or]
        def or(*children)
          Or.new(children)
        end

        # @param predicate [#call, nil] optional exact predicate evaluated on candidates
        # @return [Unknown]
        def unknown(&predicate)
          Unknown.new(&predicate)
        end

        # @!endgroup

        # Parse a plain data structure (Hash/Array, e.g. JSON) into a condition.
        #
        # Leaf format: { "field" => name, "op" => op, "value" => ... }.
        # Supported +op+ values: +eq+ (default), +in+, +gt+, +gte+, +lt+, +lte+,
        # +between+. +and+/+or+ group with an array of child conditions. Any
        # unrecognized structure becomes a conservative Unknown condition.
        # @param spec [Node, Hash, #call, nil]
        # @return [Node]
        def build(spec = nil, &block)
          return spec if spec.is_a?(Node)
          return Unknown.new(&block) if spec.nil? && block
          return Unknown.new(&spec) if spec.respond_to?(:call)
          return unknown if spec.nil?
          return build_hash(spec) if spec.is_a?(Hash)
          unknown
        end

        # @api private
        def present?(attributes, field)
          if attributes.is_a?(Hash)
            attributes.key?(field) || attributes.key?(field.to_sym)
          else
            true
          end
        end

        # @api private
        def read(attributes, field)
          if attributes.is_a?(Hash) && !attributes.key?(field) && attributes.key?(field.to_sym)
            attributes[field.to_sym]
          elsif attributes.respond_to?(:[])
            attributes[field]
          end
        end

        # @api private
        def flatten(children, kind)
          children.flat_map do |child|
            child = child.nil? ? unknown : child
            child.is_a?(kind) ? child.children : [child]
          end
        end

        private

        def build_between(field, min, max, min_inclusive, max_inclusive)
          children = []
          if !min.nil?
            children << (min_inclusive ? gte(field, min) : gt(field, min))
          end
          if !max.nil?
            children << (max_inclusive ? lte(field, max) : lt(field, max))
          end
          return unknown if children.empty?
          children.length == 1 ? children.first : And.new(children)
        end

        def build_hash(hash)
          normalized = {}
          hash.each { |key, value| normalized[key.to_s] = value }

          if normalized.key?("and")
            return And.new(Array(normalized["and"]).map { |child| build(child) })
          elsif normalized.key?("or")
            return Or.new(Array(normalized["or"]).map { |child| build(child) })
          end

          field = normalized["field"] || normalized["f"]
          return unknown if field.nil?
          op = (normalized["op"] || "eq").to_s
          value = normalized.key?("value") ? normalized["value"] : normalized["v"]
          build_leaf(field, op, value, normalized)
        end

        def build_leaf(field, op, value, normalized)
          case op
          when "eq", "==", "="
            Eq.new(field, value)
          when "in", "include"
            In.new(field, value || [])
          when "gt"
            Compare.new(field, :gt, value)
          when "gte", "ge", ">="
            Compare.new(field, :gte, value)
          when "lt"
            Compare.new(field, :lt, value)
          when "lte", "le", "<="
            Compare.new(field, :lte, value)
          when "between"
            build_between_spec(field, value, normalized)
          else
            # Unknown operator: don't guess, keep a conservative fallback.
            unknown
          end
        end

        def build_between_spec(field, value, normalized)
          if value.is_a?(Array)
            min = value[0]
            max = value[1]
          elsif value.is_a?(Hash)
            min = value["min"] || value[:min]
            max = value["max"] || value[:max]
          else
            min = normalized["min"]
            max = normalized["max"]
          end
          build_between(field, min, max, true, true)
        end
      end
    end
  end
end
