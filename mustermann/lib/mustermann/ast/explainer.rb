# frozen_string_literal: true

require 'mustermann/ast/compiler'
require 'mustermann/explanation'

module Mustermann
  module AST
    # On-demand matcher backing {Mustermann::AST::Pattern#explain}.
    #
    # Instead of compiling the AST to a regular expression, it walks the tree
    # and computes, for every node, the set of input positions that can be
    # reached after matching that node (memoized per node and position, so
    # ambiguous patterns do not lead to exponential backtracking). Whenever a
    # node cannot be matched at a given position, an expectation is recorded.
    # At the end, the expectations recorded at the furthest reachable position
    # describe what would have had to be different for the string to match.
    #
    # Since only genuinely reachable states are explored, speculative states
    # that the compiled regular expression could never reach (for instance
    # capture contents ruled out by a look-ahead) do not pollute the result.
    #
    # This is only used when a match has already failed, so normal matching
    # does not pay for any of the tracking done here.
    #
    # @!visibility private
    class Explainer
      # Matches a single character of a default capture.
      DEFAULT_CHAR = /\G[^\/\\?#]/

      # @param [Mustermann::AST::Pattern] pattern the pattern to explain for
      # @param [String] string the string that did not match
      # @return [Mustermann::Explanation] the explanation
      def self.explain(pattern, string)
        new(pattern).explain(string)
      end

      # @param [Mustermann::AST::Pattern] pattern the pattern to explain for
      def initialize(pattern)
        @pattern   = pattern
        @options   = pattern.options
        @except    = @options[:except] if pattern.send(:except_regexp)
        @compiler  = Compiler.new
      end

      # @param [String] string the string that did not match
      # @return [Mustermann::Explanation] the explanation
      def explain(string)
        @string   = string
        @memo     = {}
        @failures = Hash.new { |hash, key| hash[key] = {} }

        ends = match(ast, 0, @options)
        return except_explanation if ends.include? string.length

        ends.each { |stop| record(stop, Explanation::Expectation.end_of_input) }
        position = @failures.keys.max
        Explanation.new(pattern: @pattern, string: string, position: position,
                        expectations: @failures[position].values)
      end

      private

      def ast
        @ast ||= @pattern.to_ast
      end

      def except_explanation
        Explanation.new(pattern: @pattern, string: @string, position: @string.length,
                        expectations: [Explanation::Expectation.except(@except)])
      end

      def record(position, expectation)
        @failures[position][expectation.key] = expectation
      end

      # Computes the set of positions reachable after matching the given node
      # starting at the given position.
      def match(node, position, env)
        @memo[[node.object_id, position, env.object_id]] ||= compute(node, position, env)
      end

      def compute(node, position, env)
        case node.type
        when :root, :group     then sequence(node.payload, position, env)
        when :optional         then match(node.payload, position, env) | [position]
        when :union, :or       then node.payload.flat_map { |branch| match(branch, position, env) }.uniq
        when :char             then literal(node, position, env, encoded: true)
        when :separator        then literal(node, position, env, encoded: false)
        when :capture, :splat, :named_splat, :variable
                               then capture(node, position, env)
        when :with_look_ahead  then look_ahead(node, position, env)
        when :expression       then expression(node, position, env)
        else raise CompileError, "cannot explain #{node.type.inspect} node"
        end
      end

      def sequence(nodes, position, env)
        nodes.inject([position]) do |positions, element|
          positions.flat_map { |each| match(element, each, env) }.uniq
        end
      end

      def literal(node, position, env, encoded:)
        ends = representations(node.payload, env, encoded: encoded).filter_map do |representation|
          position + representation.length if @string[position, representation.length] == representation
        end
        record(position, Explanation::Expectation.literal(node)) if ends.empty?
        ends
      end

      # All raw string representations of a literal character, mirroring
      # Compiler#encoded: URI-escaped variants are accepted when the pattern
      # decodes URIs, separators always match literally.
      def representations(char, env, encoded:)
        return [char] unless encoded and env.fetch(:uri_decode, true)
        Compiler.char_representations(char, uri_decode: true,
                                      space_matches_plus: env.fetch(:space_matches_plus, true))
      end

      def capture(node, position, env)
        ends = capture_ends(node, position, env)
        record(position, capture_expectation(node, env)) if ends.empty?
        ends
      end

      def capture_ends(node, position, env)
        if simple_capture?(node, env)
          scan_default_class(position)
        elsif node.is_a?(:splat) and node.constraint.nil?
          (position..@string.length).to_a
        else
          regexp = full_regexp(node, env)
          (position..@string.length).select { |stop| regexp.match?(@string[position...stop]) }
        end
      end

      # Default captures without any constraint or capture option simply
      # consume a run of characters from the default character class.
      def simple_capture?(node, env)
        node.type == :capture and node.constraint.nil? and
          node.qualifier.nil? and env[:capture].nil?
      end

      def scan_default_class(position)
        stop = position
        stop += 1 while stop < @string.length and DEFAULT_CHAR.match?(@string, stop)
        stop > position ? (position + 1..stop).to_a : []
      end

      # Anchored version of the regexp the compiler produces for the node,
      # used to test whether a substring is a valid capture content.
      def full_regexp(node, env)
        @full_regexps ||= {}
        @full_regexps[[node.object_id, env.object_id]] ||=
          Regexp.new("\\A(?:#{@compiler.translate(node, no_captures: true, **env)})\\z")
      end

      # A look-ahead node constrains how far its head may consume: the head
      # must stop before any position where the remaining pattern could start.
      # Positions beyond that point are unreachable and must not contribute
      # expectations.
      def look_ahead(node, position, env)
        limit = first_forbidden(node, position, env)
        ends  = match(node.head, position, env).select { |stop| stop <= limit }
        record(position, capture_expectation(node.head, env)) if ends.empty?
        ends.flat_map { |stop| sequence(node.payload, stop, env) }.uniq
      end

      # First position at or after the given position where the look-ahead
      # (the remaining pattern) matches.
      def first_forbidden(node, position, env)
        regexp = lookahead_regexp(node, env)
        current = position
        current += 1 until current > @string.length or regexp.match?(@string, current)
        current
      end

      def lookahead_regexp(node, env)
        @lookahead_regexps ||= {}
        @lookahead_regexps[[node.object_id, env.object_id]] ||= begin
          source = node.each_leaf.inject(EMPTY_STRING) do |ahead, element|
            ahead + @compiler.translate(element, skip_optional: true, lookahead: ahead,
                                        greedy: false, no_captures: true, **env).to_s
          end
          Regexp.new("\\G(?:#{source}#{node.at_end ? '$' : '/'})")
        end
      end

      def expression(node, position, env)
        operator = node.operator
        env = env.merge(allow_reserved: operator.allow_reserved,
                        greedy: env.fetch(:greedy, true) && !operator.allow_reserved,
                        parametric: operator.parametric,
                        separator: operator.separator)
        sequence(node.payload, position, env)
      end

      def capture_expectation(node, env)
        return Explanation::Expectation.splat(node) if node.is_a? :splat
        Explanation::Expectation.capture(node, capture_detail(node, env))
      end

      # Constraint details for describing a capture, mirroring the options
      # understood by Compiler::Capture.
      def capture_detail(node, env)
        return node.constraint if node.constraint
        case capture = env[:capture]
        when Hash   then capture_detail_value(capture[node.name.to_sym])
        when nil    then nil
        else             capture_detail_value(capture)
        end
      end

      def capture_detail_value(value)
        case value
        when Class then CONVERTERS[value.name]&.first
        else value
        end
      end
    end
  end
end
