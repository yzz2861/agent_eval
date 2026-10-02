# frozen_string_literal: true
require 'mustermann/ast/compiler'
require 'mustermann/failure'

module Mustermann
  module AST
    # On-demand failure diagnosis for AST patterns.
    #
    # Rather than instrumenting the regular expression (which would tax every
    # successful match), this interpreter walks the same AST the compiler uses
    # and records the furthest input position that was reachable together with
    # the segments expected there.
    # It is only ever invoked from {Mustermann::Pattern#explain} after a regular
    # match has already failed, so normal matching pays no bookkeeping cost.
    #
    # @!visibility private
    class Explainer
      # @param pattern [Mustermann::AST::Pattern] pattern to diagnose against
      # @param string [String] input that failed to match
      # @return [Mustermann::Failure, nil] a failure explanation, or nil if it matches
      def self.explain(pattern, string)
        new(pattern).explain(string)
      end

      def initialize(pattern)
        @pattern       = pattern
        @options       = pattern.options.dup
        @uri_decode    = pattern.uri_decode
        @compiler      = pattern.compiler.new
        @fragment_cache = {}
        @literal_cache  = {}
      end

      # @param string [String] input that failed to match
      # @return [Mustermann::Failure, nil]
      def explain(string)
        @string = string
        @notes  = []
        outcomes = analyze(@pattern.to_ast, 0)

        return excluded_failure if outcomes.include?(string.length)

        farthest = @notes.map(&:first).max.to_i
        expectations = @notes.select { |pos, _| pos == farthest }.map(&:last)
        build_failure(farthest, expectations)
      end

      private

      # Run an AST node starting at +pos+ and return the input positions it can
      # finish at. Failure notes are managed by the calling construct (see
      # {#analyze_union}), so traces of branches that merely got superseded
      # cannot poison the furthest position.
      def analyze(node, pos)
        compute(node, pos)
      end

      def compute(node, pos)
        case node
        when Array                  then analyze_sequence(node, pos)
        when Node[:root]            then analyze_root(node, pos)
        when Node[:union]           then analyze_union(node, pos)
        when Node[:group]           then analyze(node.payload, pos)
        when Node[:expression]      then analyze_expression(node, pos)
        when Node[:optional]        then analyze(node.payload, pos) | [pos]
        when Node[:with_look_ahead] then analyze_with_lookahead(node, pos)
        when Node[:separator], Node[:char]
          analyze_literal(node, pos)
        when Node[:capture], Node[:splat], Node[:named_splat], Node[:variable]
          analyze_capture(node, pos)
        else
          analyze_generic(node, pos)
        end
      end

      # Unknown/future node types do not consume input.
      def analyze_generic(node, pos)
        node.respond_to?(:payload) && node.payload ? analyze(node.payload, pos) : [pos]
      end

      def analyze_sequence(nodes, pos)
        positions = [pos]
        nodes.each do |child|
          positions = positions.flat_map { |p| analyze(child, p) }.uniq
          break if positions.empty?
        end
        positions
      end

      def analyze_root(node, pos)
        outcomes = analyze(node.payload, pos)
        return outcomes.select { |p| p == @string.length } if outcomes.include?(@string.length)

        # The pattern consumed a prefix but trailing characters remain.
        note(outcomes.max, kind: :end, pattern_position: pattern_length) if outcomes.any?
        []
      end

      def analyze_union(node, pos)
        outcomes = []
        failures = []
        node.payload.each do |alternative|
          snapshot = @notes.size
          result   = analyze(alternative, pos)
          if result.empty?
            failures << (@notes.slice!(snapshot..) || [])
          else
            # Speculative traces of a superseded alternative must not survive.
            @notes.slice!(snapshot..)
            outcomes.concat(result)
          end
        end
        if outcomes.empty?
          # Every alternative failed: merge expectations at the furthest
          # position reached by any of them.
          all = failures.flatten(1)
          farthest = all.map(&:first).max.to_i
          all.select { |note_pos, _| note_pos == farthest }.each { |note| @notes << note }
        end
        outcomes.uniq
      end

      def analyze_with_lookahead(node, pos)
        lookahead = build_lookahead(node)
        analyze_capture(node.head, pos, lookahead:).flat_map do |p|
          analyze(node.payload, p)
        end
      end

      # Expressions only differ structurally through their compiled options
      # (operator prefix/separator are inserted into the payload by the
      # transformer); the operator also changes how variables are compiled.
      def analyze_expression(node, pos)
        operator = node.operator
        with_expression_options(allow_reserved: operator.allow_reserved,
                                parametric: operator.parametric,
                                separator: operator.separator) do
          analyze(node.payload, pos)
        end
      end

      def with_expression_options(**expression_options)
        @expression_options ||= {}
        previous = @expression_options
        @expression_options = previous.merge(expression_options)
        begin
          yield
        ensure
          @expression_options = previous
        end
      end

      # Mirrors the look-ahead construction in Mustermann::AST::Compiler so the
      # head capture is constrained exactly like in the compiled regexp.
      def build_lookahead(node)
        options = translate_options.merge(skip_optional: true, greedy: false, no_captures: true)
        lookahead = node.each_leaf.inject(EMPTY_STRING) do |ahead, element|
          ahead + as_source(@compiler.translate(element, **options, lookahead: ahead))
        end
        lookahead << (node.at_end ? '$' : '/')
      end

      # Translators may return a Regexp (e.g. for string/array capture
      # constraints) where surrounding code expects regexp source.
      def as_source(translation)
        return translation unless translation.is_a?(Regexp)
        translation.source.sub(/\A\(\?-mix:/, '(')
      end

      def analyze_literal(node, pos)
        candidates = literal_candidates(node.payload)
        candidates.each do |representation|
          return [pos + representation.length] if @string[pos, representation.length] == representation
        end
        note(pos, kind: :literal, pattern_position: node.start, literal: node.payload)
        []
      end

      def analyze_capture(node, pos, lookahead: nil)
        anchored, bound, min = fragment_for(node, lookahead)
        lengths = candidate_lengths(bound, anchored, pos, min)
        outcomes = lengths.map { |length| pos + length }
        if outcomes.empty? && pos <= @string.length
          note(pos, kind: capture_kind(node), pattern_position: node.start,
               name: capture_name(node), constraint: effective_constraint(node))
        end
        outcomes
      end

      # --- capture machinery -------------------------------------------

      # @return [Array(Regexp, Regexp, Integer)] exact-span fragment, greedy
      #   bound fragment, minimum character length
      def fragment_for(node, lookahead = nil)
        expression = node.is_a?(Node[:variable]) ? @expression_options : nil
        key = [node.object_id, lookahead, expression&.dig(:allow_reserved),
               expression&.dig(:parametric), expression&.dig(:separator)]
        @fragment_cache[key] ||= begin
          @current_fragment_node = node
          options  = fragment_options
          source   = as_source(@compiler.translate(node, no_captures: true, lookahead:,
                                                   **options))
          anchored = Regexp.new("\\A(?:#{source})\\z")
          greedy   = source.gsub(/(\*|\+|\})\?/, '\1')
          bound    = Regexp.new("\\A(?:#{greedy})")
          min      = minimum_length(node)
          [anchored, bound, min]
        end
      end

      def minimum_length(node)
        return 0 if node.is_a?(Node[:splat]) || node.is_a?(Node[:named_splat])
        qualifier = node.respond_to?(:qualifier) ? node.qualifier : nil
        match = qualifier && qualifier.match(/\A\{(\d+)/)
        match ? match[1].to_i : 1
      end

      def translate_options
        @translate_options ||= begin
          options = @options.transform_keys(&:to_sym)
          options[:uri_decode] = @uri_decode unless @uri_decode.nil?
          options[:greedy]     = true unless options.key?(:greedy)
          options
        end
      end

      def fragment_options
        options = translate_options.merge(@expression_options || {})
        options[:greedy] = options.fetch(:greedy, true) && !options[:allow_reserved]
        unless node_variable?
          options.delete(:parametric)
          options.delete(:separator)
        end
        options
      end

      def node_variable?
        @current_fragment_node&.is_a?(Node[:variable])
      end

      # Enumerate character lengths the capture fragment could consume at +pos+,
      # longest first. A greedy prefix match bounds the search; each candidate
      # is then verified with an exact-span match, so backtracking inside one
      # attempted length never leaks a farther but unreachable position.
      def candidate_lengths(bound, anchored, pos, min)
        rest = @string[pos..] || EMPTY_STRING
        match = bound.match(rest)
        return [] unless match
        max = match.to_s.length
        max.downto(min).select { |length| rest[0, length].match?(anchored) }
      end

      def literal_candidates(char)
        @literal_cache[char] ||= @compiler.class.char_representations(
          char, uri_decode: @uri_decode, space_matches_plus: @options.fetch(:space_matches_plus, true)
        )
      end

      def capture_kind(node)
        node.is_a?(Node[:splat]) || node.is_a?(Node[:named_splat]) ? :splat : :capture
      end

      def capture_name(node)
        node.respond_to?(:name) ? node.name : nil
      end

      def effective_constraint(node)
        constraint = node.respond_to?(:constraint) ? node.constraint : nil
        return constraint if constraint
        capture = @options[:capture]
        capture = capture[node.name.to_sym] if capture.is_a?(Hash) && node.respond_to?(:name)
        capture
      end

      # --- notes / result ----------------------------------------------

      def note(position, kind:, pattern_position:, **attributes)
        @notes << [position, Expectation.new(position:, kind:, pattern_position:, **attributes)]
      end

      def pattern_length
        @pattern.to_s.length
      end

      def excluded_failure
        expectation = Expectation.new(position: 0, kind: :excluded, pattern_position: 0)
        build_failure(0, [expectation])
      end

      def build_failure(position, expectations)
        Failure.new(pattern: @pattern, string: @string, position:, expectations:)
      end
    end

    private_constant :Explainer
  end
end
