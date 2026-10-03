# frozen_string_literal: true
require 'mustermann/ast/translator'
require 'mustermann/set/match'

module Mustermann
  class Set
    class Trie
      class Translator < AST::Translator
        translate(:node) do |trie, **options|
          regexp = t.compile(node)
          trie.mark_fast_capture(regexp, node.name) if t.fast_capture?(node)
          trie[regexp]
        end
        translate(:separator) { |trie, **options| trie[payload] }

        translate(:root) do |trie, **options|
          leaves = t(payload, trie, **options)
          if leaves.is_a? Array
            leaves.each do |leaf|
              leaf.patterns ||= []
              leaf.patterns << t.pattern
            end
          else
            leaves.patterns ||= []
            leaves.patterns << t.pattern
          end
          leaves
        end

        translate(:char) do |trie, **options|
          return trie if payload.empty?
          trie[payload]
        end

        translate(:optional) do |trie, **options|
          [*t(payload, trie, **options), trie]
        end

        translate(Array) do |trie, **options|
          i = 0
          while i < size
            element = self[i]
            if element.is_a? :char or element.is_a? :separator
              trie = t(element, trie, **options)
              i += 1
            elsif element.is_a? :splat and self[i + 1]&.is_a? :separator
              # Compile splat+separator together so the splat is bounded by the separator,
              # then continue building the trie for the remaining elements.
              trie = trie[t.compile(self[i..i + 1])]
              i += 2
            elsif element.is_a? :splat or !self[i + 1]&.is_a? :separator
              remaining = self[i..-1]
              # A single remaining non-splat node compiles to the same regexp as on the
              # node path; route it through there so fast captures are detected.
              return t(element, trie, **options) if remaining.size == 1
              return trie[t.compile(remaining)]
            else
              trie = t(element, trie, **options)
              return trie.flat_map { |node| t(self[i + 1..-1], node, **options) } if trie.is_a? Array
              i += 1
            end
          end
          trie
        end

        attr_reader :pattern

        def initialize(pattern)
          @pattern  = pattern
          @compiler = pattern.compiler.new
          @options  = pattern.options
          super()
        end

        # \G anchors to a position passed to String#match, avoiding substring allocation.
        def compile(node, **options) = /\G#{@compiler.translate(node, **@options, **options)}/

        # Is the node an unconstrained single-segment capture? Only those may use
        # the regex-free fast path: anything else (constraints, splats, optional
        # groups, repeated capture names compiled into a single edge) needs the
        # actual regexp to decide what matches.
        # @!visibility private
        def fast_capture?(node)
          return false unless node.is_a?(:capture) && !node.is_a?(:splat)
          return false if node.constraint
          case capture = @options[:capture]
          when nil  then true
          when Hash then capture[node.name.to_sym].nil?
          else false
          end
        end
      end

      attr_accessor :patterns, :set, :static, :dynamic

      def initialize(set, patterns = nil)
        @set             = set
        @patterns        = nil
        @dynamic         = nil
        @static          = nil
        @stride          = nil
        @fast_static     = nil
        @byte_lookup     = nil
        @dynamic_entries = nil
        patterns&.each { |pattern| add(pattern) }
      end

      def [](key)
        case key = Mustermann.dedup(key)
        when String
          @static      ||= {}
          @static[key] ||= Trie.new(@set)
        when Regexp
          @dynamic      ||= {}
          @dynamic[key] ||= Trie.new(@set)
        end
      end

      # Marks an edge regexp as being exactly an unconstrained single-segment
      # capture with the given name, making it eligible for the regex-free
      # fast path. Called by the Translator while building edges.
      # @!visibility private
      def mark_fast_capture(regexp, name)
        @fast_captures ||= {}
        @fast_captures[regexp] = name
      end

      def match(string, all: false, peek: false, position: 0, params: {})
        optimize! if @stride.nil?
        return build_matches(string, params, all:) if position >= string.size
        result = [] if all

        if @fast_static
          stride = @stride
          if node = @fast_static[string[position, stride]]
            if nested_result = node.match(string, all:, peek:, position: position + stride, params:)
              return nested_result unless all
              result.concat(nested_result)
            end
          end
        elsif @byte_lookup
          if node = @byte_lookup[string.getbyte(position)]
            if nested_result = node.match(string, all:, peek:, position: position + 1, params:)
              return nested_result unless all
              result.concat(nested_result)
            end
          end
        end

        if @dynamic_entries&.any?
          # Duplicate the params whenever sibling edges or a peek fallback might
          # run after a failed attempt, so a failing edge cannot pollute them.
          base_params = params if all || peek || @dynamic_entries.size > 1
          @dynamic_entries.each do |matcher, node, capture_names, fast_name|
            if fast_name
              # Fast path: unconstrained single-segment capture — no regex, no MatchData.
              end_pos = string.index('/', position) || string.size
              next if end_pos == position
              edge_params = base_params ? base_params.dup : params
              value = string.byteslice(position, end_pos - position)
              existing = edge_params[fast_name]
              edge_params[fast_name] = existing ? (existing.is_a?(Array) ? existing + [value] : [existing, value]) : value
              nested_result = node.match(string, all:, params: edge_params, peek:, position: end_pos)
              if nested_result
                return nested_result unless all
                result.concat(nested_result)
              end
              next
            end

            regexp_match = matcher.match(string, position)
            # Non-greedy patterns (e.g. splat .*?) can match 0 chars on non-empty input, making
            # no progress. Retry with an end-of-string anchor so they consume the full remainder.
            if regexp_match && regexp_match.end(0) == position
              @@anchored ||= {}
              anchored_matcher = @@anchored[matcher] ||= Mustermann.dedup(Regexp.new(matcher.source + '\z'))
              regexp_match = anchored_matcher.match(string, position)
            end
            next unless regexp_match

            edge_params = base_params ? base_params.dup : params
            capture_names.each do |name, positions|
              positions.each do |pos|
                value = regexp_match[pos]
                next unless value
                existing = edge_params[name]
                edge_params[name] = existing ? (existing.is_a?(Array) ? existing + [value] : [existing, value]) : value
              end
            end

            nested_result = node.match(string, all:, params: edge_params, peek:, position: regexp_match.end(0))
            if nested_result
              return nested_result unless all
              result.concat(nested_result)
            end
          end
        end

        if peek
          matches = build_matches(string, params, all:, matched_length: position, post_match: string[position..], pre_match: EMPTY_STRING)
          return matches unless all
          result.concat(matches)
        end

        result
      end

      NIL_VALUES = [nil].freeze

      def build_matches(string, params, all: false, matched_length: string.size, post_match: EMPTY_STRING, pre_match: EMPTY_STRING)
        result = [] if all
        matched = string[0, matched_length]

        @patterns&.each do |pattern|
          next if pattern.except_regexp&.match?(matched)

          pattern_params = build_pattern_params(pattern, params) or next

          values = @set.values_for_pattern(pattern) || NIL_VALUES
          values.each do |value|
            match = Set::Match.new(pattern, string, matched:, params: pattern_params, value:, post_match:, pre_match:)
            return match unless all
            result << match
          end
        end

        result
      end

      # Applies the pattern's param mapping (and duplicate capture name
      # strategy, if any) to the raw params collected while traversing the
      # trie. Returns nil if an on_duplicate: :check strategy rejects the
      # values, so the pattern is skipped just like a non-matching pattern.
      def build_pattern_params(pattern, params)
        strategy = pattern.duplicate_strategy
        return params if !strategy && pattern.identity_params?(params)

        duplicates = strategy ? pattern.duplicate_names : nil
        result = {}
        params.each do |key, raw|
          if duplicates&.include?(key)
            values = (raw.is_a?(Array) ? raw : [raw]).filter_map { |v| pattern.map_param(key, v) }
            if strategy == :check
              return nil if values.uniq.size > 1
              result[key] = values.first
            else
              result[key] = values
            end
          elsif raw.is_a?(Array)
            val = raw.flat_map { |v| pattern.map_param(key, v) }
            val = val.first if val.size < 2 && !pattern.always_array?(key)
            result[key] = val
          else
            val = pattern.map_param(key, raw)
            val = [val] if pattern.always_array?(key)
            result[key] = val
          end
        end

        # Occurrences inside optional groups that did not participate leave no
        # trace in the collected params; fill in the same default the linear
        # matcher would produce.
        duplicates&.each do |name|
          next if result.key?(name)
          result[name] = strategy == :collect ? [] : nil
        end
        result
      end

      def add(pattern)
        @stride          = nil
        @fast_static     = nil
        @byte_lookup     = nil
        @dynamic_entries = nil
        Translator.new(pattern).translate(pattern.to_ast, self)
      end

      # Compacts the trie by replacing sequential single-char static lookups with a
      # single stride-length hash lookup. The stride is the minimum number of static
      # steps all paths from this node share before hitting a dynamic edge or branch.
      def optimize!
        depth = min_static_depth
        if depth > 1
          @fast_static = build_stride_hash(depth)
          @byte_lookup = nil
          @stride      = depth
          @fast_static.each_value(&:optimize!)
        elsif !@static&.any?
          @fast_static = nil
          @byte_lookup = nil
          @stride      = 1
          # no children to recurse into
        else
          @fast_static = nil
          @byte_lookup = Array.new(256)
          @stride      = 1
          @static&.each { |k, v| @byte_lookup[k.getbyte(0)] = v }
          @static&.each_value(&:optimize!)
        end

        @dynamic&.each_value(&:optimize!)
        @dynamic_entries = @dynamic&.map do |matcher, node|
          # Capture names mapped to their group positions, so edges containing
          # repeated capture names collect every occurrence in order.
          names = matcher.named_captures
          # Only edges marked by the translator as exactly one unconstrained
          # single-segment capture may use the fast string.index path. The
          # capture must also be unable to match a lone '/' (reserved URI
          # template captures include it in their character class).
          fast = @fast_captures&.[](matcher) unless matcher.match?('/')
          [matcher, node, names, fast]
        end

        @fast_static     = Mustermann.dedup(@fast_static)
        @dynamic_entries = Mustermann.dedup(@dynamic_entries)
        @byte_lookup     = Mustermann.dedup(@byte_lookup)
      end

      protected

      # Returns the minimum number of guaranteed static steps from this node across
      # all possible paths, before encountering a dynamic edge, a terminal pattern,
      # or an empty node. Branching is allowed; only the minimum depth matters.
      def min_static_depth
        return 0 if @dynamic&.any?
        return 0 if @patterns&.any?
        return 0 if @static&.empty?
        1 + @static.values.map { |node| node.min_static_depth }.min
      end

      private

      # Builds a hash whose keys are +stride+-character strings and whose values are
      # the trie nodes reached after consuming exactly those characters.
      def build_stride_hash(stride)
        stride.times.reduce({ EMPTY_STRING => self }) do |frontier, _|
          frontier.each_with_object({}) do |(prefix, node), nxt|
            node.static.each { |char, child| nxt[prefix + char] = child }
          end
        end
      end

    end

    private_constant :Trie
  end
end
