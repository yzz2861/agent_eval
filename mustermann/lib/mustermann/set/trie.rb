# frozen_string_literal: true
require 'mustermann/ast/translator'
require 'mustermann/set/match'

module Mustermann
  class Set
    class Trie
      class Translator < AST::Translator
        translate(:node) { |trie, **o| trie[t.compile(node)] }
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
              return trie[t.compile(self[i..-1])]
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
      end

      attr_accessor :patterns, :set, :static, :dynamic

      def initialize(set, patterns = nil, repeated_names: EMPTY_ARRAY)
        @set             = set
        @patterns        = nil
        @dynamic         = nil
        @static          = nil
        @stride          = nil
        @fast_static     = nil
        @byte_lookup     = nil
        @dynamic_entries = nil
        @repeated_names  = repeated_names
        @repeated_names  = @repeated_names.dup if @repeated_names.frozen?
        patterns&.each { |pattern| add(pattern) }
      end

      def [](key)
        case key = Mustermann.dedup(key)
        when String
          @static      ||= {}
          @static[key] ||= Trie.new(@set, repeated_names: @repeated_names)
        when Regexp
          @dynamic      ||= {}
          @dynamic[key] ||= Trie.new(@set, repeated_names: @repeated_names)
        end
      end

      def match(string, all: false, peek: false, position: 0, params: {}, ranges: {})
        optimize! if @stride.nil?
        return build_matches(string, params, all:, ranges:) if position >= string.size
        result = [] if all

        if @fast_static
          stride = @stride
          if node = @fast_static[string[position, stride]]
            if nested_result = node.match(string, all:, peek:, position: position + stride, params:, ranges:)
              return nested_result unless all
              result.concat(nested_result)
            end
          end
        elsif @byte_lookup
          if node = @byte_lookup[string.getbyte(position)]
            if nested_result = node.match(string, all:, peek:, position: position + 1, params:, ranges:)
              return nested_result unless all
              result.concat(nested_result)
            end
          end
        end

        if @dynamic_entries&.any?
          base_params = all ? params : nil
          base_ranges = all ? ranges : nil
          @dynamic_entries.each do |matcher, node, capture_names, fast_name|
            if fast_name
              # Fast path: unconstrained single-segment capture — no regex, no MatchData.
              end_char = string.index('/', position) || string.size
              end_pos  = string.byteslice(0, end_char).bytesize
              next if end_pos == position
              edge_params = all ? base_params.dup : params
              edge_ranges = all ? base_ranges.dup : ranges
              edge_params[fast_name] = string.byteslice(position, end_pos - position)
              append_range(edge_ranges, fast_name, byte_to_char(string, position)...byte_to_char(string, end_pos))
              nested_result = node.match(string, all:, params: edge_params, ranges: edge_ranges, peek:, position: end_pos)
              return nested_result unless all
              result.concat(nested_result)
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

            edge_params = all ? base_params.dup : params
            edge_ranges = all ? base_ranges.dup : ranges
            matcher.named_captures.each do |name, groups|
              groups.each do |group|
                start, stop = regexp_match.offset(group)
                next if start.nil? || start < 0
                value = regexp_match[group]
                existing = edge_params[name]
                edge_params[name] = existing ? (existing.is_a?(Array) ? existing << value : [existing, value]) : value
                append_range(edge_ranges, name, byte_to_char(string, start)...byte_to_char(string, stop))
              end
            end

            nested_result = node.match(string, all:, params: edge_params, ranges: edge_ranges, peek:, position: regexp_match.end(0))
            return nested_result unless all
            result.concat(nested_result)
          end
        end

        if peek
          matches = build_matches(string, params, all:, ranges:, matched_length: position, post_match: string[position..], pre_match: EMPTY_STRING)
          return matches unless all
          result.concat(matches)
        end

        result
      end

      NIL_VALUES = [nil].freeze

      def build_matches(string, params, all: false, ranges: {}, matched_length: string.size, post_match: EMPTY_STRING, pre_match: EMPTY_STRING)
        result = [] if all
        matched = string[0, matched_length]

        @patterns&.each do |pattern|
          next if pattern.except_regexp&.match?(matched)

          next unless valid_edge_params?(pattern, params)
          pattern_params, pattern_ranges = build_pattern_params(pattern, params, ranges)

          values = @set.values_for_pattern(pattern) || NIL_VALUES
          values.each do |value|
            match = Set::Match.new(pattern, string, matched:, params: pattern_params, value:, post_match:, pre_match:, capture_ranges: pattern_ranges)
            return match unless all
            result << match
          end
        end

        result
      end

      def build_pattern_params(pattern, params, ranges)
        if pattern.identity_params?(params)
          finalized = params
          pattern.capture_occurrences.each do |key, count|
            next unless count > 1
            finalized = finalized.dup if finalized.equal?(params)
            if pattern.collect_capture?(key)
              value = finalized.fetch(key, EMPTY_ARRAY)
              finalized[key] = value.is_a?(Array) ? value : [value]
            end
          end
          return [finalized, finalize_ranges(pattern, ranges)]
        end
        result = {}
        params.each do |key, raw|
          if raw.is_a?(Array)
            val = raw.flat_map { |v| pattern.map_param(key, v) }
            val = val.first if (val.size < 2 || pattern.equal_capture?(key)) &&
              !pattern.always_array?(key) && !pattern.collect_capture?(key)
          else
            val = pattern.map_param(key, raw)
            val = [val] if pattern.always_array?(key)
          end
          result[key] = val
        end
        [result, finalize_ranges(pattern, ranges)]
      end

      def append_range(ranges, name, range)
        existing = ranges[name]
        ranges[name] = existing.is_a?(Array) ? existing.dup << range : existing ? [existing, range] : range
      end

      # Gives repeated captures one entry per occurrence (nil for absent
      # optional occurrences), matching the regular expression based match path.
      def finalize_ranges(pattern, ranges)
        pattern.capture_occurrences.each_with_object({}) do |(name, count), result|
          next unless ranges.key?(name)
          value = ranges[name]
          list = (count > 1 && value.is_a?(Array) ? value : [value]).first(count)
          result[name] = count > 1 ? list.dup.fill(nil, list.length...count) : value
        end.merge(ranges.reject { |name, _| pattern.repeated_capture?(name) })
      end

      # Checks the +:equal+ strategy against raw (still encoded) values; decoding
      # is applied afterwards and preserves equality.
      def valid_edge_params?(pattern, params)
        return true unless pattern.duplicate_captures == :equal
        pattern.capture_occurrences.all? do |name, count|
          next true unless count > 1
          value = params[name]
          next true if value.nil?
          values = value.is_a?(Array) ? value : [value]
          values.map { |v| pattern.map_param(name, v) }.uniq.size <= 1
        end
      end

      # Converts a byte offset into a character offset.
      def byte_to_char(string, byte_offset)
        string.byteslice(0, byte_offset).length
      end

      def add(pattern)
        @stride          = nil
        @fast_static     = nil
        @byte_lookup     = nil
        @dynamic_entries = nil
        if pattern.respond_to?(:capture_occurrences)
          pattern.capture_occurrences.each { |name, count| @repeated_names << name if count > 1 }
        end
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
          names = matcher.names.each(&:freeze)
          # Detect unconstrained single-segment captures: can use fast string.index instead of regex.
          # Two conditions: (1) the edge is a bare capture (source starts with \G(?<name>), no leading
          # static chars) and (2) the capture's character class excludes '/' (PATH_INFO never has '?' or '#').
          fast = if names.size == 1
            name = names.first
            !@repeated_names.include?(name) && matcher.source.start_with?("\\G(?<#{name}>") && !matcher.match?('/') ? name : nil
          end
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
