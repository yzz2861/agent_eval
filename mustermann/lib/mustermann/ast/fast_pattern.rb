# frozen_string_literal: true

module Mustermann
  module AST
    # Mixin for AST::Pattern subclasses that accelerates compilation and AST
    # construction for "simple" patterns: only static path segments and
    # unconstrained full-segment captures (e.g. /foo/:bar/baz/:id).
    # Patterns with optional groups, constraints, or non-default options fall
    # through to the full AST pipeline.
    module FastPattern
      # Matches patterns that consist only of slashes, static segments, and
      # simple :name captures — no optional groups, no constraints.
      SIMPLE = /\A(?:\/(?:[a-zA-Z0-9\-_.~]+|:[a-zA-Z_]\w*))+\z/

      # Regexp fragment for each printable ASCII char, matching the same output
      # as Compiler#encoded with uri_decode: true.
      ENCODED = Mustermann.dedup((0..127).each_with_object({}) do |byte, h|
        c   = byte.chr
        pct = '%%%02X' % byte
        reps = [c, pct, pct.downcase].uniq
        h[c] = reps.size == 1 ? Regexp.escape(reps.first) :
          '(?:%s)' % reps.map { |r| Regexp.escape(r) }.join('|')
      end)

      SEGMENT_SCAN = %r{(/)|(:[a-zA-Z_]\w*)|([^/:]+)}

      private_constant :SIMPLE, :ENCODED, :SEGMENT_SCAN

      # Public override: fast path for simple patterns, falls through to super otherwise.
      # Must remain public to match AST::Pattern#to_ast visibility.
      def to_ast
        return super unless simple_pattern? && fast_captures_supported?
        ast = self.class.ast_cache.fetch([@string, options]) { build_fast_ast }
        @param_converters ||= EMPTY_HASH
        ast
      end

      def params(string = nil)
        return super unless @fast_match
        return unless md = @regexp.match(string)
        result = md.named_captures
        result.transform_values! { |v| v.include?('%') ? unescape(v) : v } if string.include?('%')
        result
      end

      private

      def build_match(regexp, string)
        return super unless @fast_match
        return unless match = regexp.match(string)
        params = match.named_captures
        params.transform_values! { |v| v.include?('%') ? unescape(v) : v } if string.include?('%')
        Match.new(self, match, params: params)
      end

      def simple_pattern?
        options[:capture].nil?  &&
          options[:except].nil? &&
          options.fetch(:greedy, true) != false &&
          uri_decode &&
          @string.match?(SIMPLE)
      end

      def fast_captures_supported?
        duplicate_captures == :raise || !fast_duplicate_names?
      end

      # Simple patterns never use optional groups, so any repeated name here is
      # a real duplicate capture rejected by validation on the slow path.
      def fast_duplicate_names?
        @string.scan(/:[a-zA-Z_]\w*/).tally.values.any? { |count| count > 1 }
      end

      def compile(**options)
        return super unless simple_pattern?
        validate_fast_duplicates!(**options) if fast_duplicate_names? && duplicate_captures == :raise
        return super unless fast_captures_supported?
        fast_compile.tap { @fast_match = true }
      end

      def validate_fast_duplicates!(**options)
        validation.validate(build_fast_ast, **options)
      rescue CompileError => error
        raise error.class, "#{error.message}: #{@string.inspect}", error.backtrace
      end

      def fast_compile
        tokens = @string.scan(SEGMENT_SCAN)
        src = String.new
        tokens.each_with_index do |(sep, cap, chars), i|
          if sep
            src << '\\/'
          elsif cap
            # Mirror the compiler: wrap in atomic group when the next token is a separator.
            if tokens[i + 1]&.first
              src << "(?<#{cap[1..]}>(?>[^/\\?#]+))"
            else
              src << "(?<#{cap[1..]}>[^/\\?#]+)"
            end
          else
            chars.each_char { |c| src << ENCODED[c] }
          end
        end
        Regexp.new(src)
      end

      def build_fast_ast
        nodes = []
        pos   = 0
        @string.scan(SEGMENT_SCAN) do |sep, cap, chars|
          if sep
            node = Node::Separator.new('/')
            node.start, node.stop = pos, pos + 1
            nodes << node
            pos += 1
          elsif cap
            node = Node::Capture.new(cap[1..])
            node.start, node.stop = pos, pos + cap.length
            nodes << node
            pos += cap.length
          else
            chars.each_char do |c|
              node = Node::Char.new(c)
              node.start, node.stop = pos, pos + 1
              nodes << node
              pos += 1
            end
          end
        end
        root = Node::Root.new
        root.payload = nodes
        root.pattern = @string
        root.start, root.stop = 0, @string.length
        root
      end
    end
  end
end
