# frozen_string_literal: true

require 'set'

module JSON
  class JSONPathError < JSONError; end

  # A compiled JSONPath query.
  #
  # Supported syntax includes +$+, dot and quoted bracket members, array
  # indexes, unions, +*+, recursive descent +..+, slices with negative bounds
  # and steps, filters with +!+, +&&+, +||+, parentheses, +==+, +!=+, +<+,
  # +<=+, +>+, +>=+, current +@+ queries, and root +$+ queries.
  #
  # Filter functions, regular expressions, and any other unsupported syntax
  # raise JSON::JSONPathError while the expression is compiled.
  #
  # A member that exists and has a JSON +null+ value is represented by Ruby
  # +nil+ and remains distinct from a member that does not exist. Filter
  # existence tests use node-list emptiness rather than Ruby truthiness, and
  # <tt>@.x && @.x != null</tt> requires a present non-null member.
  class JSONPath
    # One selected node. +value+ is the selected Ruby value and +path+ is the
    # normalized JSONPath string for that value.
    Result = Struct.new(:value, :path) do
      def initialize(value, path)
        super
        freeze
      end
    end

    NOTHING = Object.new.freeze
    private_constant :NOTHING

    def self.compile(expression)
      new(expression)
    end

    def initialize(expression)
      string = String.try_convert(expression)
      unless string
        raise TypeError, "no implicit conversion of #{expression.class} into String"
      end

      @expression = string.dup.freeze
      @segments = Parser.new(@expression).parse.freeze
      freeze
    end

    attr_reader :expression

    def query(data)
      nodes = [[data, []]]
      @segments.each do |kind, selector|
        nodes = apply_segment(kind, selector, data, nodes)
      end
      nodes.map { |value, path| Result.new(value, serialize_path(path)) }.freeze
    end

    def values_at(data)
      query(data).map(&:value)
    end

    private

    def apply_segment(kind, selector, root, nodes)
      result = []

      nodes.each do |value, path|
        if kind == :child
          apply_selector(selector, value, path, root, value, result)
        else
          each_descendant(value, path) do |descendant, descendant_path|
            apply_selector(selector, descendant, descendant_path, root, descendant, result)
          end
        end
      end

      dedupe(result)
    end

    def each_descendant(value, path, seen = Set.new)
      return unless container?(value)

      if Array === value
        value.each_with_index do |child, index|
          visit_descendant(child, path + [index], seen) do |descendant, descendant_path|
            yield descendant, descendant_path
          end
        end
      else
        value.each_key do |key|
          visit_descendant(value[key], path + [key], seen) do |descendant, descendant_path|
            yield descendant, descendant_path
          end
        end
      end
    end

    def visit_descendant(value, path, seen, &block)
      return unless container?(value)
      return unless seen.add?(value.object_id)

      block.call(value, path)

      if Array === value
        value.each_with_index do |child, index|
          visit_descendant(child, path + [index], seen, &block)
        end
      else
        value.each_key do |key|
          visit_descendant(value[key], path + [key], seen, &block)
        end
      end
    ensure
      seen.delete(value.object_id)
    end

    def apply_selector(selector, value, path, root, current, result)
      case selector[0]
      when :member
        name = selector[1]
        if Hash === value && value.key?(name)
          result << [value.fetch(name), path + [name]]
        end
      when :index
        append_index(selector[1], value, path, result)
      when :wildcard
        append_wildcard(value, path, result)
      when :slice
        append_slice(selector, value, path, result)
      when :filter
        append_filter(selector[1], value, path, root, result)
      when :selectors
        selector[1].each do |child|
          apply_selector(child, value, path, root, current, result)
        end
      end
    end

    def append_index(index, value, path, result)
      return unless Array === value

      normalized = index < 0 ? index + value.length : index
      return unless normalized >= 0 && normalized < value.length

      result << [value[normalized], path + [normalized]]
    end

    def append_wildcard(value, path, result)
      if Array === value
        value.each_with_index { |child, index| result << [child, path + [index]] }
      elsif Hash === value
        value.each { |key, child| result << [child, path + [key]] }
      end
    end

    def append_slice(selector, value, path, result)
      return unless Array === value

      _, start, stop, step = selector
      each_slice_index(start, stop, step, value.length) do |index|
        result << [value[index], path + [index]]
      end
    end

    def append_filter(ast, value, path, root, result)
      if Array === value
        value.each_with_index do |child, index|
          result << [child, path + [index]] if filter_value(ast, root, child)
        end
      else
        result << [value, path] if filter_value(ast, root, value)
      end
    end

    def each_slice_index(start, stop, step, size)
      if step > 0
        start = positive_slice_bound(start, size, 0)
        stop = positive_slice_bound(stop, size, size)
        while start < stop
          yield start
          start += step
        end
      else
        start = negative_slice_start(start, size)
        stop = negative_slice_stop(stop, size)
        while start > stop
          yield start
          start += step
        end
      end
    end

    def positive_slice_bound(value, size, default)
      return default if value.nil?
      return [value, size].min if value >= 0

      [value + size, 0].max
    end

    def negative_slice_start(value, size)
      return size - 1 if value.nil?
      return [value, size - 1].min if value >= 0

      [value + size, 0].max
    end

    def negative_slice_stop(value, size)
      return -1 if value.nil?
      return [value, size - 1].min if value >= 0

      [value + size, -1].max
    end

    def filter_value(ast, root, current)
      kind, payload = ast

      case kind
      when :or
        filter_value(payload[0], root, current) || filter_value(payload[1], root, current)
      when :and
        filter_value(payload[0], root, current) && filter_value(payload[1], root, current)
      when :not
        !filter_value(payload, root, current)
      when :group
        !!filter_value(payload, root, current)
      when :boolean
        payload
      when :comparison
        compare(payload[0], payload[1], payload[2], root, current)
      when :query
        !query_nodes(payload, root, current).empty?
      else
        raise JSONPathError, "invalid filter expression"
      end
    end

    def compare(left, operator, right, root, current)
      left_value = comparison_value(left, root, current)
      right_value = comparison_value(right, root, current)

      case operator
      when '=='
        return false if left_value.equal?(NOTHING) || right_value.equal?(NOTHING)
        values_equal?(left_value, right_value)
      when '!='
        return true if left_value.equal?(NOTHING) || right_value.equal?(NOTHING)
        !values_equal?(left_value, right_value)
      when '<', '<=', '>', '>='
        return false if left_value.equal?(NOTHING) || right_value.equal?(NOTHING)
        values_ordered?(left_value, right_value, operator)
      else
        raise JSONPathError, "unsupported comparison operator #{operator.inspect}"
      end
    end

    def comparison_value(node, root, current)
      case node[0]
      when :literal
        node[1]
      when :query
        values = query_nodes(node[1], root, current)
        values.length == 1 ? values.first : NOTHING
      else
        raise JSONPathError, "invalid comparison expression"
      end
    end

    def values_equal?(left, right)
      if Numeric === left && Numeric === right
        left == right
      elsif (Array === left && Array === right) || (Hash === left && Hash === right)
        left == right
      elsif left.nil?
        right.nil?
      elsif left.equal?(true) || left.equal?(false)
        left.equal?(right)
      elsif String === left
        String === right && left == right
      else
        false
      end
    end

    def values_ordered?(left, right, operator)
      return false unless ((Numeric === left && Numeric === right) ||
                           (String === left && String === right))

      left.public_send(operator, right)
    end

    def query_nodes(query, root, current)
      base = query[0] == :root ? root : current
      nodes = [[base, []]]

      query[1].each do |kind, selector|
        next_nodes = []
        nodes.each do |value, path|
          if kind == :child
            apply_selector(selector, value, path, root, value, next_nodes)
          else
            each_descendant(value, path) do |descendant, descendant_path|
              apply_selector(selector, descendant, descendant_path, root, descendant, next_nodes)
            end
          end
        end
        nodes = dedupe(next_nodes)
      end

      nodes.map(&:first)
    end

    def container?(value)
      Array === value || Hash === value
    end

    def dedupe(nodes)
      seen = Set.new
      nodes.select do |_, path|
        seen.add?(path)
      end
    end

    def serialize_path(segments)
      rendered = segments.map do |segment|
        if Integer === segment
          "[#{segment}]"
        else
          "['#{escape_member(segment)}']"
        end
      end.join
      "$#{rendered}".freeze
    end

    def escape_member(member)
      member.gsub(/[\\'\b\f\n\r\t\x00-\x07\x0b\x0e-\x1f]/) do |character|
        case character
        when '\\' then '\\\\'
        when "'" then "\\'"
        when "\b" then '\\b'
        when "\f" then '\\f'
        when "\n" then '\\n'
        when "\r" then '\\r'
        when "\t" then '\\t'
        else format('\\u%04x', character.ord)
        end
      end
    end

    class Parser
      NUMBER = /\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/
      INTEGER = /\G-?(?:0|[1-9][0-9]*)/
      private_constant :NUMBER, :INTEGER

      def initialize(expression)
        @expression = expression
        @position = 0
      end

      def parse
        expect('$')
        segments = []

        until end?
          if peek == '.'
            advance
            if peek == '.'
              advance
              segments << [:descendant, parse_descendant_segment]
            else
              segments << [:child, parse_dot_segment]
            end
          elsif peek == '['
            segments << parse_bracket_segment(false)
          else
            error('expected a path segment')
          end
        end

        segments
      end

      private

      def parse_descendant_segment
        if peek == '['
          _, selector = parse_bracket_segment(true)
          selector
        elsif peek == '*'
          advance
          [:wildcard]
        else
          [:member, parse_name]
        end
      end

      def parse_dot_segment
        if peek == '*'
          advance
          [:wildcard]
        else
          [:member, parse_name]
        end
      end

      def parse_bracket_segment(descendant)
        expect('[')
        skip_whitespace

        if peek == '?'
          selector = [:filter, parse_filter_body]
          skip_whitespace
          expect(']')
          return [descendant ? :descendant : :child, selector]
        end

        selectors = []
        loop do
          skip_whitespace
          selectors << parse_bracket_selector
          skip_whitespace
          break unless peek == ','

          advance
        end

        expect(']')
        selector = selectors.length == 1 ? selectors.first : [:selectors, selectors]
        [descendant ? :descendant : :child, selector]
      end

      def parse_bracket_selector
        case peek
        when '*'
          advance
          [:wildcard]
        when "'", '"'
          [:member, parse_string]
        when '-', ':', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
          parse_index_or_slice
        else
          error('expected a member name, index, wildcard, or slice')
        end
      end

      def parse_index_or_slice
        start = try_integer
        skip_whitespace

        if start.nil? && peek == ':'
          start = nil
          skip_whitespace
        end

        if peek == ':'
          advance
          skip_whitespace
          stop = try_integer
          skip_whitespace
          step = 1

          if peek == ':'
            advance
            skip_whitespace
            step = integer!
            error('slice step cannot be zero') if step.zero?
          end

          skip_whitespace
          [:slice, start, stop, step]
        else
          error('expected an array index') unless start
          [:index, start]
        end
      end

      def parse_filter_body
        expect('?')
        skip_whitespace
        expression = parse_or
        skip_whitespace
        expression
      end

      def parse_or
        left = parse_and
        skip_whitespace
        if match_keyword('||')
          [:or, [left, parse_or]]
        else
          left
        end
      end

      def parse_and
        left = parse_not
        skip_whitespace
        if match_keyword('&&')
          [:and, [left, parse_and]]
        else
          left
        end
      end

      def parse_not
        skip_whitespace
        if match_keyword('!') && !at?('=')
          [:not, parse_not]
        else
          parse_basic
        end
      end

      def parse_basic
        skip_whitespace
        if peek == '('
          advance
          expression = parse_or
          skip_whitespace
          expect(')')
          return [:group, expression]
        end

        primary = parse_primary
        skip_whitespace
        if comparison_operator?
          operator = parse_comparison_operator
          right = parse_comparison_operand
          return [:comparison, [primary, operator, right]]
        end

        if primary[0] == :literal
          error('filter expression must be a boolean test')
        end

        primary
      end

      def parse_primary
        if peek == '$' || peek == '@'
          query = parse_query
          unless query[2]
            skip_whitespace
            error('comparisons require a singular query') if comparison_operator?
          end
          [:query, query]
        elsif peek == 't' || peek == 'f'
          [:boolean, parse_boolean_value]
        elsif at_keyword?('null')
          advance_keyword('null')
          [:literal, nil]
        elsif peek == "'" || peek == '"'
          [:literal, parse_string]
        elsif number_start?
          [:literal, parse_number]
        else
          error('expected a filter expression')
        end
      end

      def parse_comparison_operand
        skip_whitespace
        operand =
          if peek == '$' || peek == '@'
            query = parse_query
            error('comparisons require a singular query') unless query[2]
            [:query, query]
          elsif at_keyword?('null')
            advance_keyword('null')
            [:literal, nil]
          elsif peek == 't' || peek == 'f'
            [:literal, parse_boolean_value]
          elsif peek == "'" || peek == '"'
            [:literal, parse_string]
          elsif number_start?
            [:literal, parse_number]
          else
            error('expected a comparison value')
          end
        skip_whitespace
        operand
      end

      def parse_query
        root = peek == '$'
        advance
        segments = []

        loop do
          if peek == '.'
            advance
            if peek == '.'
              advance
              if peek == '['
                kind, selector = parse_bracket_segment(true)
              else
                kind = :descendant
                selector = peek == '*' ? consume_wildcard : [:member, parse_name]
              end
              segments << [kind, selector]
            else
              segments << [:child, peek == '*' ? consume_wildcard : [:member, parse_name]]
            end
          elsif peek == '['
            kind, selector = parse_bracket_segment(false)
            segments << [kind, selector]
          else
            break
          end
        end

        singular = segments.all? do |kind, selector|
          kind == :child && (selector[0] == :member || selector[0] == :index)
        end
        [root ? :root : :current, segments, singular]
      end

      def consume_wildcard
        advance
        [:wildcard]
      end

      def parse_boolean_value
        if at_keyword?('true')
          advance_keyword('true')
          true
        elsif at_keyword?('false')
          advance_keyword('false')
          false
        else
          error('expected true or false')
        end
      end

      def parse_number
        value = scan(NUMBER)
        error('invalid number') unless value
        value.include?('.') || value.include?('e') || value.include?('E') ? Float(value) : Integer(value)
      end

      def try_integer
        value = scan(INTEGER)
        return nil unless value
        error('negative zero is not a valid index or slice bound') if value == '-0'
        Integer(value)
      end

      def integer!
        value = try_integer
        error('expected an integer') unless value
        value
      end

      def parse_name
        start = scan(/\G(?:[A-Za-z_\u0080-\u{D7FF}\u{E000}-\u{FFFF}]|[\u{10000}-\u{EFFFF}])/)
        error('expected a member name') unless start
        rest = scan(/\G(?:[A-Za-z0-9_\u0080-\u{D7FF}\u{E000}-\u{FFFF}]|[\u{10000}-\u{EFFFF}])*/)
        start + rest
      end

      def parse_string
        quote = peek
        advance
        result = +''

        until end?
          character = advance
          if character == quote
            return result
          elsif character == '\\'
            result << parse_escape
          elsif character.ord < 0x20
            error('unescaped control character in string')
          else
            result << character
          end
        end

        error('unterminated string')
      end

      def parse_escape
        error('unterminated escape') if end?
        character = advance

        case character
        when "'", '"', '\\', '/' then character
        when 'b' then "\b"
        when 'f' then "\f"
        when 'n' then "\n"
        when 'r' then "\r"
        when 't' then "\t"
        when 'u'
          code = unicode_hex
          if code >= 0xD800 && code <= 0xDBFF
            if at?('\\') && @expression[@position + 1] == 'u'
              advance
              advance
              low = unicode_hex
              if low >= 0xDC00 && low <= 0xDFFF
                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
              else
                error('invalid Unicode surrogate pair')
              end
            else
              error('expected Unicode low surrogate')
            end
          end
          [code].pack('U')
        else
          error('invalid string escape')
        end
      end

      def unicode_hex
        digits = @expression[@position, 4]
        error('invalid Unicode escape') unless digits && digits.match?(/\A[0-9a-fA-F]{4}\z/)
        @position += 4
        digits.to_i(16)
      end

      def comparison_operator?
        at?('==') || at?('!=') || at?('<=') || at?('>=') || at?('<') || at?('>')
      end

      def parse_comparison_operator
        if at?('==') || at?('!=') || at?('<=') || at?('>=')
          operator = @expression[@position, 2]
          @position += 2
          operator
        elsif at?('<') || at?('>')
          advance
        else
          error('expected a comparison operator')
        end
      end

      def number_start?
        at?('-') || (peek >= '0' && peek <= '9')
      end

      def at_keyword?(keyword)
        at?(keyword) && !name_character?(@expression[@position + keyword.length])
      end

      def match_keyword(keyword)
        if at?(keyword)
          @position += keyword.length
          true
        else
          false
        end
      end

      def advance_keyword(keyword)
        error("expected #{keyword}") unless at_keyword?(keyword)
        @position += keyword.length
      end

      def name_character?(character)
        return false unless character
        character.match?(/\A(?:[A-Za-z0-9_\u0080-\u{D7FF}\u{E000}-\u{FFFF}]|[\u{10000}-\u{EFFFF}])\z/)
      end

      def skip_whitespace
        @position += 1 while !end? && @expression[@position] =~ /\s/
      end

      def scan(pattern)
        match = pattern.match(@expression[@position..])
        return nil unless match

        @position += match[0].length
        match[0]
      end

      def expect(expected)
        error("expected #{expected.inspect}") unless peek == expected
        advance
      end

      def at?(expected)
        @expression[@position, expected.length] == expected
      end

      def peek
        end? ? nil : @expression[@position]
      end

      def advance
        character = peek
        @position += 1 unless end?
        character
      end

      def end?
        @position >= @expression.length
      end

      def error(message)
        raise JSONPathError, "#{message} at position #{@position}"
      end
    end
  end
end
