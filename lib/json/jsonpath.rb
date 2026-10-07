# frozen_string_literal: true

require 'json/common'

module JSON
  # = JSONPath
  #
  # JSON::JSONPath extracts nodes from parsed JSON documents (Hashes, Arrays
  # and scalars as produced by JSON.parse) using a JSONPath expression,
  # without ever handing the expression to +eval+.
  #
  # An expression is compiled once and can then be evaluated independently
  # against any number of documents:
  #
  #   path = JSON::JSONPath.new('$.store.book[?(@.price < 10)].title')
  #   path.query(JSON.parse(json_a)) # => [#<JSON::JSONPath::Match ...>, ...]
  #   path.query(JSON.parse(json_b)) # => [...]
  #
  # Every result is a JSON::JSONPath::Match carrying both the selected
  # +value+ and its normalized +path+:
  #
  #   match = JSON::JSONPath.query('$.store.book[0].title', doc).first
  #   match.value # => "Sayings of the Century"
  #   match.path  # => "$['store']['book'][0]['title']"
  #
  # A member that does not exist simply produces no match, which is how a
  # missing member is distinguished from a member whose value is +null+:
  #
  #   JSON::JSONPath.query('$.missing', {'a' => nil})        # => []
  #   JSON::JSONPath.query('$.a', {'a' => nil}).first.value  # => nil
  #
  # == Supported syntax
  #
  # JSON::JSONPath implements a deliberately strict subset of RFC 9535.
  # Anything outside this grammar raises JSON::JSONPath::SyntaxError at
  # compile time:
  #
  # - Root identifier: <tt>$</tt>
  # - Member selector: <tt>$.name</tt> (shorthand: letters, digits,
  #   underscore and non-ASCII characters) or <tt>$['name']</tt> /
  #   <tt>$["name"]</tt> with the escapes <tt>\' \" \\ \/ \b \f \n
  #   \r \t \uXXXX</tt>
  # - Array index selector: <tt>$[0]</tt>; negative indices count from the
  #   end (<tt>$[-1]</tt> is the last element)
  # - Wildcard selector: <tt>$.*</tt> or <tt>$[*]</tt> (object values in
  #   insertion order, array elements in order)
  # - Recursive descent: <tt>$..name</tt>, <tt>$..['name']</tt>,
  #   <tt>$..[0]</tt>, <tt>$..*</tt>
  # - Array slice selector: <tt>$[start:end:step]</tt> where each part is an
  #   optional integer; negative values count from the end and a negative
  #   step walks backwards (<tt>$[::-1]</tt> reverses)
  # - Filter selector: <tt>$[?(expression)]</tt> applied to each member or
  #   element, where the expression is built from:
  #   - literals: strings, numbers, +true+, +false+, +null+
  #   - the current node <tt>@</tt> and the document root <tt>$</tt>,
  #     optionally followed by member/index segments (<tt>@.a[0].b</tt>,
  #     <tt>@['a']</tt>)
  #   - comparisons: <tt>== != < <= > >=</tt>
  #   - boolean operators: <tt>&& || !</tt> and parentheses
  #   - existence tests: a bare path such as <tt>@.a</tt> is true when the
  #     member or element *exists*, even if its value is +null+ or +false+
  #
  # Not supported (all rejected with JSON::JSONPath::SyntaxError): selector
  # unions (<tt>$[0,1]</tt>), function calls (<tt>length()</tt>,
  # <tt>match()</tt>, ...), script expressions (<tt>$[(@.length-1)]</tt>),
  # and filters nested inside filter queries.
  class JSONPath
    # Raised when a JSONPath expression cannot be compiled, either because
    # it is malformed or because it uses syntax outside the supported
    # subset documented on JSON::JSONPath.
    class SyntaxError < JSON::JSONError; end

    # A single node selected by a JSONPath query: the selected +value+ and
    # the normalized +path+ that addresses it.
    class Match
      # The selected value.
      attr_reader :value

      # The normalized path of the selected node, e.g.
      # <tt>$['store']['book'][0]['title']</tt>.
      attr_reader :path

      def initialize(value, path) # :nodoc:
        @value = value
        @path = path
      end

      def ==(other)
        other.is_a?(Match) && value == other.value && path == other.path
      end
      alias eql? ==

      def hash
        [value, path].hash
      end

      def inspect
        "#<#{self.class.name} #{path}=#{value.inspect}>"
      end
    end

    # Compiles +expression+ and evaluates it against +document+.
    # Equivalent to <tt>JSON::JSONPath.new(expression).query(document)</tt>.
    def self.query(expression, document)
      new(expression).query(document)
    end

    # The source expression this JSONPath was compiled from.
    attr_reader :expression

    # Compiles +expression+ so it can be evaluated repeatedly with #query.
    # Raises JSON::JSONPath::SyntaxError for malformed or unsupported
    # expressions.
    def initialize(expression)
      unless String === expression
        raise TypeError, "JSONPath expression must be a String, got #{expression.class}"
      end
      @expression = expression
      @selectors = Parser.new(expression).parse.freeze
    end

    # Evaluates the compiled expression against +document+ and returns an
    # Array of JSON::JSONPath::Match. The document is never mutated, and
    # repeated calls against different documents are independent.
    def query(document)
      nodes = [[document, EMPTY_SEGMENTS]]
      @selectors.each do |selector|
        nodes = selector.select(nodes, document)
      end
      nodes.map { |value, segments| Match.new(value, JSONPath.normalized_path(segments)) }
    end

    # Returns only the values selected by #query.
    def values(document)
      query(document).map(&:value)
    end

    # Returns only the normalized paths selected by #query.
    def paths(document)
      query(document).map(&:path)
    end

    # Builds the normalized bracket-notation path for a list of segments
    # (Strings for member names, Integers for array indices).
    def self.normalized_path(segments)
      path = +"$"
      segments.each do |segment|
        case segment
        when Integer
          path << "[" << segment.to_s << "]"
        else
          path << "['" << segment.gsub(/['\\]/) { |c| "\\#{c}" } << "']"
        end
      end
      path
    end

    EMPTY_SEGMENTS = [].freeze

    # :stopdoc:
    EMPTY = Object.new.freeze

    class ChildName
      def initialize(name)
        @name = name
      end

      def select(nodes, _root)
        result = []
        nodes.each do |value, segments|
          # Hash#key? keeps a missing member distinct from a null value.
          if Hash === value && value.key?(@name)
            result << [value[@name], segments + [@name]]
          end
        end
        result
      end
    end

    class ChildIndex
      def initialize(index)
        @index = index
      end

      def select(nodes, _root)
        result = []
        nodes.each do |value, segments|
          next unless Array === value
          index = @index < 0 ? value.length + @index : @index
          if index >= 0 && index < value.length
            result << [value[index], segments + [index]]
          end
        end
        result
      end
    end

    class Wildcard
      def select(nodes, _root)
        result = []
        nodes.each do |value, segments|
          case value
          when Hash
            value.each { |key, child| result << [child, segments + [key]] }
          when Array
            value.each_with_index { |child, i| result << [child, segments + [i]] }
          end
        end
        result
      end
    end

    class Slice
      def initialize(start, stop, step)
        @start = start
        @stop = stop
        @step = step || 1
      end

      def select(nodes, _root)
        result = []
        nodes.each do |value, segments|
          next unless Array === value
          length = value.length
          if @step > 0
            i = @start.nil? ? 0 : (@start < 0 ? [length + @start, 0].max : [@start, length].min)
            stop = @stop.nil? ? length : (@stop < 0 ? [length + @stop, 0].max : [@stop, length].min)
            while i < stop
              result << [value[i], segments + [i]]
              i += @step
            end
          else
            i = @start.nil? ? length - 1 : (@start < 0 ? [length + @start, -1].min : [@start, length - 1].min)
            stop = @stop.nil? ? -1 : (@stop < 0 ? [length + @stop, -1].min : [@stop, length - 1].min)
            while i > stop
              result << [value[i], segments + [i]]
              i += @step
            end
          end
        end
        result
      end
    end

    class Descendant
      def initialize(inner)
        @inner = inner
      end

      def select(nodes, root)
        result = []
        nodes.each do |node|
          visit(node) do |descendant|
            @inner.select([descendant], root).each { |match| result << match }
          end
        end
        result
      end

      private

      def visit(node, &block)
        yield node
        value, segments = node
        case value
        when Hash
          value.each { |key, child| visit([child, segments + [key]], &block) }
        when Array
          value.each_with_index { |child, i| visit([child, segments + [i]], &block) }
        end
      end
    end

    class Filter
      def initialize(expression)
        @expression = expression
      end

      def select(nodes, root)
        result = []
        nodes.each do |value, segments|
          case value
          when Hash
            value.each do |key, child|
              result << [child, segments + [key]] if @expression.evaluate(child, root)
            end
          when Array
            value.each_with_index do |child, i|
              result << [child, segments + [i]] if @expression.evaluate(child, root)
            end
          end
        end
        result
      end
    end

    class Or
      def initialize(left, right)
        @left = left
        @right = right
      end

      def evaluate(current, root)
        @left.evaluate(current, root) || @right.evaluate(current, root)
      end
    end

    class And
      def initialize(left, right)
        @left = left
        @right = right
      end

      def evaluate(current, root)
        @left.evaluate(current, root) && @right.evaluate(current, root)
      end
    end

    class Not
      def initialize(inner)
        @inner = inner
      end

      def evaluate(current, root)
        !@inner.evaluate(current, root)
      end
    end

    class Literal
      def initialize(value)
        @value = value
      end

      def resolve(_current, _root)
        @value
      end
    end

    # A singular query used as a filter operand: @ or $ followed only by
    # member names and array indices.
    class SingularQuery
      def initialize(segments, absolute)
        @segments = segments
        @absolute = absolute
      end

      def resolve(current, root)
        value = @absolute ? root : current
        @segments.each do |segment|
          case segment
          when String
            return EMPTY unless Hash === value && value.key?(segment)
            value = value[segment]
          when Integer
            return EMPTY unless Array === value
            index = segment < 0 ? value.length + segment : segment
            return EMPTY unless index >= 0 && index < value.length
            value = value[index]
          end
        end
        value
      end
    end

    # A bare query used as a boolean: true when it selects at least one
    # node. Existence is structural, so a member whose value is null or
    # false still exists.
    class Existence
      def initialize(query)
        @query = query
      end

      def evaluate(current, root)
        !@query.resolve(current, root).equal?(EMPTY)
      end
    end

    class Comparison
      def initialize(left, operator, right)
        @left = left
        @operator = operator
        @right = right
      end

      def evaluate(current, root)
        left = @left.resolve(current, root)
        right = @right.resolve(current, root)

        if left.equal?(EMPTY) || right.equal?(EMPTY)
          equal = left.equal?(EMPTY) && right.equal?(EMPTY)
          case @operator
          when :== then return equal
          when :!= then return !equal
          else return false
          end
        end

        case @operator
        when :== then left == right
        when :!= then left != right
        when :<, :<=, :>, :>=
          comparable =
            (Numeric === left && Numeric === right) ||
            (String === left && String === right)
          comparable ? left.public_send(@operator, right) : false
        end
      end
    end

    class Parser
      NAME_PATTERN = /[A-Za-z_\u{80}-\u{10FFFF}][A-Za-z0-9_\u{80}-\u{10FFFF}]*/
      INTEGER_PATTERN = /-?\d+/
      NUMBER_PATTERN = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/

      STRING_ESCAPES = {
        "'" => "'", '"' => '"', "\\" => "\\", "/" => "/",
        "b" => "\b", "f" => "\f", "n" => "\n", "r" => "\r", "t" => "\t",
      }.freeze

      COMPARISON_OPERATORS = ["==", "!=", "<=", ">=", "<", ">"].freeze

      def initialize(source)
        @source = source
        @pos = 0
      end

      def parse
        skip_whitespace
        expect("$", "JSONPath expression must start with the root identifier '$'")
        selectors = []
        selectors << parse_selector until eof?
        selectors
      end

      private

      def error(message)
        raise SyntaxError, "#{message} (at column #{@pos + 1} of #{@source.inspect})"
      end

      def eof?
        @pos >= @source.length
      end

      def peek
        @source[@pos]
      end

      def expect(string, message)
        error(message) unless @source[@pos, string.length] == string
        @pos += string.length
      end

      def skip_whitespace
        @pos += 1 while peek == " " || peek == "\t"
      end

      def parse_selector
        case peek
        when "."
          if @source[@pos, 2] == ".."
            @pos += 2
            parse_descendant
          else
            @pos += 1
            if peek == "*"
              @pos += 1
              Wildcard.new
            else
              name = parse_shorthand_name
              error("expected a member name or '*' after '.'") unless name
              ChildName.new(name)
            end
          end
        when "["
          parse_bracket_selector
        when nil
          error("unexpected end of expression")
        else
          error("expected '.', '..' or '[' but found #{peek.inspect}")
        end
      end

      def parse_descendant
        case peek
        when "*"
          @pos += 1
          Descendant.new(Wildcard.new)
        when "["
          Descendant.new(parse_bracket_selector)
        else
          name = parse_shorthand_name
          error("expected a member name, '*' or '[' after '..'") unless name
          Descendant.new(ChildName.new(name))
        end
      end

      def parse_bracket_selector
        @pos += 1 # consume '['
        skip_whitespace
        selector =
          case peek
          when "*"
            @pos += 1
            Wildcard.new
          when "'", '"'
            ChildName.new(parse_string_literal)
          when "?"
            @pos += 1
            skip_whitespace
            Filter.new(parse_or)
          when /[-0-9:]/
            parse_index_or_slice
          when nil
            error("unterminated '['")
          else
            error("unsupported selector starting with #{peek.inspect}")
          end
        skip_whitespace
        if peek == ","
          error("selector unions like [0, 1] are not supported")
        end
        expect("]", "expected ']'")
        selector
      end

      def parse_index_or_slice
        start = parse_optional_integer
        unless peek == ":"
          error("expected an array index or slice") if start.nil?
          return ChildIndex.new(start)
        end
        @pos += 1 # consume ':'
        stop = parse_optional_integer
        step = nil
        if peek == ":"
          @pos += 1 # consume ':'
          step = parse_optional_integer
          error("slice step of 0 is not allowed") if step == 0
        end
        Slice.new(start, stop, step)
      end

      def parse_optional_integer
        match = INTEGER_PATTERN.match(@source, @pos)
        return nil unless match && match.begin(0) == @pos
        @pos = match.end(0)
        Integer(match[0])
      end

      def parse_shorthand_name
        match = NAME_PATTERN.match(@source, @pos)
        return nil unless match && match.begin(0) == @pos
        @pos = match.end(0)
        match[0]
      end

      def parse_string_literal
        quote = @source[@pos]
        @pos += 1
        string = +""
        until eof?
          char = @source[@pos]
          @pos += 1
          if char == quote
            return string
          elsif char == "\\"
            string << parse_escape
          else
            string << char
          end
        end
        error("unterminated string literal")
      end

      def parse_escape
        error("unterminated escape sequence") if eof?
        char = @source[@pos]
        @pos += 1
        if char == "u"
          parse_unicode_escape
        elsif STRING_ESCAPES.key?(char)
          STRING_ESCAPES[char]
        else
          error("unsupported escape sequence '\\#{char}'")
        end
      end

      def parse_unicode_escape
        code = read_hex4
        if (0xD800..0xDBFF).cover?(code) && @source[@pos, 2] == "\\u"
          saved = @pos
          @pos += 2
          low = read_hex4
          if (0xDC00..0xDFFF).cover?(low)
            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
          else
            @pos = saved
            error("invalid surrogate pair in \\u escape")
          end
        elsif (0xD800..0xDFFF).cover?(code)
          error("invalid surrogate pair in \\u escape")
        end
        code.chr(Encoding::UTF_8)
      end

      def read_hex4
        hex = @source[@pos, 4]
        error("invalid \\u escape sequence") unless hex && /\A[0-9a-fA-F]{4}\z/.match?(hex)
        @pos += 4
        hex.to_i(16)
      end

      def parse_or
        left = parse_and
        loop do
          skip_whitespace
          break unless @source[@pos, 2] == "||"
          @pos += 2
          skip_whitespace
          left = Or.new(left, parse_and)
        end
        left
      end

      def parse_and
        left = parse_unary
        loop do
          skip_whitespace
          break unless @source[@pos, 2] == "&&"
          @pos += 2
          skip_whitespace
          left = And.new(left, parse_unary)
        end
        left
      end

      def parse_unary
        skip_whitespace
        if peek == "!"
          @pos += 1
          skip_whitespace
          Not.new(parse_unary)
        else
          parse_primary
        end
      end

      def parse_primary
        skip_whitespace
        if peek == "("
          @pos += 1
          expression = parse_or
          skip_whitespace
          expect(")", "expected ')'")
          expression
        else
          parse_comparison_or_existence
        end
      end

      def parse_comparison_or_existence
        left = parse_operand
        skip_whitespace
        operator = parse_comparison_operator
        unless operator
          unless SingularQuery === left
            error("a literal cannot be used as a filter test; expected a path or comparison")
          end
          return Existence.new(left)
        end
        skip_whitespace
        Comparison.new(left, operator, parse_operand)
      end

      def parse_comparison_operator
        COMPARISON_OPERATORS.each do |operator|
          if @source[@pos, operator.length] == operator
            @pos += operator.length
            return operator.to_sym
          end
        end
        nil
      end

      def parse_operand
        skip_whitespace
        case peek
        when "'", '"'
          Literal.new(parse_string_literal)
        when /[-0-9]/
          parse_number_literal
        when "@", "$"
          parse_filter_query
        when "t"
          expect_keyword("true")
          Literal.new(true)
        when "f"
          expect_keyword("false")
          Literal.new(false)
        when "n"
          expect_keyword("null")
          Literal.new(nil)
        when nil
          error("unexpected end of filter expression")
        else
          error("unsupported filter operand #{peek.inspect}; " +                "function calls and script expressions are not supported")
        end
      end

      def expect_keyword(keyword)
        expect(keyword, "invalid literal; did you mean '#{keyword}'?")
      end

      def parse_number_literal
        match = NUMBER_PATTERN.match(@source, @pos)
        error("invalid number literal") unless match && match.begin(0) == @pos
        @pos = match.end(0)
        Literal.new(match[0].match?(/[.eE]/) ? Float(match[0]) : Integer(match[0]))
      end

      def parse_filter_query
        absolute = @source[@pos] == "$"
        @pos += 1
        segments = []
        loop do
          case peek
          when "."
            if @source[@pos, 2] == ".."
              error("recursive descent is not supported inside filter expressions")
            end
            @pos += 1
            name = parse_shorthand_name
            error("expected a member name after '.' in filter expression") unless name
            error("function calls are not supported in filter expressions") if peek == "("
            segments << name
          when "["
            @pos += 1
            skip_whitespace
            case peek
            when "'", '"'
              segments << parse_string_literal
            when /[-0-9]/
              segments << parse_optional_integer
            else
              error("only member names and array indices are supported inside filter queries")
            end
            skip_whitespace
            expect("]", "expected ']'")
          else
            break
          end
        end
        SingularQuery.new(segments, absolute)
      end
    end
    # :startdoc:
  end
end
