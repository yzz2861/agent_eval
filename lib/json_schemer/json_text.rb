# frozen_string_literal: true
require 'strscan'

module JSONSchemer
  # A strict JSON (RFC 8259) parser that preserves number semantics.
  #
  # Numbers are returned as `BigDecimal` instead of `Float`, so values like
  # `1E23`, `0.0000000000000001` or `1.0000000000000001` are not silently
  # rounded before schema validation. Parse errors carry the byte offset and a
  # 1-based line and column position of the offending token.
  module JsonText
    # Maximum number of integer or fraction digits allowed in a number token.
    MAX_NUMBER_DIGITS = 10_000
    # Maximum absolute value of a number exponent.
    MAX_NUMBER_EXPONENT = 100_000

    class ParseError < StandardError
      attr_reader :offset, :line, :column, :instance_location

      def initialize(message, offset, line, column, instance_location)
        @offset = offset
        @line = line
        @column = column
        @instance_location = instance_location
        super("#{message} at line #{line}, column #{column} (offset #{offset})")
      end
    end

    module_function

    def parse(json)
      raise TypeError, 'json must be a String' unless json.is_a?(String)

      scanner = StringScanner.new(json)
      parser = Parser.new(scanner)
      value = parser.parse_value
      scanner.skip(/[ \t\r\n]*/)
      parser.error!('unexpected trailing characters') unless scanner.eos?
      value
    end

    # Exact `BigDecimal` representation of a JSON number. `Float` instances
    # (from the direct Ruby object interface) keep the precision of their
    # shortest round-trip representation; `-0.0` normalizes to zero.
    def decimal(numeric)
      if numeric.is_a?(BigDecimal)
        return BigDecimal('0') if numeric.zero?
        return numeric
      end
      return BigDecimal('0') if numeric.is_a?(Float) && numeric.zero?
      BigDecimal(numeric.to_s)
    end

    # Mathematically equal JSON numbers share a key. Used for `enum`, `const`
    # and `uniqueItems`, where `1`, `1.0`, `1E0` and `-0`/`0` compare equal.
    def exact_key(value)
      case value
      when Numeric
        decimal(value)
      when Array
        value.map { |item| exact_key(item) }
      when Hash
        value.transform_values { |item| exact_key(item) }
      else
        value
      end
    end

    def includes?(enum, instance)
      enum.any? { |candidate| exact_equal?(candidate, instance) }
    end

    def exact_equal?(candidate, instance)
      if candidate.is_a?(Numeric) && instance.is_a?(Numeric)
        decimal(candidate) == decimal(instance)
      else
        candidate == instance
      end
    end

    class Parser
      NUMBER_REGEX = /(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?/
      private_constant :NUMBER_REGEX

      def initialize(scanner)
        @scanner = scanner
        @path = []
      end

      def error!(message, pos = @scanner.pos)
        raise_located_error!(message, pos)
      end

      def parse_value
        skip_whitespace
        error!('unexpected end of JSON text') if @scanner.eos?
        case @scanner.peek(1)
        when '{' then parse_object
        when '[' then parse_array
        when '"' then parse_string
        when 't' then parse_literal('true', true)
        when 'f' then parse_literal('false', false)
        when 'n' then parse_literal('null', nil)
        when '-', '0'..'9' then parse_number
        else
          error!("unexpected character #{@scanner.peek(1).inspect}")
        end
      end

      private

      def parse_object
        object = {}
        consume('{')
        skip_whitespace
        if consume?('}')
          return object
        end
        loop do
          skip_whitespace
          error!('expected object property name') unless @scanner.peek(1) == '"'
          key = parse_string
          skip_whitespace
          error!('expected colon after property name') unless consume?(':')
          @path.push(key)
          object[key] = parse_value
          skip_whitespace
          if consume?('}')
            @path.pop
            return object
          end
          unless consume?(',')
            raise_located_error!('expected comma or closing brace in object')
          end
          @path.pop
        end
      end

      def parse_array
        array = []
        consume('[')
        skip_whitespace
        if consume?(']')
          return array
        end
        loop do
          @path.push(array.size.to_s)
          array << parse_value
          skip_whitespace
          if consume?(']')
            @path.pop
            return array
          end
          unless consume?(',')
            raise_located_error!('expected comma or closing bracket in array')
          end
          @path.pop
        end
      end

      def parse_string
        @scanner.get_byte # opening quote
        result = +''
        loop do
          error!('unterminated string') if @scanner.eos?
          byte = @scanner.get_byte
          case byte
          when '"'
            result.force_encoding(Encoding::UTF_8)
            error!('invalid UTF-8 in string') unless result.valid_encoding?
            return result
          when '\\'
            escape = @scanner.get_byte
            error!('unterminated escape sequence') if escape.nil?
            case escape
            when '"' then result << '"'
            when '\\' then result << '\\'
            when '/' then result << '/'
            when 'b' then result << "\b"
            when 'f' then result << "\f"
            when 'n' then result << "\n"
            when 'r' then result << "\r"
            when 't' then result << "\t"
            when 'u'
              result << parse_unicode_escape
            else
              error!("invalid escape character #{escape.inspect}")
            end
          else
            result << byte
          end
        end
      end

      def parse_unicode_escape
        high = parse_hex4
        if (0xD800..0xDBFF).cover?(high)
          unless @scanner.match?(/\\u/)
            raise_located_error!('unpaired high surrogate')
          end
          @scanner.skip(/\\u/)
          low = parse_hex4
          unless (0xDC00..0xDFFF).cover?(low)
            raise_located_error!('expected low surrogate after high surrogate')
          end
          code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
          [code].pack('U')
        elsif (0xDC00..0xDFFF).cover?(high)
          raise_located_error!('unexpected low surrogate')
        else
          [high].pack('U')
        end
      end

      def parse_hex4
        hex = @scanner.scan(/[0-9a-fA-F]{4}/)
        raise_located_error!('invalid unicode escape (expected 4 hex digits)') unless hex
        hex.to_i(16)
      end

      def parse_literal(literal, value)
        start = @scanner.pos
        if @scanner.match?(Regexp.escape(literal))
          @scanner.skip(Regexp.escape(literal))
          value
        else
          @scanner.pos = start
          error!("invalid literal, expected #{literal}")
        end
      end

      def parse_number
        start = @scanner.pos
        match = @scanner.scan(NUMBER_REGEX)
        # :nocov: number tokens are only dispatched for `-` and digits
        error!('invalid number') unless match
        # :nocov:
        _sign, integer, fraction, exponent = @scanner.captures
        integer_digits = integer.delete_prefix('0').length
        integer_digits = 1 if integer == '0'
        fraction_digits = fraction&.length || 0
        if integer_digits > MAX_NUMBER_DIGITS || fraction_digits > MAX_NUMBER_DIGITS
          raise_located_error!(
            "number exceeds #{MAX_NUMBER_DIGITS} digit limit", start
          )
        end
        if exponent
          absolute_exponent = exponent.start_with?('+', '-') ? exponent[1..] : exponent
          significant_exponent = absolute_exponent.sub(/\A0+(?=.)/, '')
          if significant_exponent.length > MAX_NUMBER_EXPONENT.to_s.length || significant_exponent.to_i > MAX_NUMBER_EXPONENT
            raise_located_error!(
              "number exponent exceeds limit of #{MAX_NUMBER_EXPONENT}", start
            )
          end
        end
        begin
          number = BigDecimal(match)
          number.zero? ? BigDecimal('0') : number
        end
      end

      def consume(char)
        unless @scanner.scan(Regexp.new(Regexp.escape(char)))
          # :nocov:
          error!("expected #{char.inspect}")
          # :nocov:
        end
      end

      def consume?(char)
        !!@scanner.scan(Regexp.new(Regexp.escape(char)))
      end

      def skip_whitespace
        @scanner.skip(/[ \t\r\n]*/)
      end

      def pointer
        return '' if @path.empty?
        '/' + @path.map { |token| Location.escape_json_pointer_token(token.to_s) }.join('/')
      end

      def raise_located_error!(message, pos = @scanner.pos)
        line, column = position(pos)
        raise ParseError.new(message, pos, line, column, pointer)
      end

      def position(pos)
        prefix = @scanner.string.byteslice(0, pos) || ''
        line = prefix.count("\n") + 1
        last_newline = prefix.rindex("\n")
        column = last_newline ? (pos - last_newline) : (pos + 1)
        [line, column]
      end
    end
  end
end
