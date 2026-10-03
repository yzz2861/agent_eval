# frozen_string_literal: true
require 'bigdecimal'
require 'json'
require 'set'

module JSONSchemer
  class InvalidJSON < JSON::ParserError
    attr_reader :line, :column, :offset

    def initialize(message, line:, column:, offset:)
      super(message)
      @line = line
      @column = column
      @offset = offset
    end
  end

  module ExactJSON
    MAX_NUMBER_DIGITS = 1000
    MAX_EXPONENT_ABSOLUTE = 1000
    MAX_EXPONENT_DIGITS = 4

    class << self
      def parse(json, **options)
        parse_with_locations(json, **options).first
      end

      def parse_with_locations(json, max_number_digits: MAX_NUMBER_DIGITS, max_exponent_absolute: MAX_EXPONENT_ABSOLUTE)
        parser = Parser.new(json, max_number_digits, max_exponent_absolute)
        parser.parse
      end

      def equal?(left, right)
        canonical(left) == canonical(right)
      end

      def include?(collection, value)
        collection.any? { |item| equal?(item, value) }
      end

      def unique?(array)
        values = Set.new
        array.all? { |item| values.add?(canonical(item)) }
      end

      def decimal(value)
        return value if value.is_a?(BigDecimal)
        return BigDecimal(value) if value.is_a?(Integer)
        value.finite? ? BigDecimal(value.to_s) : value
      end

      def compare?(left, operator, right)
        return left.public_send(operator, right) unless right.is_a?(Numeric)
        decimal(left).public_send(operator, right.is_a?(BigDecimal) ? right : decimal(right))
      end

      def multiple?(instance, divisor)
        return BigDecimal(instance.to_s).modulo(divisor).zero? unless divisor.is_a?(Numeric)
        decimal(instance).modulo(divisor.is_a?(BigDecimal) ? divisor : decimal(divisor)).zero?
      end

      private

      def canonical(value)
        case value
        when Numeric
          decimal_value = decimal(value)
          decimal_value = BigDecimal('0') if decimal_value.is_a?(BigDecimal) && decimal_value.zero?
          [:numeric, decimal_value.to_s]
        when Array
          [:array, value.map { |item| canonical(item) }]
        when Hash
          [:hash, value.transform_keys { |key| [key.class, key] }.transform_values { |item| canonical(item) }]
        else
          [value.class, value]
        end
      end
    end

    SourceLocation = Struct.new(:line, :column, :offset, :length)
    LocationInfo = Struct.new(:source, :properties)

    class Parser
      WHITESPACE = " \t\n\r"
      DIGITS = '0123456789'
      HEX_DIGITS = "#{DIGITS}abcdefABCDEF"

      def initialize(json, max_number_digits, max_exponent_absolute)
        raise TypeError, 'JSON must be a String' unless json.is_a?(String)
        unless max_number_digits.is_a?(Integer) && max_number_digits.positive?
          raise ArgumentError, 'max_number_digits must be a positive Integer'
        end
        unless max_exponent_absolute.is_a?(Integer) && max_exponent_absolute.positive?
          raise ArgumentError, 'max_exponent_absolute must be a positive Integer'
        end
        @json = json
        @max_number_digits = max_number_digits
        @max_exponent_absolute = max_exponent_absolute
        @pos = 0
        @line = 1
        @column = 1
        @locations = {}
      end

      def parse
        skip_byte_order_mark
        skip_whitespace
        value = parse_value
        skip_whitespace
        error!('unexpected token after JSON value') unless eof?
        [value, @locations]
      end

      private

      def skip_byte_order_mark
        @pos += 1 if @json[@pos] == "\uFEFF"
      end

      def parse_value
        location = current_location
        value = case peek
        when nil
          error!('unexpected end of JSON input')
        when '{'
          parse_object
        when '['
          parse_array
        when '"'
          parse_string
        when 't'
          parse_literal('true', true)
        when 'f'
          parse_literal('false', false)
        when 'n'
          parse_literal('null', nil)
        when '-', '0'..'9'
          parse_number
        else
          error!('unexpected token')
        end
        record_location(value, location)
        value
      end

      def parse_object
        advance
        object = {}
        register_container(object)
        skip_whitespace
        if peek == '}'
          advance
          return object
        end

        loop do
          error!('expected object property name') unless peek == '"'
          key = parse_string
          skip_whitespace
          expected!(':', 'expected colon after object property name')
          skip_whitespace
          value_start = current_location
          value = parse_value
          object[key] = value
          mark_property(object, key, value_start)
          skip_whitespace
          char = advance
          break if char == '}'
          error!('expected comma or closing brace in object') unless char == ','
          skip_whitespace
        end
        object
      end

      def parse_array
        advance
        array = []
        register_container(array)
        skip_whitespace
        if peek == ']'
          advance
          return array
        end

        loop do
          value_start = current_location
          value = parse_value
          array << value
          mark_property(array, array.size.pred, value_start)
          skip_whitespace
          char = advance
          break if char == ']'
          error!('expected comma or closing bracket in array') unless char == ','
          skip_whitespace
        end
        array
      end

      def register_container(value)
        @locations[value.object_id] = LocationInfo.new(nil, {})
      end

      def mark_property(container, key, value_start)
        info = @locations.fetch(container.object_id)
        info.properties[key] = source_location(value_start)
      end

      def record_location(value, location)
        info = @locations[value.object_id]
        source = source_location(location)
        if info
          info.source = source
        else
          @locations[value.object_id] = LocationInfo.new(source, {})
        end
      end

      def parse_literal(literal, value)
        literal.each_char do |char|
          error!("expected #{literal}") unless peek == char
          advance
        end
        value
      end

      def parse_string
        advance
        buffer = +''

        loop do
          char = advance
          case char
          when nil
            error!('unterminated string')
          when '"'
            break
          when "\n", "\r"
            error!('unescaped line break in string')
          when '\\'
            buffer << parse_escape
          else
            error!('unescaped control character in string') if char.ord < 0x20
            buffer << char
          end
        end

        buffer.freeze
      end

      def parse_escape
        char = advance
        case char
        when nil then error!('unterminated string escape')
        when '"' then '"'
        when '\\' then '\\'
        when '/' then '/'
        when 'b' then "\b"
        when 'f' then "\f"
        when 'n' then "\n"
        when 'r' then "\r"
        when 't' then "\t"
        when 'u'
          hex = parse_unicode_hex
          if (0xD800..0xDBFF).cover?(hex)
            expected!('\\', 'expected low surrogate')
            expected!('u', 'expected low surrogate')
            low = parse_unicode_hex
            error!('invalid Unicode low surrogate') unless (0xDC00..0xDFFF).cover?(low)
            [0x10000 + ((hex - 0xD800) << 10) + (low - 0xDC00)].pack('U')
          else
            error!('invalid Unicode escape') if (0xDC00..0xDFFF).cover?(hex)
            [hex].pack('U')
          end
        else
          error!('invalid string escape')
        end
      end

      def parse_unicode_hex
        hex = 4.times.map do
          char = advance
          error!('incomplete Unicode escape') unless char && HEX_DIGITS.include?(char)
          char
        end.join
        hex.to_i(16)
      end

      def parse_number
        start = @pos
        line = @line
        column = @column
        negative = consume('-')
        integer_digits = parse_digits
        error_at!(line, column, start, 'number is missing integer digits') if integer_digits.empty?
        if integer_digits.size > 1 && integer_digits.start_with?('0')
          error_at!(line, column, start, 'leading zeros are not allowed in JSON numbers')
        end

        fractional_digits = +''
        if consume('.')
          fractional_digits = parse_digits
          error_at!(line, column, start, 'number is missing fractional digits') if fractional_digits.empty?
        end

        exponent_digits = +''
        if consume('e') || consume('E')
          exponent_negative = consume('-')
          consume('+') unless exponent_negative
          exponent_digits = parse_digits
          error_at!(line, column, start, 'number is missing exponent digits') if exponent_digits.empty?
          if exponent_digits.size > MAX_EXPONENT_DIGITS
            error_at!(line, column, start, "number exponent exceeds #{@max_exponent_absolute}")
          end
          exponent = exponent_digits.to_i
          exponent = -exponent if exponent_negative
          if exponent > @max_exponent_absolute
            error_at!(line, column, start, "number exponent exceeds #{@max_exponent_absolute}")
          end
          if exponent < -@max_exponent_absolute
            error_at!(line, column, start, "number exponent is less than -#{@max_exponent_absolute}")
          end
        end

        digits = integer_digits + fractional_digits
        if digits.size > @max_number_digits
          error_at!(line, column, start, "number has more than #{@max_number_digits} digits")
        end

        lexical = @json[start...@pos]
        if fractional_digits.empty? && !lexical.include?('e') && !lexical.include?('E')
          Integer(lexical, 10)
        else
          value = BigDecimal(lexical)
          value = BigDecimal('0') if value.zero? && negative
          value
        end
      end

      def parse_digits
        digits = +''
        digits << advance while peek && DIGITS.include?(peek)
        digits
      end

      def consume(char)
        return false unless peek == char
        advance
        true
      end

      def expected!(char, message)
        error!(message) unless peek == char
        advance
      end

      def skip_whitespace
        advance while peek && WHITESPACE.include?(peek)
      end

      def peek
        @json[@pos]
      end

      def advance
        return nil if @pos >= @json.size
        char = @json[@pos]
        @pos += 1
        if char == "\n"
          @line += 1
          @column = 1
        else
          @column += 1
        end
        char
      end

      def current_location
        { :line => @line, :column => @column, :offset => @pos }
      end

      def source_location(location)
        SourceLocation.new(location.fetch(:line), location.fetch(:column), location.fetch(:offset), @pos - location.fetch(:offset))
      end

      def eof?
        @pos >= @json.size
      end

      def error!(message)
        error_at!(@line, @column, @pos, message)
      end

      def error_at!(line, column, offset, message)
        raise InvalidJSON.new("#{message} at line #{line}, column #{column}", :line => line, :column => column, :offset => offset)
      end
    end
  end
end
