# frozen_string_literal: true

module JWT
  # A strict JSON parser used when decoding JWT segments.
  #
  # In addition to accepting only syntactically valid JSON it:
  # * rejects objects containing duplicate members, even when the members
  #   only become equal after escape sequence processing,
  # * limits the nesting depth and the total number of object members and
  #   array elements,
  # * limits the lexical length of numbers,
  # * rejects strings that are not valid UTF-8.
  #
  # Error messages only contain the error category and the position in the
  # input, never any fragment of the parsed data.
  #
  # @api private
  class StrictJSON
    # Error raised for any rejected input. Subclasses ::JSON::ParserError so
    # existing rescues keep working.
    class ParseError < ::JSON::ParserError
      # @return [Integer] the zero based position of the error in the input.
      attr_reader :position

      # @param category [Symbol] the error category.
      # @param position [Integer] the zero based position of the error.
      def initialize(category, position)
        @position = position
        super("Invalid JSON: #{category} at position #{position}")
      end
    end

    DEFAULT_MAX_DEPTH    = 100
    DEFAULT_MAX_MEMBERS  = 10_000
    DEFAULT_MAX_NUMBER   = 100

    # Strictly parses a JSON document.
    #
    # @param data [String] the JSON document.
    # @param max_depth [Integer] maximum allowed nesting depth.
    # @param max_members [Integer] maximum total number of object members and
    #   array elements in the whole document.
    # @param max_number_length [Integer] maximum lexical length of a number.
    # @return [Object] the parsed value.
    # @raise [JWT::StrictJSON::ParseError] if the input is rejected.
    def self.parse(data, max_depth: DEFAULT_MAX_DEPTH,
                         max_members: DEFAULT_MAX_MEMBERS,
                         max_number_length: DEFAULT_MAX_NUMBER)
      new(data, max_depth, max_members, max_number_length).parse
    end

    def initialize(data, max_depth, max_members, max_number_length)
      @data = data
      @max_depth = max_depth
      @max_members = max_members
      @max_number_length = max_number_length
      @index = 0
      @member_count = 0
    end

    def parse
      raise ParseError.new(:unexpected_token, 0) unless @data.is_a?(::String)

      encoding_error = invalid_utf8_position(@data)
      raise ParseError.new(:invalid_encoding, encoding_error) if encoding_error

      @chars = @data.dup.force_encoding(Encoding::UTF_8).chars
      skip_whitespace
      value = parse_value(1)
      skip_whitespace
      error!(:unexpected_token, @index) unless @index == @chars.length
      value
    end

    private

    def parse_value(depth)
      error!(:unexpected_end, @index) if @index >= @chars.length

      char = @chars[@index]
      return parse_container(char, depth) if char == '{' || char == '['
      return parse_string if char == '"'
      return parse_literal(*LITERALS.fetch(char)) if LITERALS.key?(char)
      return parse_number if char == '-' || char.match?(/[0-9]/)

      error!(:unexpected_token, @index)
    end

    def parse_object(depth)
      error!(:depth_exceeded, @index) if depth > @max_depth
      @index += 1 # consume '{'
      container = {}
      return consume_close('}') { container } if peek_after_whitespace == '}'

      parse_object_members(container, depth)
      container
    end

    def parse_array(depth)
      error!(:depth_exceeded, @index) if depth > @max_depth
      @index += 1 # consume '['
      container = []
      return consume_close(']') { container } if peek_after_whitespace == ']'

      parse_array_elements(container, depth)
      container
    end

    def parse_container(char, depth)
      char == '{' ? parse_object(depth) : parse_array(depth)
    end

    LITERALS = {
      't' => ['true', true],
      'f' => ['false', false],
      'n' => ['null', nil]
    }.freeze
    private_constant(:LITERALS)

    SIMPLE_ESCAPES = {
      '"' => '"'.ord,
      '\\' => '\\'.ord,
      '/' => '/'.ord,
      'b' => "\b".ord,
      'f' => "\f".ord,
      'n' => "\n".ord,
      'r' => "\r".ord,
      't' => "\t".ord
    }.freeze
    private_constant(:SIMPLE_ESCAPES)

    def parse_object_members(object, depth)
      loop do
        expect_member_key
        key_start = @index
        key = parse_member_key
        skip_whitespace
        value = parse_value(depth + 1)
        raise ParseError.new(:duplicate_member, key_start) if object.key?(key)
        object[key] = value
        count_member!
        break unless expect_member_separator('}')
      end
    end

    def expect_member_key
      skip_whitespace
      error!(:unexpected_end, @index) if @index >= @chars.length
      error!(:unexpected_token, @index) unless @chars[@index] == '"'
    end

    def parse_member_key
      key = parse_string
      skip_whitespace
      error!(:unexpected_token, @index) unless consume(':')
      skip_whitespace
      key
    end

    def parse_array_elements(array, depth)
      loop do
        skip_whitespace
        array << parse_value(depth + 1)
        count_member!
        break unless expect_member_separator(']')
      end
    end

    # Checks the separator after a member or element. Returns true when a comma
    # signals another entry and false when the given closing character ends it.
    def expect_member_separator(close)
      skip_whitespace
      error!(:unexpected_end, @index) if @index >= @chars.length
      separator = @chars[@index]
      error!(:unexpected_token, @index) unless separator == ',' || separator == close
      @index += 1
      separator == ','
    end

    def peek_after_whitespace
      skip_whitespace
      @chars[@index]
    end

    def consume_close(close)
      @index += 1 # consume the closing character
      yield
    end

    def parse_string
      @index += 1 # consume opening quote
      codepoints = []

      while (char = @chars[@index])
        return codepoints.pack('U*') if append_string_character(char, codepoints)
      end

      error!(:unexpected_end, @index)
    end

    # Appends the current character to the codepoints. Returns true when the
    # closing quote ends the string.
    def append_string_character(char, codepoints)
      if char == '"'
        @index += 1
        true
      elsif char == '\\'
        codepoints.concat(parse_escape)
        false
      elsif char >= " "
        codepoints << char.ord
        @index += 1
        false
      else
        error!(:unescaped_control_character, @index)
      end
    end

    def parse_escape
      @index += 1 # consume backslash
      error!(:unexpected_end, @index) if @index >= @chars.length

      escaped = @chars[@index]
      @index += 1
      return [SIMPLE_ESCAPES.fetch(escaped)] if SIMPLE_ESCAPES.key?(escaped)
      return parse_unicode_escape if escaped == 'u'

      error!(:invalid_escape, @index - 1)
    end

    def parse_unicode_escape
      high = parse_hex4
      if (0xD800..0xDBFF).cover?(high)
        error!(:invalid_unicode_escape, @index) unless @chars[@index] == '\\' && @chars[@index + 1] == 'u'
        @index += 2
        low = parse_hex4
        error!(:invalid_unicode_escape, @index) unless (0xDC00..0xDFFF).cover?(low)
        [0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)]
      else
        error!(:invalid_unicode_escape, @index) if (0xDC00..0xDFFF).cover?(high)
        [high]
      end
    end

    def parse_hex4
      hex = @chars[@index, 4]
      error!(:unexpected_end, @index) if hex.nil? || hex.length < 4
      error!(:invalid_unicode_escape, @index) unless hex.join.match?(/\A[0-9a-fA-F]{4}\z/)

      @index += 4
      hex.join.to_i(16)
    end

    def parse_number
      start = @index
      consume('-')
      consume_integer_digits(start)
      consume_fraction
      consume_exponent

      lexical = @chars[start...@index].join
      error!(:number_too_long, start) if lexical.length > @max_number_length

      if lexical.include?('.') || lexical =~ /[eE]/
        Float(lexical)
      else
        Integer(lexical)
      end
    end

    def consume_integer_digits(start)
      if consume('0')
        next_char = @chars[@index]
        error!(:unexpected_token, @index) if next_char&.match?(/[0-9]/)
      elsif @chars[@index]&.match?(/[1-9]/)
        @index += 1 while @chars[@index]&.match?(/[0-9]/)
      else
        error!(:unexpected_token, [start, @index].max)
      end
    end

    def consume_fraction
      return unless consume('.')

      error!(:unexpected_token, @index) unless @chars[@index]&.match?(/[0-9]/)
      @index += 1 while @chars[@index]&.match?(/[0-9]/)
    end

    def consume_exponent
      return unless @chars[@index] == 'e' || @chars[@index] == 'E'

      @index += 1
      consume('+') || consume('-')
      error!(:unexpected_token, @index) unless @chars[@index]&.match?(/[0-9]/)
      @index += 1 while @chars[@index]&.match?(/[0-9]/)
    end

    def parse_literal(literal, value)
      error!(:unexpected_token, @index) unless @chars[@index, literal.length]&.join == literal

      @index += literal.length
      value
    end

    def consume(char)
      return false unless @chars[@index] == char

      @index += 1
      true
    end

    def skip_whitespace
      @index += 1 while @chars[@index] == ' ' || @chars[@index] == "\t" || @chars[@index] == "\n" || @chars[@index] == "\r"
    end

    def count_member!
      @member_count += 1
      error!(:member_limit_exceeded, @index) if @member_count > @max_members
    end

    def error!(category, position)
      raise ParseError.new(category, position)
    end

    # Returns the byte position of the first invalid UTF-8 byte, or nil.
    def invalid_utf8_position(data)
      bytes = data.b
      index = 0
      while index < bytes.length
        invalid_at = validate_utf8_sequence(bytes, index)
        return invalid_at if invalid_at

        index += utf8_lead(bytes.getbyte(index)).first
      end
      nil
    end

    def validate_utf8_sequence(bytes, index)
      byte = bytes.getbyte(index)
      width, expected_min, forbidden_second_bytes = utf8_lead(byte)
      return index unless width
      return index unless index + width <= bytes.length

      invalid_at = validate_utf8_continuations(bytes, index, width, forbidden_second_bytes)
      return invalid_at if invalid_at

      codepoint = decode_utf8(bytes, index, width)
      return index if codepoint < expected_min
      return index if (0xD800..0xDFFF).cover?(codepoint) || codepoint > 0x10FFFF

      nil
    end

    def validate_utf8_continuations(bytes, index, width, forbidden_second_bytes)
      (1...width).each do |offset|
        continuation = bytes.getbyte(index + offset)
        return index + offset unless continuation && (continuation & 0xC0) == 0x80
        return index + offset if offset == 1 && forbidden_second_bytes&.cover?(continuation)
      end
      nil
    end

    def utf8_lead(byte)
      case byte
      when 0x00..0x7F then [1, 0x0000, nil]
      when 0xC2..0xDF then [2, 0x0080, nil]
      when 0xE0 then [3, 0x0800, 0x80..0x9F]
      when 0xE1..0xEC then [3, 0x0800, nil]
      when 0xED then [3, 0x0800, 0xA0..0xBF]
      when 0xEE..0xEF then [3, 0x0800, nil]
      when 0xF0 then [4, 0x10000, 0x80..0x8F]
      when 0xF1..0xF3 then [4, 0x10000, nil]
      when 0xF4 then [4, 0x10000, 0x90..0xBF]
      end
    end

    def decode_utf8(bytes, index, width)
      lead = bytes.getbyte(index)
      codepoint = lead & (width == 1 ? 0x7F : (0x7F >> (width - 1)))
      (1...width).each do |offset|
        codepoint = (codepoint << 6) | (bytes.getbyte(index + offset) & 0x3F)
      end
      codepoint
    end
  end
end
