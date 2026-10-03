# frozen_string_literal: true

require 'json'

module JWT
  # A hand written strict JSON parser used for JWT header and payload
  # segments. The parser never takes the duplicate member semantics of
  # +JSON.parse+ ("last value wins") and enforces structural limits so that
  # unverified input cannot trigger expensive parsing.
  #
  # Errors are instances of JSON::ParserError and carry only the byte
  # position and the error category in their message. Parsed keys, values or
  # source fragments are never interpolated into the message.
  #
  # @api private
  module StrictJSON
    # Maximum nesting depth of arrays and objects.
    MAX_DEPTH = 100

    # Maximum number of members in a single object.
    MAX_OBJECT_MEMBERS = 100

    # Maximum lexical length of a single JSON number.
    MAX_NUMBER_LENGTH = 20

    private_constant(:MAX_DEPTH, :MAX_OBJECT_MEMBERS, :MAX_NUMBER_LENGTH)

    # Raised when a segment violates the strict parsing rules.
    class ParseError < ::JSON::ParserError
      attr_reader :position, :category

      def initialize(category, position)
        @category = category
        @position = position
        super("JSON parsing failed: #{category} at position #{position}")
      end
    end

    module_function

    # Strictly parses a JSON document.
    #
    # @param data [String] the JSON document.
    # @return [Object] the parsed document.
    def parse(data)
      raise ParseError.new(:invalid_utf8, 0) unless data.dup.force_encoding(Encoding::UTF_8).valid_encoding?

      scanner = Scanner.new(data)
      value   = scanner.parse_value(1)
      scanner.skip_whitespace
      raise ParseError.new(:unexpected_token, scanner.position) unless scanner.end?

      value
    end

    # Byte oriented scanner for the JSON grammar.
    #
    # @api private
    class Scanner
      WHITESPACE = [0x20, 0x09, 0x0a, 0x0d].freeze
      private_constant(:WHITESPACE)

      attr_reader :position

      def initialize(data)
        @data = data
        @bytes = data.bytes
        @position = 0
      end

      def end?
        @position >= @bytes.length
      end

      def skip_whitespace
        @position += 1 while !end? && WHITESPACE.include?(@bytes[@position])
      end

      def parse_value(depth)
        skip_whitespace
        raise ParseError.new(:unexpected_end, @position) if end?

        byte = @bytes[@position]
        case byte
        when 0x7b then parse_container(depth, :object)
        when 0x5b then parse_container(depth, :array)
        when 0x22 then parse_string
        when 0x74, 0x66, 0x6e then parse_literal
        when 0x2d, 0x30..0x39 then parse_number
        else raise ParseError.new(:unexpected_token, @position)
        end
      end

      def parse_container(depth, type)
        raise ParseError.new(:depth_exceeded, @position) if depth > MAX_DEPTH

        opening, closing = type == :object ? [0x7b, 0x7d] : [0x5b, 0x5d]
        container = type == :object ? {} : []
        @position += 1 # consume the opening byte
        skip_whitespace
        if peek_byte == closing
          @position += 1 # consume the closing byte
          return container
        end

        loop do
          skip_whitespace
          if type == :object
            parse_object_member(container, depth)
          else
            container << parse_value(depth + 1)
          end
          break if consume_separator?(closing)
        end

        container
      end

      def parse_object_member(object, depth)
        raise ParseError.new(:unexpected_token, @position) unless peek_byte == 0x22

        key_start = @position
        key = parse_string
        raise ParseError.new(:duplicate_member, key_start) if object.key?(key)

        skip_whitespace
        expect_byte(0x3a, :unexpected_token)
        object[key] = parse_value(depth + 1)

        raise ParseError.new(:too_many_members, key_start) if object.size > MAX_OBJECT_MEMBERS
      end

      # Consumes the comma or closing byte following a member or element.
      # Returns true when the closing byte was consumed.
      def consume_separator?(closing_byte)
        skip_whitespace
        separator = consume_byte
        return true if separator == closing_byte

        raise ParseError.new(:unexpected_token, @position - 1) unless separator == 0x2c

        false
      end

      def parse_string
        start = @position
        @position += 1 # consume opening quote
        result = String.new(encoding: Encoding::UTF_8)

        until end?
          return result if append_string_char(result)
        end

        raise ParseError.new(:unexpected_end, start)
      end

      # Appends the next string character to +result+. Returns true when the
      # closing quote was consumed.
      def append_string_char(result)
        byte = @bytes[@position]
        case
        when byte == 0x22
          @position += 1
          true
        when byte == 0x5c
          result << parse_escape
          false
        when byte < 0x20
          raise ParseError.new(:unexpected_token, @position)
        when byte < 0x80
          result << byte
          @position += 1
          false
        else
          result << consume_multibyte
          false
        end
      end

      def consume_multibyte
        byte = @bytes[@position]
        size =
          if byte >= 0xf0 then 4
          elsif byte >= 0xe0 then 3
          elsif byte >= 0xc0 then 2
          else
            raise ParseError.new(:invalid_utf8, @position)
          end

        sequence = @bytes[@position, size]
        raise ParseError.new(:invalid_utf8, @position) if sequence.length < size
        raise ParseError.new(:invalid_utf8, @position) unless valid_utf8_sequence?(byte, sequence)

        @position += size
        sequence.pack('C*').force_encoding(Encoding::UTF_8)
      end

      def valid_utf8_sequence?(first_byte, sequence)
        (1...sequence.length).each do |index|
          return false unless (sequence[index] & 0xc0) == 0x80
        end

        case sequence.length
        when 2
          first_byte >= 0xc2
        when 3
          return false if first_byte == 0xe0 && sequence[1] < 0xa0
          return false if first_byte == 0xed && sequence[1] > 0x9f
          true
        when 4
          return false if first_byte == 0xf0 && sequence[1] < 0x90
          return false if first_byte == 0xf4 && sequence[1] > 0x8f
          return false if first_byte > 0xf4
          true
        end
      end

      def parse_escape
        start = @position
        @position += 1 # consume backslash
        raise ParseError.new(:unexpected_end, start) if end?

        escaped = @data[@position]
        @position += 1
        case escaped
        when '"' then '"'
        when '\\' then '\\'
        when '/' then '/'
        when 'b' then "\b"
        when 'f' then "\f"
        when 'n' then "\n"
        when 'r' then "\r"
        when 't' then "\t"
        when 'u' then parse_unicode_escape(start)
        else raise ParseError.new(:unexpected_token, start)
        end
      end

      def parse_unicode_escape(start)
        high = parse_hex4(start)
        codepoint =
          if (0xd800..0xdbff).cover?(high)
            unless peek_byte == 0x5c && @bytes[@position + 1] == 0x75
              raise ParseError.new(:unexpected_token, @position)
            end
            @position += 2
            low = parse_hex4(start)
            unless (0xdc00..0xdfff).cover?(low)
              raise ParseError.new(:unexpected_token, start)
            end
            0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
          elsif (0xdc00..0xdfff).cover?(high)
            raise ParseError.new(:unexpected_token, start)
          else
            high
          end

        codepoint.chr(Encoding::UTF_8)
      end

      def parse_hex4(escape_start)
        hex = @bytes[@position, 4]
        raise ParseError.new(:unexpected_end, escape_start) unless hex&.length == 4
        value = hex.pack('C*').hex
        raise ParseError.new(:unexpected_token, escape_start) unless hex.all? { |byte| hex_digit?(byte) }

        @position += 4
        value
      end

      def hex_digit?(byte)
        (0x30..0x39).cover?(byte) || (0x41..0x46).cover?(byte) || (0x61..0x66).cover?(byte)
      end

      def parse_literal
        start = @position
        if @data[start, 4] == 'true'
          @position += 4
          true
        elsif @data[start, 5] == 'false'
          @position += 5
          false
        elsif @data[start, 4] == 'null'
          @position += 4
          nil
        else
          raise ParseError.new(:unexpected_token, start)
        end
      end

      def parse_number
        start = @position
        @position += 1 if peek_byte == 0x2d
        parse_integer_part
        parse_fraction_part
        parse_exponent_part
        finish_number(start)
      end

      def parse_integer_part
        if peek_byte == 0x30
          @position += 1
        elsif (0x31..0x39).cover?(peek_byte)
          @position += 1 while (0x30..0x39).cover?(peek_byte)
        else
          raise ParseError.new(:unexpected_token, @position)
        end
      end

      def parse_fraction_part
        return unless peek_byte == 0x2e

        @position += 1
        raise ParseError.new(:unexpected_token, @position) unless (0x30..0x39).cover?(peek_byte)

        @position += 1 while (0x30..0x39).cover?(peek_byte)
      end

      def parse_exponent_part
        return unless peek_byte == 0x65 || peek_byte == 0x45

        @position += 1
        @position += 1 if peek_byte == 0x2b || peek_byte == 0x2d
        raise ParseError.new(:unexpected_token, @position) unless (0x30..0x39).cover?(peek_byte)

        @position += 1 while (0x30..0x39).cover?(peek_byte)
      end

      def finish_number(start)
        length = @position - start
        if length > MAX_NUMBER_LENGTH
          raise ParseError.new(:number_too_long, start)
        end

        convert_number(start, length)
      end

      def convert_number(start, length)
        ::JSON.parse(@bytes[start, length].pack('C*'))
      rescue ::JSON::ParserError
        raise ParseError.new(:unexpected_token, start)
      end

      def peek_byte
        @bytes[@position]
      end

      def consume_byte
        byte = @bytes[@position]
        @position += 1
        byte
      end

      def expect_byte(expected_byte, category)
        actual = consume_byte
        raise ParseError.new(category, @position - 1) unless actual == expected_byte
      end
    end

    private_constant(:Scanner)
  end
end
