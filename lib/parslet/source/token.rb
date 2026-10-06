require 'parslet/token'

module Parslet
  # A token based input stream. Parslet moves through this source one token at
  # a time, while slices and error positions continue to refer to the original
  # string. Characters omitted by the lexer (whitespace, comments, etc.) may
  # remain between token ranges and do not affect the parser cursor.
  class TokenSource
    ResolvedToken = Struct.new(:type, :value, :range, :lexeme, :start_byte, :end_byte)

    class LineCache
      def initialize(string)
        @string = string
        @line_start_bytes = [0]

        string.each_byte.each_with_index do |byte, index|
          @line_start_bytes << index + 1 if byte == "\n".ord
        end
      end

      def line_and_column(position)
        position = position.bytepos if position.respond_to?(:bytepos)
        line_index = find_line_index(position)
        line_start = @line_start_bytes[line_index]
        column = @string.byteslice(line_start, position - line_start).size + 1

        [line_index + 1, column]
      end

      private

      def find_line_index(position)
        left = 0
        right = @line_start_bytes.size - 1

        while left < right
          middle = left + ((right - left + 1) / 2)

          if @line_start_bytes[middle] <= position
            left = middle
          else
            right = middle - 1
          end
        end

        left
      end
    end

    attr_reader :string, :tokens

    def initialize(string, tokens)
      unless string.respond_to?(:to_str)
        raise ArgumentError, "Must construct TokenSource with a string like object."
      end

      @string = string.to_str
      @line_cache = LineCache.new(@string)
      @tokens = resolve_tokens(tokens)
      validate_ranges
      @token_pos = 0
    end

    # Parslet uses bytepos as its opaque rewindable cursor. For token input,
    # the cursor is a token index rather than a byte offset. Use #pos for the
    # position in the original source.
    def bytepos
      @token_pos
    end

    def bytepos=(position)
      position = Integer(position)
      @token_pos = position if position >= 0 && position <= tokens.size
    end

    def pos
      Position.new(string, current_start_byte)
    end

    def current_token
      tokens[@token_pos]
    end

    def chars_left
      tokens.size - @token_pos
    end

    def consume(count)
      return empty_slice if count <= 0 || tokens.empty? || @token_pos >= tokens.size

      first_token = tokens[@token_pos]
      end_index = [@token_pos + count, tokens.size].min
      slice_string = tokens[@token_pos...end_index].map(&:lexeme).join
      @token_pos = end_index

      Slice.new(
        Position.new(string, first_token.start_byte),
        slice_string,
        @line_cache)
    end

    def consume_token
      token = current_token
      return empty_slice unless token

      @token_pos += 1
      Slice.new(
        Position.new(string, token.start_byte),
        token.lexeme,
        @line_cache,
        token)
    end

    def line_and_column(position=nil)
      @line_cache.line_and_column(position || current_start_byte)
    end

    def chars_until(_string)
      raise NoMethodError, "TokenSource does not support character searches."
    end

    private

    def resolve_tokens(tokens)
      tokens.each_with_index.map do |raw_token, index|
        token = Token.from(raw_token)
        start_byte, end_byte = normalize_range(token.range, index)
        lexeme = string.byteslice(start_byte, end_byte - start_byte)

        if lexeme.nil?
          raise ArgumentError,
            "Token #{index} range #{token.range.inspect} is outside the source."
        end

        ResolvedToken.new(
          token.type,
          token.value,
          token.range,
          lexeme,
          start_byte,
          end_byte)
      end
    end

    def normalize_range(range, index)
      unless range.respond_to?(:begin) && range.respond_to?(:end) &&
          range.respond_to?(:exclude_end?)
        raise ArgumentError,
          "Token #{index} range must be a byte Range."
      end

      start_byte = Integer(range.begin)
      raw_end_byte = Integer(range.end)
      end_byte = range.exclude_end? ? raw_end_byte : raw_end_byte + 1

      if start_byte < 0
        raise ArgumentError,
          "Token #{index} range #{range.inspect} starts before the source."
      end

      if end_byte <= start_byte
        raise ArgumentError,
          "Token #{index} range #{range.inspect} is empty or reversed."
      end

      if end_byte > string.bytesize
        raise ArgumentError,
          "Token #{index} range #{range.inspect} ends after the source."
      end

      unless valid_character_boundary?(start_byte) && valid_character_boundary?(end_byte)
        raise ArgumentError,
          "Token #{index} range #{range.inspect} does not start on a character boundary."
      end

      [start_byte, end_byte]
    rescue ArgumentError, TypeError => error
      raise if error.message.start_with?("Token ")
      raise ArgumentError,
        "Token #{index} range must be a byte Range."
    end

    def valid_character_boundary?(byte_offset)
      string.byteslice(0, byte_offset).valid_encoding?
    end

    def validate_ranges
      previous_end_byte = 0

      tokens.each_with_index do |token, index|
        if token.start_byte < previous_end_byte
          raise ArgumentError,
            "Token #{index} range #{token.range.inspect} overlaps a previous token or is not ordered."
        end

        previous_end_byte = token.end_byte
      end
    end

    def current_start_byte
      if token = current_token
        token.start_byte
      else
        tokens.last ? tokens.last.end_byte : 0
      end
    end

    def empty_slice
      Slice.new(Position.new(string, current_start_byte), "", @line_cache)
    end
  end
end
