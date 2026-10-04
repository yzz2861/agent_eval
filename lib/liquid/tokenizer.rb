# frozen_string_literal: true

require "strscan"

module Liquid
  class Tokenizer
    attr_reader :line_number, :for_liquid_tag, :last_token, :last_token_range

    TAG_END = /%\}/
    TAG_OR_VARIABLE_START = /\{[\{\%]/
    NEWLINE = /\n/

    OPEN_CURLEY = "{".ord
    CLOSE_CURLEY = "}".ord
    PERCENTAGE = "%".ord

    def initialize(
      source:,
      string_scanner:,
      line_numbers: false,
      line_number: nil,
      for_liquid_tag: false,
      source_start_offset: 0,
      track_source_ranges: false
    )
      @line_number = line_number || (line_numbers ? 1 : nil)
      @for_liquid_tag = for_liquid_tag
      @source = source.to_s.to_str
      @offset = 0
      @tokens = []
      @token_ranges = []
      @last_token = nil
      @last_token_range = nil
      @source_start_offset = source_start_offset
      @track_source_ranges = track_source_ranges

      if @source
        @ss = string_scanner
        @ss.string = @source
        tokenize
      end
    end

    def shift
      token = @tokens[@offset]

      return unless token

      @offset += 1
      if @track_source_ranges
        @last_token = token
        @last_token_range = @token_ranges[@offset - 1]
      end

      if @line_number
        @line_number += @for_liquid_tag ? 1 : token.count("\n")
      end

      token
    end

    private

    def tokenize
      if @for_liquid_tag
        if @track_source_ranges
          tokenize_liquid_tag
        else
          @tokens = @source.split("\n")
        end
      else
        tokenize_normal
      end

      @source = nil
      @ss = nil
    end

    def tokenize_normal
      if @track_source_ranges
        until @ss.eos?
          start = @ss.pos
          token = shift_normal
          @tokens << token
          @token_ranges << source_range(start, @ss.pos)
        end
      else
        @tokens << shift_normal until @ss.eos?
      end
    end

    def tokenize_liquid_tag
      offset = 0
      @source.each_line do |line|
        token = line.chomp("\n")
        @tokens << token
        @token_ranges << source_range(offset, offset + token.bytesize)
        offset += line.bytesize
      end
    end

    def source_range(start_byte, end_byte)
      (@source_start_offset + start_byte)...(@source_start_offset + end_byte)
    end

    def shift_normal
      token = next_token

      return unless token

      token
    end

    def next_token
      # possible states: :text, :tag, :variable
      byte_a = @ss.peek_byte

      if byte_a == OPEN_CURLEY
        @ss.scan_byte

        byte_b = @ss.peek_byte

        if byte_b == PERCENTAGE
          @ss.scan_byte
          return next_tag_token
        elsif byte_b == OPEN_CURLEY
          @ss.scan_byte
          return next_variable_token
        end

        @ss.pos -= 1
      end

      next_text_token
    end

    def next_text_token
      start = @ss.pos

      unless @ss.skip_until(TAG_OR_VARIABLE_START)
        token = @ss.rest
        @ss.terminate
        return token
      end

      pos = @ss.pos -= 2
      @source.byteslice(start, pos - start)
    rescue ::ArgumentError => e
      if e.message == "invalid byte sequence in #{@ss.string.encoding}"
        raise SyntaxError, "Invalid byte sequence in #{@ss.string.encoding}"
      else
        raise
      end
    end

    def next_variable_token
      start = @ss.pos - 2

      byte_a = byte_b = @ss.scan_byte

      while byte_b
        byte_a = @ss.scan_byte while byte_a && byte_a != CLOSE_CURLEY && byte_a != OPEN_CURLEY

        break unless byte_a

        if @ss.eos?
          return byte_a == CLOSE_CURLEY ? @source.byteslice(start, @ss.pos - start) : "{{"
        end

        byte_b = @ss.scan_byte

        if byte_a == CLOSE_CURLEY
          if byte_b == CLOSE_CURLEY
            return @source.byteslice(start, @ss.pos - start)
          elsif byte_b != CLOSE_CURLEY
            @ss.pos -= 1
            return @source.byteslice(start, @ss.pos - start)
          end
        elsif byte_a == OPEN_CURLEY && byte_b == PERCENTAGE
          return next_tag_token_with_start(start)
        end

        byte_a = byte_b
      end

      "{{"
    end

    def next_tag_token
      start = @ss.pos - 2
      if (len = @ss.skip_until(TAG_END))
        @source.byteslice(start, len + 2)
      else
        "{%"
      end
    end

    def next_tag_token_with_start(start)
      @ss.skip_until(TAG_END)
      @source.byteslice(start, @ss.pos - start)
    end
  end
end
