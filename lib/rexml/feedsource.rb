# frozen_string_literal: false
require_relative "source"

module REXML
  # A Source that is fed chunks of data by its caller instead of
  # reading from an IO by itself.  This is useful when the caller
  # already owns reading the input, for example a non-blocking event
  # loop.  See Parsers::FeedParser.
  #
  # When the parser runs out of data, the parsing fiber is suspended
  # with Fiber.yield so that the caller can feed more data and resume
  # parsing.  Data is exposed to the parser only up to the last token
  # boundary (one of ">", '"', "'" or ";") and bytes that may be an
  # incomplete multi-byte character are held back as well, so a
  # construct split across chunks is never mistaken for malformed XML.
  # Once #finish is called everything is exposed and any remaining
  # incompleteness is reported as an error by the parser.
  class FeedSource < Source # :nodoc: all
    # Characters after which a token may be complete.  Data after the
    # last of these characters is held back until more data (or
    # #finish) arrives.
    TOKEN_BOUNDARY_PATTERN = /[>"';]/

    def initialize(encoding=nil)
      @finished = false
      @raw_buffer = +""
      @held_text = +""
      @parser_fiber = nil
      @encoding_detected = !encoding.nil?
      super(+"", encoding)
    end

    # The fiber that parses this source.  Only this fiber is suspended
    # when more data is needed.
    attr_accessor :parser_fiber

    # Appends a chunk of data.  Returns self.
    def feed(data)
      raise IOError, "cannot feed after finish" if @finished
      @raw_buffer << data.b
      prepare_buffer
      self
    end

    # Marks the input as complete and exposes any held back data.
    # Feeding more data after this call raises IOError.
    def finish
      return self if @finished
      @finished = true
      prepare_buffer
      self
    end

    def finished?
      @finished
    end

    def read_until(term)
      pattern = Private::PRE_DEFINED_TERM_PATTERNS[term] || /#{Regexp.escape(term)}/
      loop do
        data = @scanner.scan_until(pattern)
        return data if data
        break unless await_data
      end
      rest = @scanner.rest
      @scanner.pos = @scanner.string.bytesize
      rest
    end

    def ensure_buffer
      while @scanner.eos? && !@finished
        break unless await_data
      end
    end

    def match(pattern, cons=false)
      loop do
        if cons
          md = @scanner.scan(pattern)
        else
          md = @scanner.check(pattern)
        end
        return @scanner if md
        return nil if fail_fast?(pattern)
        return nil unless await_data
      end
    end

    def match?(pattern, cons=false)
      loop do
        if cons
          n_matched_bytes = @scanner.skip(pattern)
        else
          n_matched_bytes = @scanner.match?(pattern)
        end
        return true if n_matched_bytes
        if pattern.is_a?(String)
          # A string pattern can still match when the remaining buffer
          # is a prefix of it; otherwise the input is malformed.
          return false unless pattern.start_with?(@scanner.rest)
        elsif fail_fast?(pattern)
          return false
        end
        return false unless await_data
      end
    end

    def skip_spaces
      loop do
        return true if @scanner.skip(Private::SPACES_PATTERN)
        return false unless @scanner.eos?
        return false unless await_data
      end
    end

    def peek_byte
      while @scanner.eos?
        break unless await_data
      end
      @scanner.peek_byte
    end

    def empty?
      super and @finished
    end

    def current_line
      consumed = @scanner.string.byteslice(0, @scanner.pos) || +""
      line = consumed.count("\n") + 1
      [@scanner.pos, line, line]
    end

    private

    # Yields to the caller so that it can feed more data.  Returns
    # false when no more data can arrive (the input is finished, or
    # this is called outside of the parsing fiber).
    def await_data
      return false if @finished
      return false unless @parser_fiber && Fiber.current.equal?(@parser_fiber)
      Fiber.yield(:need_more_data)
      true
    end

    def fail_fast?(pattern)
      return true if pattern.is_a?(String)
      Parsers::BaseParser::FAIL_FAST_PATTERNS.include?(pattern)
    end

    def prepare_buffer
      detect_encoding_if_needed
      pump_buffer
    end

    def detect_encoding_if_needed
      return if @encoding_detected
      return if @raw_buffer.bytesize < 3 && !@finished
      @encoding_detected = true
      if @raw_buffer.start_with?("\xFE\xFF".b)
        self.encoding = "UTF-16BE"
        @raw_buffer = @raw_buffer.byteslice(2..-1) || +""
      elsif @raw_buffer.start_with?("\xFF\xFE".b)
        self.encoding = "UTF-16LE"
        @raw_buffer = @raw_buffer.byteslice(2..-1) || +""
      elsif @raw_buffer.start_with?("\xEF\xBB\xBF".b)
        self.encoding = "UTF-8"
        @raw_buffer = @raw_buffer.byteslice(3..-1) || +""
      end
    end

    def pump_buffer
      return unless @encoding_detected
      if @finished
        bytes = @raw_buffer
        @raw_buffer = +""
      else
        return if @raw_buffer.empty?
        bytes = extract_valid_prefix(@raw_buffer)
        @raw_buffer = @raw_buffer.byteslice(bytes.bytesize..-1) || +""
      end
      text = @held_text + decode_bytes(bytes)
      if @finished
        @held_text = +""
      else
        boundary = text.rindex(TOKEN_BOUNDARY_PATTERN)
        if boundary
          @held_text = text[(boundary + 1)..-1] || +""
          text = text[0..boundary]
        else
          @held_text = text
          return
        end
      end
      @scanner << text unless text.empty?
    end

    # Returns the longest prefix of +bytes+ that is valid in the
    # current encoding.  A trailing incomplete multi-byte character is
    # left out so that it can be completed by a following chunk.
    def extract_valid_prefix(bytes)
      return bytes if bytes.dup.force_encoding(@encoding).valid_encoding?
      # An incomplete character is only a few bytes long.  If more
      # bytes are needed to make the buffer valid, the buffer contains
      # genuinely invalid bytes; they are held back and reported once
      # #finish flushes them.
      1.upto(6) do |trim|
        break if trim >= bytes.bytesize
        prefix = bytes.byteslice(0, bytes.bytesize - trim)
        return prefix if prefix.dup.force_encoding(@encoding).valid_encoding?
      end
      +""
    end

    def decode_bytes(bytes)
      if @to_utf
        decode(bytes.force_encoding(@encoding))
      else
        bytes.force_encoding(::Encoding::UTF_8)
      end
    end

    # The scanner always holds decoded UTF-8 text, so unlike Source
    # there is nothing to convert on an encoding change; only future
    # chunks need to be decoded differently.
    def encoding_updated
      @to_utf = @encoding != "UTF-8"
      @scanner.string.force_encoding(::Encoding::UTF_8)
    end
  end
end
