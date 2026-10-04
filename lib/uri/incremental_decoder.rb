# frozen_string_literal: true
#--
# = uri/incremental_decoder.rb
#
# License::
#   You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

module URI
  # Incremental decoder for percent-encoded (URL-encoded) data.
  #
  # URI::IncrementalDecoder decodes a percent-encoded stream chunk by
  # chunk, without ever requiring the whole encoded input to be
  # concatenated in memory.  It is meant for gateways and proxies that
  # read long URL-encoded fields in blocks.
  #
  # A decoder is created with a +mode+ and a target +encoding+:
  #
  #   dec = URI::IncrementalDecoder.new(mode: :form)
  #   dec.feed("a+b%21%20%E4%BD") # => "a b! "
  #   dec.feed("%A0%E5%A5%BD")    # => "你好"
  #   dec.finish                  # => ""
  #
  # Two modes are supported:
  #
  # [:component]
  #   Decodes like URI.decode_uri_component: <tt>'+'</tt> is preserved.
  # [:form]
  #   Decodes like URI.decode_www_form_component: <tt>'+'</tt> is
  #   decoded as a space.
  #
  # Chunk boundaries may fall anywhere: inside a <tt>%HH</tt> escape or
  # inside a multi-byte character of the target encoding.  Decoded
  # bytes are buffered and only complete characters are ever emitted;
  # an incomplete trailing character is held back until the missing
  # bytes arrive (or until #finish, which flushes whatever remains,
  # like URI.decode_www_form_component does for invalid input).
  #
  # == Errors
  #
  # A <tt>'%'</tt> that is not followed by two hexadecimal digits
  # raises URI::IncrementalDecoder::InvalidEscapeError from #feed, and
  # a trailing incomplete escape at end of input raises
  # URI::IncrementalDecoder::TruncatedInputError from #finish.  Both
  # exceptions carry the byte +offset+ of the offending <tt>'%'</tt>
  # in the original (concatenated) input, along with the raw
  # +fragment+.
  #
  # Once an exception has been raised the decoder is in a failed
  # state: any further #feed or #finish call raises
  # URI::IncrementalDecoder::StateError and no partial output is
  # produced.  Call #reset to reuse the decoder for a new input.
  # Likewise, calling #feed after a successful #finish raises
  # StateError.
  class IncrementalDecoder
    # Base class for the errors raised by URI::IncrementalDecoder.
    class Error < StandardError; end

    # Raised by #feed when a <tt>'%'</tt> is not followed by two
    # hexadecimal digits.
    class InvalidEscapeError < Error
      # Byte offset of the offending <tt>'%'</tt> in the original input.
      attr_reader :offset

      # The raw input bytes at #offset (up to 3 bytes).
      attr_reader :fragment

      def initialize(offset, fragment) # :nodoc:
        @offset = offset
        @fragment = fragment
        super("invalid percent-escape #{fragment.inspect} at input offset #{offset}")
      end
    end

    # Raised by #finish when the input ends in the middle of a
    # percent-escape (a dangling <tt>'%'</tt> or <tt>%H</tt>).
    class TruncatedInputError < Error
      # Byte offset of the dangling <tt>'%'</tt> in the original input.
      attr_reader :offset

      # The dangling bytes (<tt>"%"</tt> or <tt>"%H"</tt>).
      attr_reader :fragment

      def initialize(offset, fragment) # :nodoc:
        @offset = offset
        @fragment = fragment
        super("truncated percent-escape #{fragment.inspect} at input offset #{offset}")
      end
    end

    # Raised when #feed or #finish is called after the decoder has
    # finished or failed.  Call #reset to reuse the decoder.
    class StateError < Error; end

    # The decoding mode: +:component+ or +:form+.
    attr_reader :mode

    # The encoding of the strings returned by #feed and #finish.
    attr_reader :encoding

    PERCENT = 0x25 # :nodoc:
    PLUS    = 0x2B # :nodoc:

    HEX_DIGIT = [false] * 256 # :nodoc:
    "0123456789abcdefABCDEF".each_byte { |byte| HEX_DIGIT[byte] = true }
    HEX_DIGIT.freeze

    # Matches one valid escape, one plain run, or a lone '%' (invalid).
    # In form mode '+' gets its own alternative so it can become a space.
    SCAN_COMPONENT = /%([0-9A-Fa-f]{2})|([^%]+)|%/ # :nodoc:
    SCAN_FORM      = /%([0-9A-Fa-f]{2})|\+|([^%+]+)|%/ # :nodoc:

    # Creates an incremental decoder.
    #
    # +mode+ is +:component+ (preserve <tt>'+'</tt>) or +:form+
    # (decode <tt>'+'</tt> as a space); default is +:component+.
    #
    # +encoding+ is the encoding of the decoded output; default is
    # Encoding::UTF_8.  Decoded bytes are interpreted in this encoding
    # and only complete characters are emitted.  Any encoding with a
    # converter to UTF-8 (and Encoding::BINARY, which emits every byte
    # immediately) is supported.
    def initialize(mode: :component, encoding: Encoding::UTF_8)
      unless mode == :component || mode == :form
        raise ArgumentError, "unknown mode: #{mode.inspect} (expected :component or :form)"
      end
      @mode = mode
      @encoding = Encoding.find(encoding)
      @scan = mode == :form ? SCAN_FORM : SCAN_COMPONENT
      @probe_target =
        case @encoding
        when Encoding::BINARY then nil
        when Encoding::UTF_8 then Encoding::UTF_16BE
        else Encoding::UTF_8
        end
      reset
    end

    # Feeds one +chunk+ of the percent-encoded input and returns the
    # decoded output as a String in the target encoding.  The returned
    # string may be empty when the chunk ends inside an escape sequence
    # or inside a multi-byte character.
    #
    # Raises InvalidEscapeError if the chunk contains a <tt>'%'</tt>
    # that is not followed by two hexadecimal digits; the decoder is
    # then failed and must be #reset before further use.
    #
    # Raises StateError if the decoder has already finished or failed.
    def feed(chunk)
      check_running!
      unless chunk = String.try_convert(chunk)
        raise TypeError, "no implicit conversion of #{chunk.class} into String"
      end
      chunk = chunk.b
      data = @escape.empty? ? chunk : @escape + chunk
      base = @received - @escape.bytesize
      @escape = +"".b
      @received += chunk.bytesize

      # Hold back a trailing incomplete escape ("%", "%H") so that a
      # '%HH' sequence split across chunks is never misread.
      size = data.bytesize
      limit = size
      if size >= 1 && data.getbyte(size - 1) == PERCENT
        limit = size - 1
      elsif size >= 2 && data.getbyte(size - 2) == PERCENT && HEX_DIGIT[data.getbyte(size - 1)]
        limit = size - 2
      end
      if limit < size
        @escape = data.byteslice(limit, size - limit)
        @escape_offset = base + limit
      end

      out = +"".b
      segment = data.byteslice(0, limit)
      segment.scan(@scan) do
        match = Regexp.last_match
        if hex = match[1]
          out << hex.to_i(16)
        elsif plain = match[2]
          out << plain
        elsif match[0] == "+"
          out << " "
        else
          fail_with(InvalidEscapeError.new(base + match.begin(0),
                                           segment.byteslice(match.begin(0), 3)))
        end
      end
      @pending << out
      pump
    end

    # Finishes the decoding and returns the remaining decoded output as
    # a String in the target encoding.
    #
    # Raises TruncatedInputError if the input ends with a dangling
    # <tt>'%'</tt> or <tt>%H</tt>; the decoder is then failed and must
    # be #reset before further use.
    #
    # If the decoded bytes end with an incomplete character of the
    # target encoding, those bytes are flushed as-is, like
    # URI.decode_www_form_component does for invalid input.
    #
    # Raises StateError if the decoder has already finished or failed.
    def finish
      check_running!
      @finished = true
      unless @escape.empty?
        @failed = true
        raise TruncatedInputError.new(@escape_offset, @escape)
      end
      out = @pending
      @pending = +"".b
      out.force_encoding(@encoding)
    end

    # Whether the decoder has raised an error.  A failed decoder
    # rejects further #feed/#finish calls with StateError until
    # #reset is called.
    def failed?
      @failed
    end

    # Whether #finish has been called successfully.
    def finished?
      @finished
    end

    # Resets the decoder to its initial state, forgetting all buffered
    # input and output, so it can decode a new input with the same
    # mode and encoding.  Returns self.
    def reset
      @escape = +"".b        # held-back "%" or "%H" fragment
      @escape_offset = 0     # input offset of @escape
      @pending = +"".b       # decoded bytes not yet emitted
      @received = 0          # total input bytes fed so far
      @finished = false
      @failed = false
      self
    end

    private

    def check_running!
      raise StateError, "decoder has failed; call #reset to reuse it" if @failed
      raise StateError, "decoder already finished; call #reset to reuse it" if @finished
    end

    def fail_with(error)
      @failed = true
      raise error
    end

    # Moves as many decoded bytes as possible out of the buffer,
    # holding back only a trailing incomplete character of the target
    # encoding.  Returns the emitted string in the target encoding.
    def pump
      return +"" if @pending.empty?
      emit = safe_emit_length(@pending)
      if emit == @pending.bytesize
        out = @pending
        @pending = +"".b
      else
        out = @pending.byteslice(0, emit)
        @pending = @pending.byteslice(emit, @pending.bytesize - emit)
      end
      out.force_encoding(@encoding)
    end

    # Returns how many leading bytes of +bytes+ end on a character
    # boundary of the target encoding.  Invalid-but-complete byte
    # sequences count as complete (they are passed through, like
    # URI.decode_www_form_component does); only a truncated trailing
    # character is held back.
    def safe_emit_length(bytes)
      return bytes.bytesize unless @probe_target
      converter = Encoding::Converter.new(@encoding, @probe_target)
      src = bytes.dup
      dst = +"".b
      emit = 0
      loop do
        before = src.bytesize
        case converter.primitive_convert(src, dst)
        when :finished
          return emit + before
        when :incomplete_input
          tail = converter.primitive_errinfo[3]
          return emit + before - (tail ? tail.bytesize : 0)
        else
          # :invalid_byte_sequence (or :undefined_conversion): the
          # offending bytes were consumed and reported; pass them
          # through and keep scanning the remainder.
          emit += before - src.bytesize
        end
      end
    end
  end
end
