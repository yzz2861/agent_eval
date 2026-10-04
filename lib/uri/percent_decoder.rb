# frozen_string_literal: true

module URI
  # PercentDecoder incrementally decodes a percent-encoded (%HH) stream,
  # such as a long URL-encoded field that a gateway reads in chunks.
  #
  # Instead of buffering the whole encoded input, feed each chunk to #feed
  # as it arrives and close the stream with #finish. Both return whatever
  # decoded output has become ready (possibly an empty string):
  #
  #   decoder = URI::PercentDecoder.new(mode: :form)
  #   decoder.feed("q=%E4%B8") # => "q="     (character not complete yet)
  #   decoder.feed("%AD+x")    # => "中 x"
  #   decoder.finish           # => ""
  #
  # A %HH escape or a multibyte character may be split across chunks at any
  # byte boundary; incomplete characters are never emitted before their
  # last byte arrives.
  #
  # == Modes
  #
  # [+:component+ (default)]
  #   Decodes like a generic URI component (see RFC 3986): only %HH escapes
  #   are decoded, a literal <tt>'+'</tt> is kept as-is.
  # [+:form+]
  #   Decodes like an +application/x-www-form-urlencoded+ field
  #   (see URI.decode_www_form_component): additionally, <tt>'+'</tt>
  #   decodes to a space.
  #
  # == Output encoding
  #
  # Decoded bytes are interpreted in +encoding+ (an Encoding or its name,
  # default: Encoding::UTF_8), following the same convention as
  # URI.decode_www_form_component; returned strings bear that encoding.
  # Pass Encoding::BINARY to get the raw decoded bytes with no character
  # boundary checks.
  #
  # == Errors
  #
  # All decoding errors are subclasses of PercentDecoder::Error and carry
  # Error#offset: the 0-based byte offset in the concatenation of all
  # chunks fed so far, pointing at the offending input:
  #
  # [InvalidEscapeError]
  #   A <tt>'%'</tt> was not followed by two hexadecimal digits.
  #   InvalidEscapeError#sequence returns the offending input bytes.
  # [InvalidByteSequenceError]
  #   Decoded bytes are not valid in the output encoding.
  #   InvalidByteSequenceError#bytes returns the invalid byte sequence.
  # [TruncatedInputError]
  #   #finish was called with an incomplete escape or an incomplete
  #   multibyte character still pending. TruncatedInputError#fragment
  #   returns the leftover bytes.
  #
  # A decoder is single-use: once any Error has been raised, or once
  # #finish has succeeded, the decoder is dead and both #feed and #finish
  # raise StateError. Create a new instance to decode another stream.
  # (Passing a non-String argument to #feed raises TypeError and leaves
  # the decoder usable.)
  class PercentDecoder
    # Base class for decoding errors raised by PercentDecoder.
    # #offset is the 0-based byte offset in the decoded input stream.
    class Error < StandardError
      attr_reader :offset

      def initialize(message, offset)
        @offset = offset
        super(message)
      end
    end

    # Raised when a '%' is not followed by two hexadecimal digits.
    # #sequence holds the offending input bytes (e.g. "%GZ").
    class InvalidEscapeError < Error
      attr_reader :sequence

      def initialize(message, offset, sequence:)
        @sequence = sequence
        super(message, offset)
      end
    end

    # Raised when decoded bytes are invalid in the output encoding.
    # #bytes holds the invalid byte sequence.
    class InvalidByteSequenceError < Error
      attr_reader :bytes

      def initialize(message, offset, bytes:)
        @bytes = bytes
        super(message, offset)
      end
    end

    # Raised by #finish when the input ends with an incomplete %HH escape
    # or an incomplete multibyte character. #fragment holds the leftover
    # bytes.
    class TruncatedInputError < Error
      attr_reader :fragment

      def initialize(message, offset, fragment:)
        @fragment = fragment
        super(message, offset)
      end
    end

    # Raised when #feed or #finish is called on a dead decoder
    # (already finished, or failed with a decoding Error).
    class StateError < StandardError; end

    HEX_VALUES = Array.new(256, -1) # :nodoc:
    "0123456789ABCDEFabcdef".each_byte do |byte|
      HEX_VALUES[byte] = byte.chr(Encoding::US_ASCII).to_i(16)
    end
    HEX_VALUES.freeze
    private_constant :HEX_VALUES

    PERCENT = 0x25 # :nodoc:
    PLUS    = 0x2B # :nodoc:
    private_constant :PERCENT, :PLUS

    attr_reader :mode, :encoding

    # Creates a decoder. +mode+ is +:component+ (default) or +:form+;
    # +encoding+ is the Encoding (or its name) of the decoded output,
    # defaulting to Encoding::UTF_8.
    def initialize(mode: :component, encoding: Encoding::UTF_8)
      mode = mode.to_sym if mode.respond_to?(:to_sym)
      unless mode == :component || mode == :form
        raise ArgumentError, "unknown mode: #{mode.inspect} (expected :component or :form)"
      end
      @mode = mode
      @encoding = encoding.nil? ? Encoding::UTF_8 : Encoding.find(encoding)

      @offset = 0            # input bytes consumed so far
      @escape = nil          # in-progress escape ("%", "%H") or nil
      @escape_offset = 0     # input offset of the '%' of @escape
      @pending = +"".b       # decoded bytes not yet known to end on a character boundary
      @pending_offsets = []  # input offset of each byte of @pending
      @finished = false
      @failed = false
    end

    # Decodes one chunk of input and returns the decoded output that is
    # ready (a String in the output encoding, possibly empty).
    #
    # Raises TypeError if +chunk+ is not a String (the decoder stays
    # usable), InvalidEscapeError or InvalidByteSequenceError on malformed
    # input (the decoder becomes unusable), and StateError on a dead
    # decoder.
    def feed(chunk)
      check_running!(:feed)
      unless chunk.is_a?(String)
        raise TypeError, "no implicit conversion of #{chunk.class} into String"
      end
      process(chunk.b)
      drain
    rescue Error
      @failed = true
      raise
    end

    # Closes the stream and returns the remaining decoded output.
    #
    # Raises TruncatedInputError if the input ends with an incomplete
    # escape or character, InvalidByteSequenceError on malformed input
    # (both make the decoder unusable), and StateError on a dead decoder.
    def finish
      check_running!(:finish)
      if @escape
        raise TruncatedInputError.new(
          "incomplete percent-escape #{@escape.inspect} at input offset #{@escape_offset}",
          @escape_offset, fragment: @escape.dup)
      end
      output = drain
      unless @pending.empty?
        raise TruncatedInputError.new(
          "incomplete #{@encoding.name} character at input offset #{@pending_offsets.first}",
          @pending_offsets.first, fragment: @pending.dup)
      end
      @finished = true
      output
    rescue Error
      @failed = true
      raise
    end

    # Whether #finish has completed successfully.
    def finished?
      @finished
    end

    # Whether a decoding Error has been raised.
    def failed?
      @failed
    end

    # Decodes +string+ in one shot; equivalent to feeding it to a fresh
    # decoder and finishing. Accepts the same keyword arguments as #new.
    def self.decode(string, mode: :component, encoding: Encoding::UTF_8)
      decoder = new(mode: mode, encoding: encoding)
      decoder.feed(string) << decoder.finish
    end

    private

    def check_running!(action)
      if @finished
        raise StateError, "cannot #{action}: decoder already finished"
      end
      if @failed
        raise StateError, "cannot #{action}: decoder failed with a decoding error; create a new decoder"
      end
    end

    def process(bytes)
      bytes.each_byte do |byte|
        if @escape
          if HEX_VALUES[byte] >= 0
            @escape << byte
            if @escape.bytesize == 3
              @pending << ((HEX_VALUES[@escape.getbyte(1)] << 4) | HEX_VALUES[@escape.getbyte(2)])
              @pending_offsets << @escape_offset
              @escape = nil
            end
          else
            @escape << byte
            raise InvalidEscapeError.new(
              "invalid percent-escape #{@escape.inspect} at input offset #{@escape_offset}",
              @escape_offset, sequence: @escape.dup)
          end
        elsif byte == PERCENT
          @escape = "%".b
          @escape_offset = @offset
        elsif byte == PLUS && @mode == :form
          @pending << 0x20
          @pending_offsets << @offset
        else
          @pending << byte
          @pending_offsets << @offset
        end
        @offset += 1
      end
    end

    # Emits the longest prefix of @pending that forms complete characters
    # in the output encoding, keeping any incomplete trailing character.
    def drain
      return empty_output if @pending.empty?
      string = @pending.dup.force_encoding(@encoding)
      return take(string.bytesize) if string.valid_encoding?
      converter = new_boundary_converter
      return empty_output unless converter # encoding cannot be introspected; #finish will report the leftover
      source = @pending.dup.force_encoding(@encoding)
      result = converter.primitive_convert(source, +"", nil, nil, 0)
      _result, _source_encoding, _destination_encoding, error_bytes, readagain_bytes =
        converter.primitive_errinfo
      case result
      when :incomplete_input
        take(string.bytesize - error_bytes.bytesize)
      when :invalid_byte_sequence
        position = string.bytesize - error_bytes.bytesize -
                   readagain_bytes.bytesize - source.bytesize
        raise InvalidByteSequenceError.new(
          "invalid byte sequence #{error_bytes.inspect} in #{@encoding.name} " +          "at input offset #{@pending_offsets[position]}",
          @pending_offsets[position], bytes: error_bytes)
      else
        take(string.bytesize)
      end
    end

    # Moves the first +count+ pending bytes to the output.
    def take(count)
      output = @pending.byteslice(0, count).force_encoding(@encoding)
      @pending = @pending.byteslice(count, @pending.bytesize - count) || +"".b
      @pending_offsets.shift(count)
      output
    end

    def empty_output
      (+"").force_encoding(@encoding)
    end

    # A converter used only to locate character boundaries and invalid
    # bytes; its converted output is discarded.
    def new_boundary_converter
      target = @encoding == Encoding::UTF_8 ? Encoding::UTF_16LE : Encoding::UTF_8
      Encoding::Converter.new(@encoding, target)
    rescue Encoding::ConverterNotFoundError
      nil
    end
  end
end
