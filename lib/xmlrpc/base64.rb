# frozen_string_literal: false
#
# xmlrpc/base64.rb
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# Released under the same term of license as Ruby.

module XMLRPC # :nodoc:

# This class is necessary for 'xmlrpc4r' to determine that a string should
# be transmitted base64-encoded and not as a raw-string.
#
# You can use XMLRPC::Base64 on the client and server-side as a
# parameter and/or return-value.
class Base64
  include Comparable

  # Line width used by Base64.encode (pack("m")): 60 encoded chars.
  ENCODE_LINE_WIDTH = 60

  # Default number of bytes read from a streaming source at a time.
  DEFAULT_READ_SIZE  = 4096

  # Default maximum number of decoded bytes written to a sink at a time.
  DEFAULT_WRITE_SIZE = 4096

  # Raised by a streaming decoder when the received base64 data is not
  # well-formed (bad character, dangling quantum or broken padding).
  class FormatError < ArgumentError; end

  # Creates a new XMLRPC::Base64 instance with string +str+ as the
  # internal string. When +state+ is +:dec+ it assumes that the
  # string +str+ is not in base64 format (perhaps already decoded),
  # otherwise if +state+ is +:enc+ it decodes +str+
  # and stores it as the internal string.
  def initialize(str, state = :dec)
    case state
    when :enc
      @str = Base64.decode(str)
    when :dec
      @str = str
    else
      raise ArgumentError, "wrong argument; either :enc or :dec"
    end
  end

  # Returns the decoded internal string.
  def decoded
    @str
  end

  # Returns the base64 encoded internal string.
  def encoded
    Base64.encode(@str)
  end

  # Compare two base64 values, based on decoded string
  def <=>(other)
    return nil unless other.is_a?(self.class)
    decoded <=> other.decoded
  end

  # Decodes string +str+ with base64 and returns that value.
  def Base64.decode(str)
    str.gsub(/\s+/, "").unpack("m")[0]
  end

  # Encodes string +str+ with base64 and returns that value.
  def Base64.encode(str)
    [str].pack("m")
  end

  # Wraps a readable IO object so that it is transmitted as a streamed
  # <code><base64></code> value, without building the whole encoded
  # document in memory.
  #
  # The IO must respond to <code>read(length)</code>. At most
  # +read_size+ bytes are read per call, and the 0-2 trailing bytes that
  # do not fill a 3-byte base64 triple are retained and joined with the
  # next read.
  #
  # By default the IO keeps its ownership with the caller and is *not*
  # closed. Pass <code>close: true</code> to transfer ownership: the IO
  # is then closed exactly once when encoding finishes, and also when the
  # consumer raises or stops early.
  def Base64.stream(io, close: false, read_size: DEFAULT_READ_SIZE)
    Stream.new(io, close: close, read_size: read_size)
  end

  # Wraps a writable IO (a _sink_) that selected decoded
  # <code><base64></code> values are streamed into.
  #
  # The IO must respond to <code>write(str)</code>. At most +write_size+
  # decoded bytes are written per call.
  #
  # By default the IO keeps its ownership with the caller and is *not*
  # closed. Pass <code>close: true</code> to transfer ownership: the IO
  # is then closed exactly once after the enclosing document has been
  # parsed, and also when parsing is aborted (malformed data, a failing
  # write or cancellation).
  def Base64.sink(io, close: false, write_size: DEFAULT_WRITE_SIZE)
    Sink.new(io, close: close, write_size: write_size)
  end

  # See Base64.stream.
  class Stream
    attr_reader :io

    def initialize(io, close: false, read_size: Base64::DEFAULT_READ_SIZE)
      unless io.respond_to?(:read)
        raise ArgumentError, "base64 stream source must respond to #read"
      end
      unless read_size.is_a?(Integer) && read_size > 0
        raise ArgumentError, "read_size must be a positive Integer"
      end
      @io = io
      @close = close
      @read_size = read_size
      @closed = false
    end

    # Whether this wrapper owns (and will close) its IO.
    def close?
      @close
    end

    # Whether the IO has already been closed through this wrapper.
    def closed?
      @closed
    end

    # Yields the base64-encoded content as chunks (complete 60-character
    # lines plus the final line), byte-identical to Base64.encode of the
    # full decoded content. Returns an Enumerator when no block is given.
    def each_chunk
      return enum_for(:each_chunk) unless block_given?

      leftover = String.new(encoding: Encoding::BINARY)
      line     = String.new(encoding: Encoding::BINARY)

      begin
        loop do
          chunk = @io.read(@read_size)
          break if chunk.nil? || chunk.empty?

          leftover << chunk.b
          usable = (leftover.bytesize / 3) * 3
          next if usable == 0

          feed_line(line, [leftover.byteslice(0, usable)].pack("m0")) do |piece|
            yield piece
          end
          leftover = leftover.byteslice(usable, leftover.bytesize - usable)
        end

        if leftover.bytesize > 0
          feed_line(line, [leftover].pack("m0")) do |piece|
            yield piece
          end
        end
        yield line.dup << "\n" unless line.empty?
      ensure
        close! if @close
      end
      nil
    end

    # Returns the full base64-encoded content (buffered). Useful when a
    # streamed value ends up on a non-streaming code path.
    def encoded
      buffer = String.new(encoding: Encoding::BINARY)
      each_chunk { |piece| buffer << piece }
      buffer
    end

    # Closes the wrapped IO if this wrapper owns it. Safe to call more
    # than once.
    def close!
      return if @closed
      @closed = true
      @io.close if @close
    end

    private

    def feed_line(line, encoded)
      line << encoded
      while line.bytesize >= Base64::ENCODE_LINE_WIDTH
        yield line.byteslice(0, Base64::ENCODE_LINE_WIDTH) << "\n"
        line.slice!(0, Base64::ENCODE_LINE_WIDTH)
      end
    end
  end

  # See Base64.sink.
  class Sink
    attr_reader :io, :write_size

    def initialize(io, close: false, write_size: Base64::DEFAULT_WRITE_SIZE)
      unless io.respond_to?(:write)
        raise ArgumentError, "base64 sink must respond to #write"
      end
      unless write_size.is_a?(Integer) && write_size > 0
        raise ArgumentError, "write_size must be a positive Integer"
      end
      @io = io
      @close = close
      @write_size = write_size
      @closed = false
    end

    # Whether this wrapper owns (and will close) its IO.
    def close?
      @close
    end

    # Whether the IO has already been closed through this wrapper.
    def closed?
      @closed
    end

    # Closes the wrapped IO if this wrapper owns it. Safe to call more
    # than once.
    def close
      return if @closed
      @closed = true
      @io.close if @close
    end
  end

  # Streaming, strict base64 decoder. State (the unfinished 4-character
  # quantum and padding) is kept across calls, so arbitrarily split XML
  # text events decode identically to one contiguous string.
  #
  # Only bytes belonging to fully decoded groups are ever written to the
  # sink; any malformed input raises FormatError and stops decoding.
  class StrictDecoder
    WHITESPACE = [9, 10, 13, 32].freeze
    PADDING    = "=".ord

    VALUES = Array.new(256)
    ("A".."Z").each_with_index { |c, i| VALUES[c.ord] = i }
    ("a".."z").each_with_index { |c, i| VALUES[c.ord] = i + 26 }
    ("0".."9").each_with_index { |c, i| VALUES[c.ord] = i + 52 }
    VALUES["+".ord] = 62
    VALUES["/".ord] = 63

    def initialize(sink, write_size: Base64::DEFAULT_WRITE_SIZE)
      @sink = sink
      @write_size = write_size
      @carry = String.new(encoding: Encoding::BINARY)
      @pending = String.new(encoding: Encoding::BINARY)
      @padding_pending = false # saw the first '=' of an "ab==" quantum
      @closed = false         # a padding quantum finished the value
    end

    # Feeds one (possibly partial) chunk of base64 text.
    def decode(text)
      text.each_byte do |byte|
        next if WHITESPACE.include?(byte)
        raise FormatError, "unexpected character after base64 padding" if @closed

        if byte == PADDING
          handle_padding
        else
          value = VALUES[byte]
          raise FormatError, "illegal character in base64 value" if value.nil?
          @carry << byte
          flush_quantum if @carry.bytesize == 4
        end
      end
      flush_pending(false)
      self
    end
    alias << decode

    # Validates the trailing quantum and flushes all buffered bytes.
    def finish
      if @padding_pending
        raise FormatError, "truncated base64 padding"
      end

      case @carry.bytesize
      when 0
      when 2 then emit_tail(1)
      when 3 then emit_tail(2)
      else raise FormatError, "truncated base64 quantum"
      end

      flush_pending(true)
      self
    end

    private

    def handle_padding
      if @padding_pending
        unless @carry.bytesize == 3
          raise FormatError, "misplaced base64 padding"
        end
        @padding_pending = false
        @carry << "="
        emit_quantum(2)
      else
        case @carry.bytesize
        when 2
          # Expect a second '=' to close this quantum.
          @carry << "="
          @padding_pending = true
        when 3
          @carry << "="
          emit_quantum(1)
        else
          raise FormatError, "misplaced base64 padding"
        end
      end
    end

    def flush_quantum
      emit_quantum(0)
    end

    # Decodes @carry (exactly 4 chars, with +skip+ trailing padding bytes)
    # and writes the resulting 1-3 bytes.
    def emit_quantum(skip)
      vals = @carry.bytes.map { |b| b == PADDING ? 0 : VALUES.fetch(b) }
      word = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
      packed = [word].pack("N")
      emit_bytes(packed.byteslice(1, 3 - skip)) unless skip == 3
      @carry = String.new(encoding: Encoding::BINARY)
      @closed = true if skip == 1 || skip == 2
    end

    # Decodes an unpadded 2- or 3-char tail.
    def emit_tail(length)
      vals = @carry.bytes.map { |b| VALUES.fetch(b) }
      bytes = [(vals[0] << 2) | (vals[1] >> 4)]
      bytes << (((vals[1] & 0x0f) << 4) | (vals[2] >> 2)) if length == 2
      emit_bytes(bytes.pack("C*"))
    end

    def emit_bytes(str)
      @pending << str.b
    end

    def flush_pending(final)
      if final
        until @pending.empty?
          piece = @pending.byteslice(0, @write_size)
          rest = @pending.byteslice(@write_size, @pending.bytesize - @write_size)
          @pending = rest || String.new(encoding: Encoding::BINARY)
          write_all(piece)
        end
      else
        while @pending.bytesize > @write_size
          piece = @pending.byteslice(0, @write_size)
          @pending = @pending.byteslice(@write_size, @pending.bytesize - @write_size)
          write_all(piece)
        end
      end
    end

    def write_all(chunk)
      offset = 0
      while offset < chunk.bytesize
        written = @sink.write(chunk.byteslice(offset, chunk.bytesize - offset).b)
        unless written.is_a?(Integer) && written > 0
          raise "base64 sink write returned #{written.inspect}"
        end
        offset += written
      end
    end
  end

end


end # module XMLRPC


=begin
= History
    $Id$
=end
