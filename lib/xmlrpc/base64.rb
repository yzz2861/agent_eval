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

  READ_SIZE = 4
  BYTES_PER_LINE = 45

  # A readable IO object whose content should be sent as a base64 value.
  #
  # The IO is not closed unless +close+ is true. Callers retain ownership of
  # objects passed directly to XML-RPC methods. A readable IO may also be
  # passed directly; wrapping it with +close: true+ transfers ownership.
  class Stream
    attr_reader :io

    def initialize(io, close: false)
      unless io.respond_to?(:read)
        raise ArgumentError, "base64 stream must respond to #read"
      end
      @io = io
      @close = close
      @closed = false
    end

    def owned?
      @close
    end

    def size
      @io.size if @io.respond_to?(:size)
    end

    def close
      return if @closed
      @closed = true
      @io.close if @close && @io.respond_to?(:close) && !@io.closed?
    end
  end

  # A writable IO object that receives a decoded response base64 value.
  #
  # The IO is not closed unless +close+ is true. Plain IO objects passed by
  # callers remain owned by the caller. Complete base64 quanta are decoded and
  # written while XML is being parsed, but malformed values stop parsing.
  class Sink
    attr_reader :io

    def initialize(io, close: false)
      unless io.respond_to?(:write)
        raise ArgumentError, "base64 sink must respond to #write"
      end
      @io = io
      @close = close
      @closed = false
    end

    def close
      return if @closed
      @closed = true
      @io.close if @close && @io.respond_to?(:close) && !@io.closed?
    end
  end

  class StreamEncoder # :nodoc: all
    def initialize(stream)
      @stream = stream
      @io = stream.io
      @carry = String.new
      @carry.force_encoding(Encoding::BINARY)
      @raw_line = String.new
      @raw_line.force_encoding(Encoding::BINARY)
      @output = String.new
      @output.force_encoding(Encoding::BINARY)
      @finished = false
    end

    def encoded_size
      size = @stream.size
      return nil if size.nil?
      4 * ((size + 2) / 3) + (size + BYTES_PER_LINE - 1) / BYTES_PER_LINE
    end

    def read(length = nil, outbuf = nil)
      result = outbuf || String.new
      result.force_encoding(Encoding::BINARY)
      result.clear

      while result.empty?
        while @output.empty? && !@finished
          fill
        end
        break if @output.empty?

        chunk = @output.dup
        chunk = chunk.byteslice(0, length) if length
        result << chunk
        consume_binary(@output, chunk.bytesize)
      end

      if result.empty?
        outbuf.replace(result) if outbuf
        @stream.close if @finished
        return nil
      end

      outbuf.replace(result) if outbuf
      result
    end

    def close
      @stream.close
    end

    def owned_input?
      @stream.owned?
    end

    private

    def fill
      chunk = @io.read(READ_SIZE)
      if chunk && !chunk.empty?
        @carry << chunk.to_s
        while @raw_line.bytesize < BYTES_PER_LINE
          remaining = BYTES_PER_LINE - @raw_line.bytesize
          take = [@carry.bytesize, remaining].min
          break if take.zero?
          @raw_line << consume_binary(@carry, take)
          emit_line if @raw_line.bytesize == BYTES_PER_LINE
        end
        return
      end

      @finished = true
      if @raw_line.bytesize > 0 || @carry.bytesize > 0
        @raw_line << @carry
        @carry.clear
        emit(@raw_line.bytesize)
      end
      @output << "\n" if !@output.empty? && @output.getbyte(-1) != "\n".ord
    end

    def emit(size)
      chunk = consume_binary(@raw_line, size)
      @output << [chunk].pack("m0")
      @output << "\n"
      @raw_line.clear
    end

    def emit_line
      emit(@raw_line.bytesize)
    end

    def consume_binary(buffer, size)
      chunk = buffer.byteslice(0, size)
      remainder = buffer.byteslice(size, buffer.bytesize - size)
      buffer.replace(remainder || String.new)
      chunk
    end
  end

  class StreamDecoder # :nodoc: all
    BASE64_CHAR = "A-Za-z0-9+/"
    WHITESPACE = /\s+/
    VALID_QUANTUM = /\A(?:[#{BASE64_CHAR}]{4}|[#{BASE64_CHAR}]{3}=|[#{BASE64_CHAR}]{2}==)\z/

    def initialize(sink)
      @sink = sink
      @buffer = String.new
      @buffer.force_encoding(Encoding::BINARY)
      @padded = false
    end

    def <<(data)
      cleaned = data.to_s.gsub(WHITESPACE, "")
      return self if cleaned.empty?
      @buffer << cleaned
      process until @buffer.bytesize < 4
      self
    end

    def finish
      unless @buffer.empty?
        begin
          raise "RPC-value of type base64 is wrong"
        ensure
          @sink.close
        end
      end
      @sink.close
    end

    def close
      @sink.close
    end

    private

    def process
      quantum = consume_binary(@buffer, 4)
      if @padded || quantum !~ VALID_QUANTUM
        begin
          raise "RPC-value of type base64 is wrong"
        ensure
          @sink.close
        end
      end

      if quantum.include?("=")
        @padded = true
        write(quantum.unpack("m0").first)
      else
        write(quantum.unpack("m0").first)
      end
    end

    def write(data)
      until data.empty?
        written = @sink.io.write(data)
        raise "RPC-value of type base64 sink write failed" unless written.is_a?(Integer) && written > 0
        data = data.byteslice(written, data.bytesize - written) || String.new
      end
    end

    def consume_binary(buffer, size)
      chunk = buffer.byteslice(0, size)
      remainder = buffer.byteslice(size, buffer.bytesize - size)
      buffer.replace(remainder || String.new)
      chunk
    end
  end

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

end


end # module XMLRPC


=begin
= History
    $Id$
=end
