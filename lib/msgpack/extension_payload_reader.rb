# frozen_string_literal: true

module MessagePack
  class ExtensionPayloadReader
    WAIT = Object.new.freeze

    def initialize(unpacker, length)
      @unpacker = unpacker
      @remaining = length
      @closed = false
    end

    def read(length = nil, outbuf = nil)
      result =
        if length.nil?
          read_all
        else
          read_partial(length, false)
        end

      write_outbuf(outbuf, result)
      result
    end

    def readpartial(length, outbuf = nil)
      result = read_partial(length, true)
      write_outbuf(outbuf, result)
      result
    end

    alias read_nonblock readpartial

    def eof?
      @remaining.zero?
    end
    alias eof :eof?

    def closed?
      @closed
    end

    def close
      finish
      nil
    end

    def finish
      until @remaining.zero?
        consumed = skip_available(@remaining)
        if consumed.zero?
          Fiber.yield(WAIT)
        else
          @remaining -= consumed
        end
      end
      @closed = true
    end

    def discard_available
      while @remaining.positive?
        consumed = skip_available(@remaining)
        break if consumed.zero?
        @remaining -= consumed
      end
      @closed = true
    end

    private

    def read_all
      chunks = []
      while @remaining.positive?
        chunks << read_chunk(@remaining)
      end
      chunks.join
    end

    def read_partial(length, raise_on_eof)
      length = check_length(length)
      if @remaining.zero?
        raise EOFError, "end of extension payload reached"
      end
      return +"" if length.zero?

      read_chunk(@remaining < length ? @remaining : length)
    end

    def read_chunk(length)
      chunk = read_available(length)
      while chunk.nil?
        Fiber.yield(WAIT)
        chunk = read_available(length)
      end
      consume(chunk.bytesize)
      chunk
    end

    def consume(length)
      @remaining -= length
      if @unpacker.respond_to?(:consume_extension_payload, true)
        @unpacker.__send__(:consume_extension_payload, length)
      else
        @unpacker.__send__(:assert_extension_payload_length, length)
      end
    end

    def read_available(length)
      if @unpacker.respond_to?(:read_extension_payload_chunk, true)
        @unpacker.__send__(:read_extension_payload_chunk, length)
      else
        @unpacker.buffer.read(length)
      end
    end

    def skip_available(length)
      if @unpacker.respond_to?(:skip_extension_payload_chunk, true)
        @unpacker.__send__(:skip_extension_payload_chunk, length)
      else
        consumed = @unpacker.buffer.skip(length)
        @unpacker.__send__(:consume_extension_payload, consumed) if consumed.positive?
        consumed
      end
    end

    def check_length(length)
      length = Integer(length)
      raise ArgumentError, "negative string size (or size too big)" if length.negative?
      length
    rescue ArgumentError, TypeError
      raise TypeError, "no implicit conversion of #{length.class} into Integer"
    end

    def write_outbuf(outbuf, result)
      return if outbuf.nil?
      StringValue(outbuf)
      outbuf.replace(result || +"")
    end
  end
end
