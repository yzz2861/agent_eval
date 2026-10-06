module MessagePack
  class ExtensionPayloadReader
    def read(length = nil, outbuf = nil)
      raise IOError, "extension payload reader is closed" if send(:"__closed?__")

      if outbuf
        unless outbuf.respond_to?(:replace)
          raise TypeError, "no implicit conversion of #{outbuf.class} into String"
        end
      end

      if length.nil?
        chunks = []
        remaining = send(:__remaining__)
        until remaining.zero?
          chunks << readpartial(remaining)
          remaining = send(:__remaining__)
        end
        result = chunks.empty? ? "".b : chunks.join
      else
        length = length.to_int
        raise ArgumentError, "negative string size (or size too big)" if length < 0
        return "".b if length.zero?
        remaining = send(:__remaining__)
        result = readpartial(length < remaining ? length : remaining)
      end

      if outbuf
        outbuf.replace(result)
        outbuf
      else
        result
      end
    end

    def readpartial(length, outbuf = nil)
      raise IOError, "extension payload reader is closed" if send(:"__closed?__")

      length = length.to_int
      raise ArgumentError, "negative string size (or size too big)" if length < 0
      raise EOFError, "end of extension payload reached" if send(:__remaining__).zero?

      chunk = send(:__read_available__, length)
      if send(:"__pending?__")
        Fiber.yield(true)
        chunk = send(:__read_available__, length) while send(:"__pending?__")
      end

      raise EOFError, "end of extension payload reached" if chunk.nil?

      if outbuf
        raise TypeError, "no implicit conversion of #{outbuf.class} into String" unless outbuf.respond_to?(:replace)
        outbuf.replace(chunk)
        outbuf
      else
        chunk
      end
    end

    def eof?
      send(:"__closed?__") || send(:__remaining__).zero?
    end
    alias eof eof?

    def close
      send(:__close__) unless send(:"__closed?__")
      nil
    end

    def closed?
      send(:"__closed?__")
    end

    def __resume__
      fiber = @fiber
      if fiber.nil?
        fiber = Fiber.new do
          decoder = send(:__decoder__)
          decoder.call(self)
        end
        @fiber = fiber
      end

      fiber.resume
    end
  end
end
