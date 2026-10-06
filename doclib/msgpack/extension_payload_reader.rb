module MessagePack
  class ExtensionPayloadReader
    # Read up to _length_ bytes from the current extension payload.
    # With no length argument, reads until the declared payload boundary.
    def read(length = nil, outbuf = nil)
    end

    # Read immediately available bytes, up to _length_. If no payload bytes
    # have been fed yet, the streaming decoder suspends and the Unpacker
    # reports EOFError until more data is supplied.
    def readpartial(length, outbuf = nil)
    end

    # Returns true when the reader reaches the current extension payload boundary.
    def eof?
    end

    # Marks the reader closed. The unpacker still aligns itself to the payload
    # boundary after the streaming decoder returns.
    def close
    end

    def closed?
    end
  end
end
