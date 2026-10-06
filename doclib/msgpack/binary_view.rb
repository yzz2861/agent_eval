module MessagePack

  #
  # Read-only view of a binary value decoded by an Unpacker with binary_view: true.
  #
  # A view does not expose a mutable String. Its length is available immediately,
  # and its bytes can be read by range or written directly to an IO.
  #
  # On MRI, a payload contained in one String-backed input chunk shares that
  # chunk's storage and zero_copy? returns true. A payload split across feed
  # calls, or held in the unpacker's internal/IO buffer, is copied once into an
  # independent String and zero_copy? returns false. JRuby currently always uses
  # this copied fallback because its decoder copies incoming byte arrays.
  #
  # Views keep their storage alive independently. Feeding more data, resetting
  # the unpacker, running GC, compacting the heap, or replacing the original
  # input String does not change bytes already returned in a view.
  #
  class BinaryView
    #
    # @return [Integer] number of bytes in the view
    #
    def bytesize
    end

    #
    # Reads a byte range as another frozen BinaryView. Integer index without a
    # length returns a one-byte BinaryView, or nil outside the view.
    #
    # @return [BinaryView, nil]
    #
    def [](index, length = nil)
    end

    alias byteslice []
    alias slice []

    #
    # Yields each byte as an Integer.
    #
    # @return [BinaryView, Enumerator]
    #
    def each
    end

    #
    # Returns bytes as an Array of Integers.
    #
    # @return [Array<Integer>]
    #
    def bytes
    end

    #
    # Writes the represented bytes to io using io.write.
    #
    # @return [Integer]
    #
    def write_to(io)
    end

    #
    # Returns a mutable ASCII-8BIT String copy of the view.
    #
    # @return [String]
    #
    def to_s
    end

    #
    # @return [Boolean] true when this view shares one String-backed input chunk
    #
    def zero_copy?
    end
  end
end
