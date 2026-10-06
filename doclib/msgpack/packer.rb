module MessagePack

  #
  # MessagePack::Packer is a class to serialize objects.
  #
  class Packer
    #
    # Creates a MessagePack::Packer instance.
    # See Buffer#initialize for supported options.
    #
    # @overload initialize(options={})
    #   @param options [Hash]
    #
    # @overload initialize(io, options={})
    #   @param io [IO]
    #   @param options [Hash]
    #   This packer writes serialized objects into the IO when the internal buffer is filled.
    #   _io_ must respond to write(string) or append(string) method.
    #
    # Supported options:
    #
    # * *:compatibility_mode* serialize in older versions way, without str8 and bin types
    # * *:collection_buffer_size* maximum number of bytes temporarily buffered for a streaming
    #   collection written to a non-positionable IO (default 1 MiB, minimum 5 bytes)
    #
    # See also Buffer#initialize for other options.
    #
    def initialize(*args)
    end

    #
    # Register a new ext type to serialize it. This method should be called with one of
    # method name or block, which returns bytes(ASCII-8BIT String) representation of
    # object to be serialized.
    #
    # @overload register_type(type, klass, &block)
    #   @param type [Fixnum] type id (0-127) user defined type id for specified Class
    #   @param klass [Class] Class to be serialized with specified type id
    #   @yieldparam object [Object] object to be serialized
    #
    # @overload register_type(type, klass, method_name)
    #   @param type [Fixnum] type id (0-127) user defined type id for specified Class
    #   @param klass [Class] Class to be serialized with specified type id
    #   @param method_name [Symbol] method which returns bytes of serialized representation
    #
    # @return nil
    #
    def register_type(type, klass, method_name, &block)
    end

    #
    # Returns a list of registered types, ordered by type id.
    # Each element is a Hash object includes keys :type, :class and :packer.
    #
    # @return Array
    #
    def registered_types
    end

    #
    # Returns true/false which indicate specified class or type id is registered or not.
    #
    # @param klass_or_type [Class or Fixnum] Class or type id (0-127) to be checked
    # @return true or false
    #
    def type_registered?(klass_or_type)
    end

    #
    # Internal buffer
    #
    # @return MessagePack::Buffer
    #
    attr_reader :buffer

    #
    # Serializes an object into internal buffer, and flushes to io if necessary.
    #
    # If it could not serialize the object, it raises
    # NoMethodError: undefined method `to_msgpack' for #<the_object>.
    #
    # @param obj [Object] object to serialize
    # @return [Packer] self
    #
    def write(obj)
    end

    alias pack write

    #
    # Serializes an Array immediately, or starts a streaming array.
    #
    # With no argument and a block, yields a collection writer. A positionable IO
    # (responding to +seek+, +pos+, and +truncate+) receives a 5-byte placeholder and
    # only the header is rewritten when the collection is closed. Other outputs buffer
    # serialized bytes up to the collection buffer limit and write nothing until the
    # whole collection is valid.
    #
    # An Enumerator is consumed once and streamed. This avoids materializing the array
    # or iterating it twice to count its length.
    #
    # @param values [Array, Enumerator, nil]
    # @param buffer_size [Integer, nil] per-call override for non-positionable IO
    # @return [Packer, CollectionWriter] packer for block/enumerator form, writer when no block is given
    #
    def write_array(values = nil, buffer_size: nil)
    end

    #
    # Serializes a Hash immediately, or starts a streaming map.
    #
    # The Enumerator form accepts either [key, value] pairs or key/value yielded by
    # methods such as Hash#each_pair. The block form yields a collection writer on which
    # keys and values alternate.
    #
    # @param pairs [Hash, Enumerator, nil]
    # @param buffer_size [Integer, nil] per-call override for non-positionable IO
    # @return [Packer, CollectionWriter] packer for block/enumerator form, writer when no block is given
    #
    def write_map(pairs = nil, buffer_size: nil)
    end

    #
    # Starts an array whose length is not known in advance. Call #write on the returned
    # writer for each element, then call #finish or #end_array.
    #
    # @param buffer_size [Integer, nil] temporary byte limit for non-positionable IO
    # @return [CollectionWriter]
    #
    def begin_array(buffer_size: nil)
    end
    alias start_array begin_array

    #
    # Starts a map whose length is not known in advance. Keys and values must alternate;
    # #add(key, value) is also available. Call #finish or #end_map when complete.
    #
    # @param buffer_size [Integer, nil] temporary byte limit for non-positionable IO
    # @return [CollectionWriter]
    #
    def begin_map(buffer_size: nil)
    end
    alias start_map begin_map

    #
    # Serializes a nil object. Same as write(nil).
    #
    def write_nil
    end

    #
    # Serializes a string object as binary data. Same as write("string".encode(Encoding::BINARY)).
    #
    def write_bin(obj)
    end

    #
    # Write a header of an array whose size is _n_.
    # For example, write_array_header(1).write(true) is same as write([ true ]).
    #
    # @return [Packer] self
    #
    def write_array_header(n)
    end

    #
    # Write a header of an map whose size is _n_.
    # For example, write_map_header(1).write('key').write(true) is same as write('key'=>true).
    #
    # @return [Packer] self
    #
    def write_map_header(n)
    end

    #
    # Write a header of a binary string whose size is _n_. Useful if you want to append large binary data without loading it into memory at once.
    # For example,
    # MessagePack::Packer.new(io).write_bin_header(12).flush
    # io.write('chunk1')
    # io.write('chunk2')
    # is the same as
    # write('chunk1chunk2'.encode(Encoding::BINARY)).
    #
    # @return [Packer] self
    #
    def write_bin_header(n)
    end

    #
    # Serializes _value_ as 32-bit single precision float into internal buffer.
    # _value_ will be approximated with the nearest possible single precision float, thus
    # being potentially lossy. However, the serialized string will only take up 5 bytes
    # instead of 9 bytes compared to directly serializing a 64-bit double precision Ruby Float.
    #
    # @param value [Numeric]
    # @return [Packer] self
    #
    def write_float32(value)
    end

    #
    # Flushes data in the internal buffer to the internal IO. Same as _buffer.flush.
    # If internal IO is not set, it does nothing.
    #
    # @return [Packer] self
    #
    def flush
    end

    #
    # Makes the internal buffer empty. Same as _buffer.clear_.
    #
    # @return nil
    #
    def reset
    end
    alias clear reset

    #
    # Returns size of the internal buffer. Same as buffer.size.
    #
    # @return [Integer]
    #
    def size
    end

    #
    # Returns _true_ if the internal buffer is empty. Same as buffer.empty?.
    # This method is slightly faster than _size_.
    #
    # @return [Boolean]
    #
    def empty?
    end

    #
    # Returns all data in the buffer as a string, and reset the buffer.
    #
    # @return [String]
    #
    def full_pack
    end

    #
    # Returns all data in the buffer as a string. Same as buffer.to_str.
    #
    # Does not empty the buffer, in most case _full_pack_ is prefered.
    #
    # @return [String]
    #
    def to_str
    end

    alias to_s to_str

    #
    # Returns content of the internal buffer as an array of strings. Same as buffer.to_a.
    # This method is faster than _to_str_.
    #
    # @return [Array] array of strings
    #
    def to_a
    end

    #
    # Writes all of data in the internal buffer into the given IO. Same as buffer.write_to(io).
    # This method consumes and removes data from the internal buffer.
    # _io_ must respond to write(data) method.
    #
    # @param io [IO]
    # @return [Integer] byte size of written data
    #
    def write_to(io)
    end
  end
end
