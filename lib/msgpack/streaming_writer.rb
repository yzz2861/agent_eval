require "tempfile"

module MessagePack
  class Packer
    # Opens a streaming array: elements are appended one by one and the
    # array header is finalized when the block returns. See StreamingWriter.
    #
    # Returns the number of elements written.
    def write_streaming_array(&block)
      StreamingWriter.start(self, :array, &block)
    end

    # Opens a streaming map: keys and values are appended one by one and the
    # map header is finalized when the block returns. The commit fails with
    # StreamingWriter::IncompleteMapError if a key is left without a value.
    #
    # Returns the number of pairs written.
    def write_streaming_map(&block)
      StreamingWriter.start(self, :map, &block)
    end
  end

  # StreamingWriter writes a MessagePack array or map whose size is not
  # known in advance, e.g. when elements come from a one-shot enumerator.
  # Elements are serialized and flushed as they are appended; they are never
  # retained as Ruby objects, so memory usage stays bounded regardless of
  # the collection size.
  #
  # Two strategies are used depending on the destination:
  #
  # * Seekable IO (responds to #pos/#seek, e.g. File, StringIO): a 5-byte
  #   array32/map32 header placeholder is reserved, elements are written
  #   directly, and the header is patched in place on commit. If the block
  #   raises, the IO is rewound (and truncated when possible) to the
  #   position it had before the collection started.
  # * Any other stream (pipes, sockets, or a packer without IO): elements
  #   are staged as serialized bytes in a temporary file (bounded memory),
  #   and on commit a minimal-width header followed by the staged bytes is
  #   appended to the destination. If the block raises, nothing is written
  #   to the destination at all.
  #
  # Note: a seekable IO opened in append mode (O_APPEND) cannot be patched
  # in place and must not be used as a streaming destination.
  class StreamingWriter
    class Error < StandardError; end
    # Raised on commit when a map has a key without its value.
    class IncompleteMapError < Error; end

    MAX_COUNT = 0xffffffff
    COPY_CHUNK_SIZE = 16 * 1024
    HEADER_PLACEHOLDER_SIZE = 5

    ARRAY32_PLACEHOLDER = [0xdd, 0].pack("CN").freeze
    MAP32_PLACEHOLDER = [0xdf, 0].pack("CN").freeze

    # Number of elements (array) or complete pairs (map) written so far.
    attr_reader :count

    def self.start(packer, type)
      raise ArgumentError, "block required" unless block_given?

      io = packer.buffer.io
      if io && seekable?(io)
        run_direct(packer, io, type) { |writer| yield writer }
      else
        run_staged(packer, type) { |writer| yield writer }
      end
    end

    def self.seekable?(io)
      return false unless io.respond_to?(:pos) && io.respond_to?(:seek)
      io.seek(io.pos, IO::SEEK_SET)
      true
    rescue IOError, SystemCallError
      false
    end

    # Writes the collection directly to a seekable IO, reserving a 32-bit
    # header that is patched with the final count on commit.
    def self.run_direct(packer, io, type)
      packer.flush
      start_pos = io.pos
      io.write(type == :map ? MAP32_PLACEHOLDER : ARRAY32_PLACEHOLDER)

      writer = new(packer, type)
      committed = false
      begin
        yield writer
        count = writer.finish
        packer.flush
        end_pos = io.pos
        io.seek(start_pos, IO::SEEK_SET)
        io.write(header32(type, count))
        io.seek(end_pos, IO::SEEK_SET)
        committed = true
        count
      ensure
        unless committed
          # Drop buffered elements of the aborted collection so a later
          # flush cannot rewrite them, then rewind the IO.
          packer.buffer.clear
          begin
            io.seek(start_pos, IO::SEEK_SET)
            io.truncate(start_pos) if io.respond_to?(:truncate)
          rescue IOError, SystemCallError
            # best effort rollback
          end
        end
      end
    end

    # Stages the collection in a temporary file (which is seekable, so the
    # direct strategy applies, including for nested collections), then
    # appends a minimal-width header and the staged bytes to the real
    # destination. The destination is left untouched if the block raises.
    def self.run_staged(packer, type)
      tmp = Tempfile.new(["msgpack-streaming", ".bin"])
      tmp.binmode
      begin
        child = MessagePack::Packer.new(tmp, compatibility_mode: packer.compatibility_mode?)
        packer.registered_types.each do |entry|
          child.register_type(entry[:type], entry[:class], &entry[:packer])
        end

        count = run_direct(child, tmp, type) { |writer| yield writer }

        if type == :map
          packer.write_map_header(count)
        else
          packer.write_array_header(count)
        end
        tmp.seek(HEADER_PLACEHOLDER_SIZE, IO::SEEK_SET)
        copy_staged(packer, tmp)
        count
      ensure
        tmp.close
        tmp.unlink
      end
    end

    def self.copy_staged(packer, src)
      if (io = packer.buffer.io)
        packer.flush
        IO.copy_stream(src, io)
      else
        while (chunk = src.read(COPY_CHUNK_SIZE))
          packer.buffer << chunk
        end
      end
    end

    def self.header32(type, count)
      [type == :map ? 0xdf : 0xdd, count].pack("CN")
    end

    def initialize(packer, type)
      @packer = packer
      @type = type
      @count = 0
      @pending_key = false
      @finished = false
    end

    # Appends one element (array) or one key/value slot (map). For maps,
    # alternate keys and values, or use #write_pair.
    def write(value)
      check_active
      @packer.write(value)
      advance
      self
    end
    alias :<< :write

    # Appends one key/value pair. Only valid for maps.
    def write_pair(key, value)
      check_active
      raise Error, "write_pair is only valid for maps" unless @type == :map
      raise Error, "previous key is still waiting for its value" if @pending_key
      @packer.write(key)
      @packer.write(value)
      @count += 1
      self
    end

    # Appends a nested streaming array as a single element/value.
    def write_streaming_array(&block)
      write_nested(:array, &block)
    end

    # Appends a nested streaming map as a single element/value.
    def write_streaming_map(&block)
      write_nested(:map, &block)
    end

    # Finalizes the collection. Raises IncompleteMapError if a map key is
    # left without a value.
    def finish
      check_active
      if @type == :map && @pending_key
        raise IncompleteMapError, "map has a key without a value"
      end
      @finished = true
      @count
    end

    private

    def write_nested(type)
      check_active
      StreamingWriter.start(@packer, type) { |writer| yield writer }
      advance
      self
    end

    def advance
      if @type == :map
        if @pending_key
          @pending_key = false
          @count += 1
        else
          @pending_key = true
        end
      else
        @count += 1
      end
      raise Error, "collection exceeds 2**32-1 elements" if @count > MAX_COUNT
    end

    def check_active
      raise Error, "collection is already finished" if @finished
    end
  end
end
