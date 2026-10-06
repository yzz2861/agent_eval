require "stringio"

module MessagePack
  class Packer
    # see ext for other methods

    alias_method :initialize_native, :initialize
    alias_method :write_array_without_stream, :write_array
    alias_method :write_map_without_stream, :write_hash

    DEFAULT_COLLECTION_BUFFER_SIZE = 1024 * 1024

    class CollectionBufferOverflowError < StandardError
    end

    class CappedStream
      def initialize(limit)
        unless limit.is_a?(Integer) && limit >= 5
          raise ArgumentError, "collection buffer size must be an Integer greater than or equal to 5"
        end

        @io = StringIO.new("".b)
        @limit = limit
      end

      attr_reader :limit

      def write(data)
        data = data.to_s
        projected_size = @io.pos + data.bytesize
        if projected_size > @limit && projected_size > @io.size
          raise CollectionBufferOverflowError, "collection exceeds buffered size limit of #{@limit} bytes"
        end

        @io.write(data)
      end

      def seek(amount, whence = IO::SEEK_SET)
        @io.seek(amount, whence)
      end

      def pos
        @io.pos
      end

      def truncate(length)
        if length > @limit
          raise CollectionBufferOverflowError, "collection exceeds buffered size limit of #{@limit} bytes"
        end

        @io.truncate(length)
      end

      def read(length = nil)
        @io.read(length)
      end

      def rewind
        @io.rewind
      end

      def size
        @io.size
      end

      def flush
        @io.flush
      end

      def binmode
        @io.binmode
      end

      def close
        @io.reopen("".b)
        @io.truncate(0)
      end
    end

    class CollectionWriter
      ARRAY = :array
      MAP = :map
      HEADER_SHIFT_CHUNK_SIZE = 16 * 1024

      attr_accessor :staged
      attr_reader :io
      attr_accessor :on_finish

      def initialize(packer, io, type, parent: nil, bounded: false, on_finish: nil)
        @packer = packer
        @io = io
        @type = type
        @parent = parent
        @bounded = bounded
        @on_finish = on_finish
        @items = 0
        @pairs = 0
        @pending_value = false
        @closed = false

        @packer.flush
        @start = @io.pos
        if @type == ARRAY
          @packer.write_array_header(0xffffffff)
        else
          @packer.write_map_header(0xffffffff)
        end
        @packer.flush
      end

      def write(value)
        ensure_open!
        @packer.write(value)
        note_value!
        enforce_buffer_limit!
        self
      end
      alias << write

      def add(key, value)
        ensure_open!
        unless @type == MAP
          raise ArgumentError, "add can only be called on a map collection"
        end

        write(key)
        write(value)
        self
      end
      alias put add
      alias write_pair add

      def write_array(enumerable = nil, &block)
        write_nested_collection(ARRAY, enumerable, block)
      end

      def write_map(pairs = nil, &block)
        write_nested_collection(MAP, pairs, block)
      end

      def begin_array
        build_nested_collection(ARRAY)
      end
      alias start_array begin_array

      def begin_map
        build_nested_collection(MAP)
      end
      alias start_map begin_map

      def finish
        ensure_open!
        if @type == MAP && @pending_value
          raise ArgumentError, "map collection is missing a value for its final key"
        end

        count = collection_count
        if count > 0xffffffff
          raise ArgumentError, "size of collection is too long to pack: #{count} should be <= #{0xffffffff}"
        end

        @packer.flush
        rewrite_header(count)
        @closed = true
        @parent&.note_child_collection!(@type)
        @on_finish&.call(self)
        self
      end

      def end_array
        unless @type == ARRAY
          raise ArgumentError, "cannot close a map with end_array"
        end

        finish
      end

      def end_map
        unless @type == MAP
          raise ArgumentError, "cannot close an array with end_map"
        end

        finish
      end

      def abort
        return self if @closed

        @packer.flush
        @io.truncate(@start)
        @io.seek(0, IO::SEEK_END)
        @closed = true
        self
      end

      def closed?
        @closed
      end

      def release_stage!
        return unless @staged

        @packer.reset
        @io.close
        @staged = false
      end

      protected
      def note_child_collection!(_type)
        note_value!
        enforce_buffer_limit!
      end

      private

      def write_nested_collection(type, enumerable, block)
        child = build_nested_collection(type)

        begin
          if block
            block.call(child)
          elsif enumerable
            if type == ARRAY
              enumerable.each { |value| child.write(value) }
            else
              enumerable.each do |*args|
              if args.length == 1
                pair = args[0]
                unless pair.is_a?(::Array) && pair.length == 2
                  raise ArgumentError, "map pair must contain a key and a value"
                end
                  child.add(pair[0], pair[1])
                elsif args.length == 2
                  child.add(args[0], args[1])
                else
                  raise ArgumentError, "map pair must contain a key and a value"
                end
              end
            end
          end
          child.finish
        rescue Exception
          child.abort unless child.closed?
          raise
        end

        self
      end

      def build_nested_collection(type)
        CollectionWriter.new(@packer, @io, type, parent: self, bounded: @bounded)
      end

      def note_value!
        if @type == ARRAY
          @items += 1
        elsif @pending_value
          @pairs += 1
          @pending_value = false
        else
          @pending_value = true
        end
      end

      def collection_count
        @type == ARRAY ? @items : @pairs
      end

      def enforce_buffer_limit!
        return unless @bounded

        @packer.flush
        if @io.size > @io.limit
          raise CollectionBufferOverflowError
        end
      end

      def ensure_open!
        raise IOError, "collection is already closed" if @closed
      end

      def rewrite_header(count)
        header = collection_header(count)
        old_end = @io.size

        if header.bytesize == 5 || !@io.respond_to?(:read)
          @io.seek(@start)
          @io.write(max_width_header(count))
          @io.seek(0, IO::SEEK_END)
          return
        end

        body_size = old_end - @start - 5
        source_position = @start + 5
        target_position = @start + header.bytesize

        while source_position < old_end
          @io.seek(source_position)
          chunk = @io.read(HEADER_SHIFT_CHUNK_SIZE)
          break if chunk.nil? || chunk.empty?

          @io.seek(target_position)
          @io.write(chunk)
          source_position += chunk.bytesize
          target_position += chunk.bytesize
        end

        @io.seek(@start)
        @io.write(header)
        @io.truncate(@start + header.bytesize + body_size)
        @io.seek(0, IO::SEEK_END)
      end

      def collection_header(count)
        if @type == ARRAY
          array_header(count)
        else
          map_header(count)
        end
      end

      def array_header(count)
        if count < 16
          [(0x90 | count)].pack("C")
        elsif count < 65536
          "\xDC".b + [count].pack("n")
        else
          "\xDD".b + [count].pack("N")
        end
      end

      def map_header(count)
        if count < 16
          [(0x80 | count)].pack("C")
        elsif count < 65536
          "\xDE".b + [count].pack("n")
        else
          "\xDF".b + [count].pack("N")
        end
      end

      def max_width_header(count)
        if @type == ARRAY
          "\xDD".b + [count].pack("N")
        else
          "\xDF".b + [count].pack("N")
        end
      end
    end

    def initialize(*args)
      options = args.last.is_a?(Hash) ? args.last : {}
      self.collection_buffer_size = options.fetch(:collection_buffer_size, DEFAULT_COLLECTION_BUFFER_SIZE)
      initialize_native(*args)
    end

    def write_array(enumerable = nil, buffer_size: nil)
      if block_given? || enumerable.nil?
        writer = begin_collection(ARRAY_KIND, buffer_size)
        return writer unless block_given?

        consume_collection(writer) { |collection| yield collection }
      elsif enumerable.is_a?(Enumerator)
        writer = begin_collection(ARRAY_KIND, buffer_size)
        consume_collection(writer) { |collection| enumerable.each { |value| collection.write(value) } }
      else
        write_array_without_stream(enumerable)
      end
    end

    def write_map(pairs = nil, buffer_size: nil)
      if block_given? || pairs.nil?
        writer = begin_collection(MAP_KIND, buffer_size)
        return writer unless block_given?

        consume_collection(writer) { |collection| yield collection }
      elsif pairs.is_a?(Enumerator)
        writer = begin_collection(MAP_KIND, buffer_size)
        consume_collection(writer) do |collection|
          pairs.each do |*args|
            if args.length == 1
              pair = args[0]
              unless pair.is_a?(::Array) && pair.length == 2
                raise ArgumentError, "map pair must contain a key and a value"
              end
              collection.add(pair[0], pair[1])
            elsif args.length == 2
              collection.add(args[0], args[1])
            else
              raise ArgumentError, "map pair must contain a key and a value"
            end
          end
        end
      else
        write_map_without_stream(pairs)
      end
    end

    def begin_array(buffer_size: nil)
      begin_collection(CollectionWriter::ARRAY, buffer_size)
    end
    alias start_array begin_array

    def begin_map(buffer_size: nil)
      begin_collection(CollectionWriter::MAP, buffer_size)
    end
    alias start_map begin_map

    ARRAY_KIND = CollectionWriter::ARRAY
    MAP_KIND = CollectionWriter::MAP

    def begin_collection(type, buffer_size)
      io = buffer.io
      if positionable_io?(io)
        CollectionWriter.new(self, io, type)
      else
        limit = buffer_size || @collection_buffer_size || DEFAULT_COLLECTION_BUFFER_SIZE
        capped_io = CappedStream.new(limit)
        stage_packer = build_stage_packer(capped_io)
        writer = CollectionWriter.new(stage_packer, capped_io, type, bounded: true)
        writer.staged = true
        writer.on_finish = method(:commit_staged_collection)
        writer
      end
    end

    def consume_collection(writer)
      begin
        yield writer
        writer.finish
      rescue Exception
        writer.abort unless writer.closed?
        raise
      ensure
        writer.release_stage! if writer.staged
      end

      self
    end

    def commit_staged_collection(writer)
      writer.io.rewind
      while chunk = writer.io.read(CollectionWriter::HEADER_SHIFT_CHUNK_SIZE)
        buffer.write(chunk)
      end
      flush
      writer.release_stage!
    end

    def build_stage_packer(io)
      stage_packer = self.class.new(
        io,
        compatibility_mode: compatibility_mode?,
        write_reference_threshold: 256,
        io_buffer_size: 1024
      )

      registered_types.each do |entry|
        next unless entry[:packer]
        stage_packer.register_type(entry[:type], entry[:class], entry[:packer])
      end

      stage_packer
    end

    def positionable_io?(io)
      io.respond_to?(:seek) && io.respond_to?(:pos) && io.respond_to?(:truncate)
    end
    def collection_buffer_size
      @collection_buffer_size || DEFAULT_COLLECTION_BUFFER_SIZE
    end
    def collection_buffer_size=(limit)
      unless limit.is_a?(Integer) && limit >= 5
        raise ArgumentError, "collection buffer size must be an Integer greater than or equal to 5"
      end

      @collection_buffer_size = limit
    end
    private :begin_collection, :consume_collection, :commit_staged_collection,
            :build_stage_packer, :positionable_io?, :collection_buffer_size=

    # The semantic of duping a packer is just too weird.
    undef_method :dup
    undef_method :clone

    def register_type(type, klass, method_name = nil, &block)
      raise ArgumentError, "expected Module/Class got: #{klass.inspect}" unless klass.is_a?(Module)
      register_type_internal(type, klass, block || method_name.to_proc)
    end

    def registered_types
      list = []

      registered_types_internal.each_pair do |klass, ary|
        list << {type: ary[0], class: klass, packer: ary[1]}
      end

      list.sort{|a, b| a[:type] <=> b[:type] }
    end

    def type_registered?(klass_or_type)
      case klass_or_type
      when Module
        klass = klass_or_type
        registered_types.any?{|entry| klass <= entry[:class] }
      when Integer
        type = klass_or_type
        registered_types.any?{|entry| type == entry[:type] }
      else
        raise ArgumentError, "class or type id"
      end
    end
  end
end
