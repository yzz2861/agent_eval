# frozen_string_literal: true

module Zip
  # RangeIO presents a read-only, IO-like interface over any object that
  # can fetch arbitrary byte ranges — an object storage client, for
  # example. It allows Zip::File to read an archive directly from such a
  # source: the central directory is located by reading from the tail of
  # the object, and entry data is then fetched on demand, so opening a
  # large archive and reading a small entry from it does not download the
  # whole object.
  #
  # == The data source protocol
  #
  # A data source must respond to:
  #
  # +read_at(offset, length)+:: Returns a String of up to +length+ bytes
  #                             starting at +offset+. Fewer bytes than
  #                             requested may be returned (a short read);
  #                             RangeIO re-requests the remainder. An empty
  #                             response is taken to mean the end of the
  #                             data.
  # +version+::                 A stable identifier (an ETag, a generation
  #                             number, etc) for the version of the object
  #                             being read. It is checked around every
  #                             +read_at+ call: if it changes while the
  #                             archive is being read, SourceVersionError
  #                             is raised rather than splicing together
  #                             data from different versions of the object.
  #
  # A source may also respond to +size+, returning the total number of
  # bytes in the object. If it doesn't, the size is discovered lazily by
  # probing the source.
  #
  # == Example
  #
  #   source = MyObjectStorageClient.new(bucket, key) # responds to read_at, version, size
  #   Zip::File.open(source) do |zip|
  #     puts zip.read('README.md')
  #   end
  #
  # Small, adjacent reads are coalesced: data is fetched from the source
  # in blocks of +buffer_size+ bytes and subsequent reads are served from
  # the cached block where possible.
  class RangeIO
    # The default size of the read-ahead buffer, in bytes.
    DEFAULT_BUFFER_SIZE = 32_768

    # The wrapped data source.
    attr_reader :source

    def initialize(source, buffer_size: DEFAULT_BUFFER_SIZE)
      unless source.respond_to?(:read_at) && source.respond_to?(:version)
        raise ArgumentError,
              'a ranged data source must respond to #read_at and #version'
      end

      @source      = source
      @buffer_size = buffer_size
      @pos         = 0
      @closed      = false
      @size        = source.size if source.respond_to?(:size)
      @version     = nil # Captured from the source on the first fetch.
      @buffer      = +''.b
      @buffer_pos  = 0
    end

    # Reads bytes from the current position. With no +length+, reads to
    # the end of the source. With a +length+, reads up to that many bytes,
    # returning nil if the position is already at the end of the source.
    def read(length = nil, outbuf = nil)
      raise IOError, 'closed stream' if closed?

      check_version!

      raise ArgumentError, "negative length #{length} given" if length&.negative?

      data =
        if length.nil?
          fetch(@pos, remaining)
        elsif length.zero?
          +''.b
        elsif !eof?
          read_bytes([length, remaining].min)
        end

      @pos += data.bytesize if data
      if outbuf
        outbuf.replace(data.to_s)
        data ? outbuf : nil
      else
        data
      end
    end

    # Seeks to the given position, like IO#seek. Seeking to a negative
    # position raises Errno::EINVAL; seeking beyond the end of the source
    # is allowed.
    def seek(offset, whence = IO::SEEK_SET)
      raise IOError, 'closed stream' if closed?

      target =
        case whence
        when IO::SEEK_SET then offset
        when IO::SEEK_CUR then @pos + offset
        when IO::SEEK_END then size + offset
        else
          raise ArgumentError, "unknown seek whence: #{whence}"
        end

      raise Errno::EINVAL, 'seek to negative offset' if target.negative?

      @pos = target
      0
    end

    # The current read position.
    def tell
      @pos
    end
    alias pos tell

    def pos=(position)
      seek(position, IO::SEEK_SET)
      position
    end

    def rewind
      seek(0, IO::SEEK_SET)
    end

    # The total number of bytes in the source.
    def size
      @size ||= probe_size
    end

    def eof?
      @pos >= size
    end
    alias eof eof?

    def close
      @closed = true
      nil
    end

    def closed?
      @closed
    end

    def binmode
      self
    end

    private

    def remaining
      [size - @pos, 0].max
    end

    def read_bytes(length)
      if length >= @buffer_size
        fetch(@pos, length)
      else
        read_from_buffer(length)
      end
    end

    # Serves a small read from the cached block, refilling the block from
    # the source when the requested range isn't covered by it. Refills
    # always fetch a whole block, so runs of adjacent small reads are
    # merged into a single request to the source.
    def read_from_buffer(length)
      unless @buffer_pos <= @pos && @pos + length <= @buffer_pos + @buffer.bytesize
        @buffer = fetch(@pos, [@buffer_size, remaining].min)
        @buffer_pos = @pos
      end

      @buffer.byteslice(@pos - @buffer_pos, length)
    end

    # Fetches the given range from the source, re-requesting the remainder
    # if the source returns fewer bytes than asked for. Every request is
    # bracketed by version checks so that data from different versions of
    # the source is never spliced together.
    def fetch(offset, length)
      return +''.b if length <= 0

      data = +''.b
      while data.bytesize < length
        chunk = checked_read_at(offset + data.bytesize, length - data.bytesize)
        break if chunk.empty?

        data << chunk
      end
      data
    end

    def checked_read_at(offset, length)
      before = @source.version
      raise SourceVersionError if @version && before != @version

      chunk = @source.read_at(offset, length).to_s

      after = @source.version
      raise SourceVersionError if before != after

      @version = after
      chunk
    end

    # Cached data is only valid for the version of the source it was
    # fetched from, so the version is checked before any read — even one
    # that would be served from the cache.
    def check_version!
      return if @version.nil?

      raise SourceVersionError if @source.version != @version
    end

    # Discovers the size of the source by probing for the end of the data.
    # Only used when the source doesn't report its own size.
    def probe_size
      return 0 if fetch(0, 1).empty?

      lower = 0
      upper = @buffer_size
      until fetch(upper, 1).empty?
        lower = upper
        upper *= 2
      end

      while upper - lower > 1
        mid = (lower + upper) / 2
        if fetch(mid, 1).empty?
          upper = mid
        else
          lower = mid
        end
      end
      upper
    end
  end
end
