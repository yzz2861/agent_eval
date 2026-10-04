# frozen_string_literal: true

module Zip
  # SegmentedIO presents the numbered volumes of a split (multi-volume) zip
  # archive as a single, logically-addressed, read-only IO. Volumes are
  # supplied lazily by a Zip::VolumeProvider; see that class for the
  # provider contract and the owned/borrowed rules for the IOs it returns.
  #
  # The logical address space is the concatenation of all volumes in disk
  # order, so a logical offset of, say, 150 with 100-byte volumes means
  # offset 50 of disk 1. Zip metadata, however, addresses data as
  # (disk number, offset within that disk) pairs; use #logical_offset to
  # translate those into logical offsets before seeking.
  #
  # Reads and seeks behave like a normal IO and transparently cross volume
  # boundaries, so local headers, data descriptors, compressed data and the
  # central directory may all span volumes.
  class SegmentedIO
    CHUNK_SIZE = 32_768 # :nodoc:

    def initialize(provider) # :nodoc:
      @provider = provider
      @volumes  = {} # disk number => [io, owned?]
      @sizes    = {} # disk number => byte size (shared with dups)
      @pos      = 0
      @closed   = false
    end

    # A dup shares the provider (and its volume-size cache) but gets its
    # own cursor and its own set of volume handles, so owned volumes are
    # re-opened for the dup and closing one stream never closes the
    # handles of another.
    def initialize_copy(other)
      super
      raise IOError, 'closed stream' if other.closed?

      @volumes = {}
      @pos     = 0
      @closed  = false
    end

    # Translates a (disk number, offset within that disk) pair - as found in
    # zip metadata - into a logical offset suitable for #seek. Raises
    # MissingVolumeError if the disk is not supplied and VolumeOffsetError
    # if the offset lies outside the disk.
    def logical_offset(disk_number, offset)
      check_open!
      base = 0
      (0...disk_number).each do |disk|
        base += required_size(disk)
      end
      size = required_size(disk_number)
      if offset.negative? || offset > size
        raise ::Zip::VolumeOffsetError.new(offset, size, disk_number)
      end

      base + offset
    end

    def seek(amount, whence = ::IO::SEEK_SET) # :nodoc:
      check_open!
      target =
        case whence
        when ::IO::SEEK_SET then amount
        when ::IO::SEEK_CUR then @pos + amount
        when ::IO::SEEK_END then size + amount
        else raise ArgumentError, "unknown seek whence: #{whence}"
        end
      raise Errno::EINVAL, 'Invalid argument' if target.negative?
      raise ::Zip::VolumeOffsetError.new(target, size) if target > size

      @pos = target
      0
    end

    # The current logical offset.
    def tell
      @pos
    end
    alias pos tell

    def pos=(new_pos) # :nodoc:
      seek(new_pos, ::IO::SEEK_SET)
    end

    def rewind # :nodoc:
      seek(0, ::IO::SEEK_SET)
    end

    # Reads across volume boundaries, following IO#read semantics: with no
    # argument reads to the end of the archive; with a length, returns up to
    # that many bytes (nil if already at the end).
    def read(length = nil, outbuf = nil)
      check_open!
      data =
        if length.nil?
          read_all
        else
          raise ArgumentError, 'negative length' if length.negative?

          read_partial(length)
        end
      data = +''.b if data.nil? && length.nil?

      if outbuf
        outbuf.replace(data || '')
        data.nil? ? nil : outbuf
      else
        data
      end
    end

    def eof? # :nodoc:
      check_open!
      @pos >= size
    end
    alias eof eof?

    # The total logical size of the archive: the sum of all volume sizes.
    def size
      check_open!
      total_size
    end

    def binmode # :nodoc:
      self
    end

    # Closes every owned volume handle this stream is holding. Borrowed
    # volumes are left open, as they belong to the caller.
    def close
      return if @closed

      @volumes.each_value { |(io, owned)| io.close if owned }
      @volumes.clear
      @closed = true
      nil
    end

    def closed? # :nodoc:
      @closed
    end

    private

    def check_open!
      raise IOError, 'closed stream' if @closed
    end

    def read_all
      buffer = +''.b
      while (chunk = read_partial(CHUNK_SIZE))
        buffer << chunk
      end
      buffer
    end

    def read_partial(length)
      return nil if length.positive? && @pos >= total_size
      return +''.b if length.zero?

      buffer = +''.b
      while buffer.bytesize < length
        disk, disk_offset = locate(@pos)
        remaining_in_disk = @sizes[disk] - disk_offset
        break if remaining_in_disk <= 0 && !advance_disk?(disk)

        next if remaining_in_disk <= 0

        io, = fetch_volume(disk)
        io.seek(disk_offset, ::IO::SEEK_SET)
        chunk = io.read([length - buffer.bytesize, remaining_in_disk].min)
        break if chunk.nil? || chunk.empty?

        buffer << chunk
        @pos += chunk.bytesize
      end
      buffer.empty? ? nil : buffer
    end

    # Moves the cursor to the start of the disk after +disk+. Returns false
    # if there is no such volume (end of archive).
    def advance_disk?(disk)
      size = fetch_size(disk + 1)
      return false if size.nil?

      @pos = (0..disk).sum { |d| @sizes[d] }
      true
    end

    # Returns [disk_number, offset_within_disk] for a logical position.
    def locate(pos)
      base = 0
      disk = 0
      loop do
        size = fetch_size(disk)
        return [disk - 1, @sizes[disk - 1]] if size.nil?
        return [disk, pos - base] if pos < base + size

        base += size
        disk += 1
      end
    end

    def total_size
      last = @provider.last_disk_number
      return (0..last).sum { |disk| required_size(disk) } if last

      total = 0
      disk = 0
      while (size = fetch_size(disk))
        total += size
        disk += 1
      end
      total
    end

    def required_size(disk)
      fetch_size(disk) || raise(::Zip::MissingVolumeError, disk)
    end

    def fetch_size(disk)
      return @sizes[disk] if @sizes.key?(disk)

      volume = fetch_volume(disk)
      return handle_missing_size(disk) if volume.nil?

      io, = volume
      @sizes[disk] = measure(io)
    end

    def handle_missing_size(disk)
      last = @provider.last_disk_number
      raise ::Zip::MissingVolumeError, disk if disk.zero? || (last && disk <= last)

      nil
    end

    def measure(io)
      return io.size if io.respond_to?(:size)

      saved = io.pos
      io.seek(0, ::IO::SEEK_END)
      io.tell
    ensure
      io.seek(saved, ::IO::SEEK_SET) if saved
    end

    # Returns [io, owned?] for a disk, or nil if the provider does not
    # supply it. Raises DuplicateVolumeError if the provider hands out the
    # same IO object for two different disks.
    def fetch_volume(disk)
      return @volumes[disk] if @volumes.key?(disk)

      raw = @provider.volume(disk)
      return nil if raw.nil?

      volume = if raw.kind_of?(::Zip::VolumeProvider::Volume)
                 raw
               else
                 ::Zip::VolumeProvider.borrowed(raw)
               end
      check_duplicate!(disk, volume.io)
      @volumes[disk] = [volume.io, volume.owned?]
    end

    def check_duplicate!(disk, io)
      @volumes.each do |other_disk, (other_io, _)|
        next unless other_disk != disk && other_io.equal?(io)

        raise ::Zip::DuplicateVolumeError.new(disk, other_disk)
      end
    end
  end
end
