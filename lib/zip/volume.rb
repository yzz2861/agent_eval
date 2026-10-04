# frozen_string_literal: true

module Zip
  # Provides access to the individual disks of a multi-volume archive.
  #
  # The block receives a zero-based disk number and must return an opened,
  # binary IO object for that disk. IOs returned this way are owned by the
  # archive reader and will be closed when they are no longer needed.
  #
  # Use VolumeProvider.borrow when reusing IOs that are owned by the caller.
  # Those IOs are not closed; internally duplicated handles are closed instead.
  class VolumeProvider
    attr_reader :volume_count

    def initialize(volume_count = nil, &open_volume)
      unless block_given?
        raise ArgumentError, 'a block opening a volume by disk number is required'
      end

      @volume_count = volume_count
      @open_volume = open_volume
    end

    def self.borrow(volumes)
      volumes = validate_borrowed_volumes(volumes)
      new(volumes.length) do |disk_number|
        volumes.fetch(disk_number).dup
      end
    end

    def self.validate_borrowed_volumes(volumes)
      unless volumes.respond_to?(:[]) && volumes.respond_to?(:length)
        raise ArgumentError, 'borrowed volumes must be indexed by zero-based disk number'
      end

      Array.new(volumes.length) do |disk_number|
        io = volumes[disk_number]
        raise MissingVolumeError, disk_number if io.nil?
        unless io.respond_to?(:seek) && io.respond_to?(:read) && io.respond_to?(:close)
          raise ArgumentError, "volume #{disk_number} must be an IO-like object"
        end

        io
      end
    end

    def open_multi_volume_io(disk_number = 0, offset = 0)
      MultiVolumeIO.new(self, disk_number, offset)
    end

    alias open_io open_multi_volume_io

    def volume_provider?
      true
    end

    def open(disk_number)
      validate_disk_number(disk_number) unless @volume_count.nil?
      io = @open_volume.call(disk_number)
      raise MissingVolumeError, disk_number if io.nil?
      unless io.respond_to?(:seek) && io.respond_to?(:read) && io.respond_to?(:close)
        raise Error, "volume provider returned an invalid IO for disk #{disk_number}"
      end

      io
    rescue Errno::ENOENT
      raise MissingVolumeError, disk_number
    end

    private

    def validate_disk_number(disk_number)
      return if disk_number.is_a?(Integer) && disk_number >= 0 && disk_number < @volume_count

      raise VolumeOffsetError.new(disk_number, 0)
    end
  end

  # Presents the disks of a multi-volume archive as one seekable IO. Positions
  # are still represented by MultiVolumeIO::Position so offsets remain relative
  # to the disk that contains them.
  class MultiVolumeIO
    Position = Struct.new(:disk, :offset) do
      def to_a
        [disk, offset]
      end
    end

    Volume = Struct.new(:io, :logical_size, :base, :path)

    def initialize(provider, disk_number = 0, offset = 0)
      @provider = provider
      @volumes = {}
      @disk = disk_number
      @offset = offset
      validate_volumes
      seek_to(disk_number, offset)
    end

    def volume_provider?
      false
    end

    def multi_volume?
      true
    end

    def volume_count
      @provider.volume_count || discover_volume_count
    end

    def volume_size(disk_number)
      volume(disk_number).logical_size
    end

    def position
      Position.new(@disk, @offset)
    end

    alias tell position

    def seek_to(disk_number, offset)
      validate_disk_number(disk_number)
      volume = volume(disk_number)
      validate_offset(disk_number, offset, volume.logical_size)
      io_seek(volume, offset)
      @disk = disk_number
      @offset = offset
      0
    end

    def seek_from_disk_offset(disk_number, offset)
      validate_disk_number(disk_number)
      while offset > volume(disk_number).logical_size
        offset -= volume(disk_number).logical_size
        disk_number += 1
        return seek_to(volume_count, 0) if disk_number >= volume_count
      end

      seek_to(disk_number, offset)
    end

    def seek(position, whence = IO::SEEK_SET)
      case position
      when Position
        seek_to(position.disk, position.offset)
      when Integer
        seek_integer(position, whence)
      else
        raise ArgumentError, 'position must be an integer or MultiVolumeIO::Position'
      end
    end

    def read(length = nil)
      return +''.b if length == 0

      result = +''.b

      loop do
        if at_volume_end?
          break unless @disk + 1 < volume_count

          advance_to_available_volume
        end
        break if @disk >= volume_count

        volume = volume(@disk)
        bytes = volume.io.read(length.nil? ? nil : length - result.bytesize)
        result << bytes if bytes
        @offset = volume.io.tell - volume.base
        break if length.nil? || result.bytesize == length || @disk >= volume_count
      end

      result.empty? ? nil : result
    end

    def eof?
      return false unless at_volume_end?

      @disk + 1 >= volume_count
    end

    alias eof eof?

    def close
      @volumes.each_value do |volume|
        volume.io.close unless volume.io.respond_to?(:closed?) && volume.io.closed?
      end
      @volumes.clear
      nil
    end

    def dup
      self.class.new(@provider, @disk, @offset)
    end

    private

    def seek_integer(position, whence)
      case whence
      when IO::SEEK_SET
        seek_to(@disk, position)
      when IO::SEEK_CUR
        seek_relative(position)
      when IO::SEEK_END
        seek_from_end(position)
      else
        raise ArgumentError, "unsupported seek whence #{whence}"
      end
    end

    def seek_relative(distance)
      disk_number = @disk
      offset = @offset + distance

      while offset.negative?
        previous = disk_number - 1
        raise VolumeOffsetError.new(disk_number, offset) if previous.negative?

        disk_number = previous
        offset += volume(disk_number).logical_size
      end

      while offset >= volume(disk_number).logical_size
        offset -= volume(disk_number).logical_size
        disk_number += 1
        return seek_to(volume_count, 0) if disk_number >= volume_count && offset.zero?
      end

      seek_to(disk_number, offset)
    end

    def seek_from_end(distance)
      disk_number = volume_count - 1
      offset = volume(disk_number).logical_size + distance
      offset = 0 if offset.negative?

      seek_to(disk_number, offset)
    end

    def advance_to_available_volume
      return unless @disk + 1 < volume_count

      @disk += 1
      @offset = 0
      io_seek(volume(@disk), 0)
    end

    def at_volume_end?
      @offset >= volume(@disk).logical_size
    end

    def volume(disk_number)
      @volumes[disk_number] ||= open_volume(disk_number)
    end

    def validate_volumes
      return if @provider.volume_count.nil?

      @provider.volume_count.times { |disk_number| volume(disk_number) }
    end

    def open_volume(disk_number)
      io = @provider.open(disk_number)
      base = disk_number.zero? && leading_split_signature?(io) ? 4 : 0
      io.seek(base, IO::SEEK_SET)
      size = io_size(io) - base
      path = io.path if io.respond_to?(:path)
      result = Volume.new(io, size, base, path)
      check_duplicate_volume(disk_number, result)
      result
    end

    def check_duplicate_volume(disk_number, volume)
      @volumes.each do |other_disk, other|
        duplicate = volume.io.equal?(other.io)
        duplicate ||= !volume.path.nil? && volume.path == other.path
        next unless duplicate

        raise DuplicateVolumeError.new(disk_number, other_disk)
      end
    end

    def leading_split_signature?(io)
      io.seek(0, IO::SEEK_SET)
      io.read(4) == [SPLIT_FILE_SIGNATURE].pack('V')
    end

    def io_size(io)
      io.seek(0, IO::SEEK_END)
      io.tell
    end

    def io_seek(volume, offset)
      volume.io.seek(offset + volume.base, IO::SEEK_SET)
    end

    def validate_disk_number(disk_number)
      return if disk_number.is_a?(Integer) && disk_number >= 0 && disk_number < volume_count

      raise VolumeOffsetError.new(disk_number, 0)
    end

    def validate_offset(disk_number, offset, size)
      return if offset.is_a?(Integer) && offset >= 0 && offset <= size

      raise VolumeOffsetError.new(disk_number, offset, size)
    end

    def discover_volume_count
      disk_number = 0
      disk_number += 1 while disk_number >= 0 && provider_has_volume?(disk_number)
      disk_number
    end

    def provider_has_volume?(disk_number)
      volume(disk_number)
      true
    rescue MissingVolumeError
      false
    end
  end
end
