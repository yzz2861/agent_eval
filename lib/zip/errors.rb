# frozen_string_literal: true

module Zip
  # The superclass for all rubyzip error types. Simply rescue this one if
  # you don't need to know what sort of error has been raised.
  class Error < StandardError; end

  # Error raised if an unsupported compression method is used.
  class CompressionMethodError < Error
    # The compression method that has caused this error.
    attr_reader :compression_method

    # Create a new CompressionMethodError with the specified incorrect
    # compression method.
    def initialize(method)
      super()
      @compression_method = method
    end

    # The message returned by this error.
    def message
      "Unsupported compression method: #{COMPRESSION_METHODS[@compression_method]}."
    end
  end

  # Error raised if there is a problem while decompressing an archive entry.
  class DecompressionError < Error
    # The error from the underlying Zlib library that caused this error.
    attr_reader :zlib_error

    # Create a new DecompressionError with the specified underlying Zlib
    # error.
    def initialize(zlib_error)
      super()
      @zlib_error = zlib_error
    end

    # The message returned by this error.
    def message
      "Zlib error ('#{@zlib_error.message}') while inflating."
    end
  end

  # Error raised when trying to extract an archive entry over an
  # existing file.
  class DestinationExistsError < Error
    # Create a new DestinationExistsError with the clashing destination.
    def initialize(destination)
      super()
      @destination = destination
    end

    # The message returned by this error.
    def message
      "Cannot create file or directory '#{@destination}'. " \
        'A file already exists with that name.'
    end
  end

  # Error raised when trying to add an entry to an archive where the
  # entry name already exists.
  class EntryExistsError < Error
    # Create a new EntryExistsError with the specified source and name.
    def initialize(source, name)
      super()
      @source = source
      @name = name
    end

    # The message returned by this error.
    def message
      "'#{@source}' failed. Entry #{@name} already exists."
    end
  end

  # Error raised when an entry name is invalid.
  class EntryNameError < Error
    # Create a new EntryNameError with the specified name.
    def initialize(name = nil)
      super()
      @name = name
    end

    # The message returned by this error.
    def message
      if @name.nil?
        'Illegal entry name. Names must have fewer than 65,536 characters.'
      else
        "Illegal entry name '#{@name}'. Names must not start with '/'."
      end
    end
  end

  # Error raised if an entry is larger on extraction than it is advertised
  # to be.
  class EntrySizeError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # Create a new EntrySizeError with the specified entry.
    def initialize(entry)
      super()
      @entry = entry
    end

    # The message returned by this error.
    def message
      "Entry '#{@entry.name}' should be #{@entry.size}B, but is larger when inflated."
    end
  end

  class EntryNumberMismatchError < Error
    # Create a new EntryNumberMismatchError with the specified size and size in bytes.
    def initialize(size, size_in_bytes)
      super()
      @size = size
      @size_in_bytes = size_in_bytes
    end

    # The message returned by this error.
    def message
      "Zip consistency problem: an impossibly high number of entries (#{@size}) " \
        'is declared in this file, compared to the size of the central directory ' \
        "(#{@size_in_bytes} bytes)."
    end
  end

  # Error raised if a split archive is read. Rubyzip does not support reading
  # split archives.
  class SplitArchiveError < Error
    # The message returned by this error.
    def message
      'This is a split (multi-volume) archive. To read it, supply its volumes ' \
        'with a volume provider, e.g. Zip::File.open(name, volume_provider: ...).'
    end
  end

  # Error raised when a volume needed to read a multi-volume archive is not
  # supplied by the volume provider.
  class MissingVolumeError < Error
    # The disk number of the missing volume.
    attr_reader :disk_number

    # Create a new MissingVolumeError with the missing disk number.
    def initialize(disk_number)
      super()
      @disk_number = disk_number
    end

    # The message returned by this error.
    def message
      "Volume #{@disk_number} is required to read this archive, " \
        'but the volume provider did not supply it.'
    end
  end

  # Error raised when a volume provider supplies the same underlying IO or
  # file for more than one disk number.
  class DuplicateVolumeError < Error
    # Create a new DuplicateVolumeError with the two clashing disk numbers.
    def initialize(disk_number, other_disk_number)
      super()
      @disk_number = disk_number
      @other_disk_number = other_disk_number
    end

    # The message returned by this error.
    def message
      "Volumes #{@disk_number} and #{@other_disk_number} share the same " \
        'underlying IO or file; each volume of an archive must be distinct.'
    end
  end

  # Error raised when an archive structure points outside the bounds of a
  # volume (or of the whole multi-volume archive).
  class VolumeOffsetError < Error
    # Create a new VolumeOffsetError. +disk_number+ may be nil when the
    # offset is into the archive's logical address space as a whole.
    def initialize(offset, size, disk_number = nil)
      super()
      @offset = offset
      @size = size
      @disk_number = disk_number
    end

    # The message returned by this error.
    def message
      location = @disk_number.nil? ? 'the archive' : "volume #{@disk_number}"
      "Offset #{@offset} is out of bounds for #{location} (#{@size} bytes)."
    end
  end

  # Error raised if there is not enough metadata for the entry to be streamed.
  class StreamingError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # Create a new StreamingError with the specified entry.
    def initialize(entry)
      super()
      @entry = entry
    end

    # The message returned by this error.
    def message
      "The local header of this entry ('#{@entry.name}') does not contain " \
        'the correct metadata for `Zip::InputStream` to be able to ' \
        'uncompress it. Please use `Zip::File` instead of `Zip::InputStream`.'
    end
  end
end
