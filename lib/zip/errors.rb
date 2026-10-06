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

  # Superclass for errors raised by `Zip::File#extract_transactionally`.
  # Rescuing this class catches every failure mode of a transactional
  # extraction (invalid entry names, conflicting entries, failed publish,
  # failed rollback, ...).
  class TransactionalExtractionError < Error; end

  # Raised when an entry name in an archive is absolute, contains path
  # traversal (`..`) segments, or otherwise cannot be represented safely
  # inside the destination directory.
  class UnsafeEntryPathError < TransactionalExtractionError
    # Create a new UnsafeEntryPathError for the specified entry name.
    def initialize(entry_name)
      super()
      @entry_name = entry_name
    end

    # The message returned by this error.
    def message
      "Entry '#{@entry_name}' is unsafe: it must be a relative path that " \
        'stays within the destination directory.'
    end
  end

  # Raised when two or more entries in an archive resolve to the same path
  # in the destination directory.
  class DuplicateEntryPathError < TransactionalExtractionError
    # Create a new DuplicateEntryPathError for the specified destination path.
    def initialize(path)
      super()
      @path = path
    end

    # The message returned by this error.
    def message
      "More than one entry in the archive resolves to the path '#{@path}'."
    end
  end

  # Raised when two distinct entries resolve to paths that clash on a
  # case-insensitive filesystem (e.g. `Foo.txt` and `foo.txt`).
  class CaseFoldingConflictError < TransactionalExtractionError
    # Create a new CaseFoldingConflictError for the two clashing names.
    def initialize(first_name, second_name)
      super()
      @first_name = first_name
      @second_name = second_name
    end

    # The message returned by this error.
    def message
      "Entries '#{@first_name}' and '#{@second_name}' conflict on a " \
        'case-insensitive filesystem.'
    end
  end

  # Raised when an entry cannot be written because an earlier entry claims
  # the same path as a different kind of filesystem object (for example,
  # one entry is the file `a` while another is the directory `a/`), or
  # because an entry's parent path is already claimed by a file or symlink.
  class EntryPathConflictError < TransactionalExtractionError
    # Create a new EntryPathConflictError for the entry and the path that
    # blocks it.
    def initialize(entry_name, conflicting_path)
      super()
      @entry_name = entry_name
      @conflicting_path = conflicting_path
    end

    # The message returned by this error.
    def message
      "Entry '#{@entry_name}' conflicts with an earlier entry at " \
        "'#{@conflicting_path}'."
    end
  end

  # Raised when a symlink entry points to an absolute target or a target
  # that resolves to a location outside the destination directory.
  class UnsafeSymlinkError < TransactionalExtractionError
    # Create a new UnsafeSymlinkError for the symlink and its declared
    # target.
    def initialize(link_name, target)
      super()
      @link_name = link_name
      @target = target
    end

    # The message returned by this error.
    def message
      "Symlink entry '#{@link_name}' points outside the destination " \
        "directory ('#{@target}')."
    end
  end

  # Raised when an entry's data fails verification after extraction
  # (its CRC checksum or uncompressed size does not match the central
  # directory).
  class CRCError < TransactionalExtractionError
    # Create a new CRCError for the specified entry name.
    def initialize(entry_name)
      super()
      @entry_name = entry_name
    end

    # The message returned by this error.
    def message
      "Extracted data for entry '#{@entry_name}' failed verification " \
        '(CRC or size mismatch). The archive may be corrupt.'
    end
  end

  # Raised when the destination already exists and the requested strategy
  # for existing destinations is `:refuse` (the default).
  class TransactionalDestinationExistsError < TransactionalExtractionError
    # Create a new error for the specified destination.
    def initialize(destination)
      super()
      @destination = destination
    end

    # The message returned by this error.
    def message
      "Destination '#{@destination}' already exists. Pass " \
        '`on_existing: :backup_replace` to replace it after making a backup.'
    end
  end

  # Raised when publishing a transactionally extracted tree fails and the
  # previous destination cannot be fully restored. The backup is left on
  # disk so no data is silently lost.
  class RollbackError < TransactionalExtractionError
    # The original error that caused the rollback.
    attr_reader :cause_error

    # The path to the backup that could not be fully restored, if any.
    attr_reader :backup_path

    # Create a new RollbackError.
    def initialize(message, cause_error: nil, backup_path: nil)
      super(message)
      @cause_error = cause_error
      @backup_path = backup_path
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
      'Rubyzip cannot extract from split archives at this time.'
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
