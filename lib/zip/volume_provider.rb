# frozen_string_literal: true

module Zip
  # A VolumeProvider supplies the IO objects for the numbered volumes
  # ("disks") of a split or spanned zip archive. Volumes are numbered from
  # zero, in archive order: the last volume (the one carrying the end of
  # central directory record) has the highest number.
  #
  # A provider is any object that responds to:
  #
  # - +volume(disk_number)+ - returns the IO-like object for that disk, a
  #   Zip::VolumeProvider::Volume, or +nil+ if the volume is not available.
  #   Returning +nil+ for a volume the archive needs raises
  #   Zip::MissingVolumeError.
  # - +last_disk_number+ (optional) - the highest disk number available, or
  #   +nil+ if unknown. When given, a missing intermediate volume is
  #   detected (and reported) rather than being mistaken for the end of the
  #   archive.
  #
  # Returned IOs are *borrowed* by default: rubyzip reads and seeks them but
  # never closes them. Wrap an IO with Zip::VolumeProvider.owned to transfer
  # ownership - owned IOs are closed when the reading stream is closed.
  # Borrowed IOs are shared between every stream reading the archive, so
  # only one entry should be read at a time from a borrowed-IO provider;
  # owned IOs are re-opened per reader and support concurrent entry streams.
  #
  # Example:
  #
  #   provider = Zip::VolumeProvider.for_paths(
  #     0 => 'backup.z01', 1 => 'backup.z02', 2 => 'backup.zip'
  #   )
  #   Zip::File.open('backup.zip', volume_provider: provider) do |zip|
  #     puts zip.read('notes.txt')
  #   end
  class VolumeProvider
    # A single volume: an IO-like object plus a flag saying whether rubyzip
    # owns (and must close) it. See Zip::VolumeProvider.
    class Volume
      attr_reader :io

      def initialize(io, owned: false)
        @io    = io
        @owned = owned
      end

      def owned?
        @owned
      end
    end

    class << self
      # Wrap +io+ so that rubyzip takes ownership of it and closes it when
      # the reading stream is closed.
      def owned(io)
        Volume.new(io, owned: true)
      end

      # Wrap +io+ as a borrowed volume: rubyzip will never close it.
      def borrowed(io)
        Volume.new(io, owned: false)
      end

      # Builds a provider from a map of disk number to filesystem path.
      # Files are opened lazily (in binary mode) and are owned by the
      # reader. The highest key is used as +last_disk_number+.
      def for_paths(paths)
        PathMap.new(paths)
      end

      # Builds a provider from a map of disk number to IO-like object.
      # The IOs are borrowed: the caller keeps ownership. The highest key
      # is used as +last_disk_number+.
      def for_ios(ios)
        IOMap.new(ios)
      end
    end

    # Creates a provider backed by a block. The block receives a disk
    # number and must return a Volume, an IO-like object (treated as
    # borrowed), or nil.
    def initialize(&block)
      @block = block
    end

    # Returns the volume for +disk_number+: a Volume, an IO-like object
    # (treated as borrowed), or nil if the volume is not available.
    def volume(disk_number)
      raise NotImplementedError, 'VolumeProvider subclasses must implement #volume' unless @block

      @block.call(disk_number)
    end

    # The highest disk number this provider can supply, or nil if unknown.
    def last_disk_number
      nil
    end

    # Provider backed by a map of disk number to path. See .for_paths.
    class PathMap < VolumeProvider
      def initialize(paths)
        super()
        @paths = {}
        paths.each do |disk_number, path|
          expanded = ::File.expand_path(path)
          if (other = @paths.key(expanded))
            raise ::Zip::DuplicateVolumeError.new(disk_number, other)
          end

          @paths[disk_number] = expanded
        end
        @paths = @paths.sort.to_h
      end

      def volume(disk_number)
        path = @paths[disk_number]
        ::Zip::VolumeProvider.owned(::File.open(path, 'rb')) if path
      end

      def last_disk_number
        @paths.empty? ? nil : @paths.keys.max
      end
    end

    # Provider backed by a map of disk number to IO. See .for_ios.
    class IOMap < VolumeProvider
      def initialize(ios)
        super()
        @ios = ios.sort.to_h
      end

      def volume(disk_number)
        @ios[disk_number]
      end

      def last_disk_number
        @ios.empty? ? nil : @ios.keys.max
      end
    end
  end
end
