# frozen_string_literal: true

module Zip
  # Configuration for reproducible (deterministic) zip archives.
  #
  # Build systems often need archives whose bytes depend only on the
  # content being archived - not on the order files happened to be added
  # in, the mtimes or permissions of the source files, or the platform
  # the archive was built on. Passing `reproducible: true` (or a Hash of
  # explicit options) to Zip::File or Zip::OutputStream normalizes:
  #
  # - entry order: entries are sorted by name when the archive is
  #   committed (Zip::File only; Zip::OutputStream is a stream, so there
  #   the caller controls the order entries are written in),
  # - entry mtimes: pinned to a fixed timestamp (1980-01-01 00:00:00,
  #   the earliest date the zip format can represent, by default),
  # - unix permission bits: 0o644 for files, 0o755 for directories and
  #   symlinks,
  # - the host platform marker: the fstype field is pinned to
  #   Zip::FSTYPE_UNIX regardless of the build platform, and
  # - non-essential extra fields: all extra fields are stripped except
  #   those needed to read the archive back (Zip64 when sizes require
  #   it, AES for encrypted entries).
  #
  # Each aspect can be individually preserved instead of normalized by
  # passing a Hash with the relevant key set to `false`, e.g.
  # `reproducible: { time: false }` keeps the source files' mtimes while
  # normalizing everything else. See #initialize for the full list of
  # options.
  #
  # Symlink entries keep their symlink file type - only their permission
  # bits are normalized. They are never converted into regular files.
  #
  # The determinism guarantee is deliberately narrow: identical bytes
  # are produced only for identical input content, identical
  # configuration, and identical versions of rubyzip and the underlying
  # zlib (compressed bytes are whatever that zlib version produces).
  class Reproducible
    # Default normalized timestamp: the earliest date the zip format
    # can represent.
    DEFAULT_TIME = ::Time.utc(1980, 1, 1).freeze

    # Default normalized unix permission bits, by entry type.
    DEFAULT_FILE_PERMISSIONS      = 0o644
    DEFAULT_DIRECTORY_PERMISSIONS = 0o755
    DEFAULT_SYMLINK_PERMISSIONS   = 0o755

    attr_reader :time, :file_permissions, :directory_permissions,
                :symlink_permissions, :fstype, :suppress_extra_fields

    # Resolves the `reproducible:` option accepted by Zip::File and
    # Zip::OutputStream into a Zip::Reproducible instance, or nil when
    # reproducible mode is off.
    def self.resolve(options)
      case options
      when nil, false then nil
      when Reproducible then options
      when true then new
      when Hash then new(**options)
      else
        raise ArgumentError,
              "reproducible must be true, false or a Hash of options, got: #{options.inspect}"
      end
    end

    # All options default to normalizing their aspect of the entry
    # metadata; pass `false` (or nil) for any of them to preserve the
    # original metadata instead.
    #
    # - `sort_entries`: sort entries by name when a Zip::File is
    #   committed. (Has no effect on Zip::OutputStream, which streams
    #   entries in the order the caller writes them.)
    # - `time`: the mtime to stamp on every entry - a Time, an Integer
    #   of epoch seconds, or `:source_date_epoch` to use the
    #   SOURCE_DATE_EPOCH environment variable (the reproducible-builds
    #   convention). Defaults to DEFAULT_TIME.
    # - `file_permissions`, `directory_permissions`,
    #   `symlink_permissions`: the unix permission bits to stamp on each
    #   entry type.
    # - `fstype`: the host filesystem type marker to stamp on every
    #   entry. Defaults to Zip::FSTYPE_UNIX so that unix file-type bits
    #   (including the symlink marker) are always recorded.
    # - `suppress_extra_fields`: passed to ExtraField#suppress_fields! -
    #   `true` strips all non-essential extra fields.
    def initialize(sort_entries: true, time: DEFAULT_TIME,
                   file_permissions: DEFAULT_FILE_PERMISSIONS,
                   directory_permissions: DEFAULT_DIRECTORY_PERMISSIONS,
                   symlink_permissions: DEFAULT_SYMLINK_PERMISSIONS,
                   fstype: ::Zip::FSTYPE_UNIX,
                   suppress_extra_fields: true)
      @sort_entries          = sort_entries ? true : false
      @time                  = resolve_time(time)
      @file_permissions      = check_permissions(file_permissions, :file_permissions)
      @directory_permissions = check_permissions(directory_permissions, :directory_permissions)
      @symlink_permissions   = check_permissions(symlink_permissions, :symlink_permissions)
      @fstype                = check_fstype(fstype)
      @suppress_extra_fields = suppress_extra_fields
    end

    def sort_entries?
      @sort_entries
    end

    # Normalizes the metadata of a single entry, in place. Only the
    # aspects configured for normalization are touched; the entry's file
    # type (file/directory/symlink) is never changed.
    def normalize(entry)
      entry.dos_time = @time if @time
      permissions = permissions_for(entry.ftype)
      entry.unix_perms = permissions if permissions
      entry.fstype = @fstype if @fstype
      entry
    end

    private

    def resolve_time(time)
      case time
      when nil, false then nil
      when :source_date_epoch then source_date_epoch
      when ::Zip::DOSTime then time
      when ::Time then ::Zip::DOSTime.from_time(time)
      when ::Integer then ::Zip::DOSTime.from_time(::Time.at(time).utc)
      else
        raise ArgumentError,
              "reproducible :time must be a Time, an Integer of epoch seconds, " \
              ":source_date_epoch or false, got: #{time.inspect}"
      end
    end

    def source_date_epoch
      value = ENV.fetch('SOURCE_DATE_EPOCH', nil)
      unless value&.match?(/\A\d+\z/)
        raise Error,
              'reproducible :time is :source_date_epoch, but SOURCE_DATE_EPOCH ' \
              'is not set to an integer of epoch seconds'
      end

      ::Zip::DOSTime.from_time(::Time.at(value.to_i).utc)
    end

    def check_permissions(value, name)
      return nil if value.nil? || value == false
      return value if value.kind_of?(::Integer) && value >= 0 && value <= 0o7777

      raise ArgumentError,
            "reproducible #{name} must be an Integer of unix permission bits " \
            "or false, got: #{value.inspect}"
    end

    def check_fstype(value)
      return nil if value.nil? || value == false
      return value if ::Zip::FSTYPES.key?(value)

      raise ArgumentError,
            "reproducible :fstype must be one of Zip::FSTYPES or false, got: #{value.inspect}"
    end

    def permissions_for(ftype)
      case ftype
      when :file then @file_permissions
      when :directory then @directory_permissions
      when :symlink then @symlink_permissions
      end
    end
  end
end

