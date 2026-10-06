# frozen_string_literal: true

require 'fileutils'
require 'pathname'
require 'tmpdir'
require 'zlib'

module Zip
  # Extracts an archive into a private staging directory, verifies every
  # extracted entry, and only then publishes the result at the destination
  # with an atomic rename. If anything goes wrong (a bad entry name, a CRC
  # mismatch, a failure while publishing) the destination is left exactly
  # as it was before: no half-extracted tree is ever visible there.
  #
  # This class is the engine behind `Zip::File#extract_transactionally`;
  # most users should call that instead of using this class directly.
  class TransactionalExtractor # :nodoc:
    STRATEGIES = %i[refuse backup_replace].freeze
    private_constant :STRATEGIES

    # @param entries [Enumerable<Zip::Entry>] the entries to extract
    # @param destination [String] where the extracted tree should end up
    # @param on_existing [:refuse, :backup_replace] what to do when
    #   `destination` already exists
    # @param case_sensitive [Boolean, nil] when nil (the default) the
    #   destination filesystem is probed; when true, entry names that
    #   differ only in case are allowed; when false, they always conflict
    # @param configure_entry [Proc] called with each entry before it is
    #   extracted; used to apply restore options
    def initialize(entries, destination, on_existing: :refuse,
                   case_sensitive: nil, configure_entry: nil)
      @entries = entries.to_a
      @destination = ::File.absolute_path(destination.to_s)
      @on_existing = on_existing
      @case_sensitive = if case_sensitive.nil?
                          filesystem_case_sensitive?
                        else
                          case_sensitive
                        end
      @configure_entry = configure_entry
    end

    # Runs the full transaction: preflight checks, staged extraction and
    # verification, then publication. Returns the destination path.
    def extract
      validate_strategy
      prepare_for_existing_destination
      @planned = preflight

      staging = create_staging_directory
      run_transaction(staging)
      @destination
    end

    private

    # A minimal plan of what is going to be extracted: each item is a
    # [entry, key, ftype] tuple in extraction order (directories, symlinks,
    # files).
    def preflight
      seen_paths = {}
      planned = []

      @entries.each do |entry|
        ftype = validate_entry_type(entry)
        key = normalize_entry_name(entry.name)
        validate_symlink_target(entry, key) if ftype == :symlink

        if (previous_type = seen_paths[key])
          if previous_type == ftype
            raise DuplicateEntryPathError, key
          else
            raise EntryPathConflictError.new(entry.name, key)
          end
        end
        seen_paths[key] = ftype
        planned << [entry, key, ftype]
      end

      check_ancestor_conflicts(seen_paths)
      check_case_folding_conflicts(seen_paths.keys) unless @case_sensitive

      ordered_plan(planned)
    end

    def validate_strategy
      return if STRATEGIES.include?(@on_existing)

      raise ArgumentError,
            "unknown on_existing strategy #{@on_existing.inspect} " \
            "(expected one of #{STRATEGIES.map(&:inspect).join(', ')})"
    end

    def prepare_for_existing_destination
      return unless destination_exists?

      raise TransactionalDestinationExistsError, @destination if @on_existing == :refuse

      @backup_path = make_backup_path
    end

    def create_staging_directory
      FileUtils.mkdir_p(::File.dirname(@destination))
      staging = Dir.mktmpdir(staging_prefix, ::File.dirname(@destination))
      # Keep the staging tree private while it is being assembled, so its
      # half-finished contents cannot be observed through the filesystem
      # even before the atomic publish.
      begin
        ::File.chmod(0o700, staging)
      rescue SystemCallError
        nil
      end
      staging
    end

    def run_transaction(staging)
      extract_into(staging)
      publish(staging)
    rescue StandardError
      FileUtils.remove_entry(staging, true)
      raise
    end

    def validate_entry_type(entry)
      return :directory if entry.directory?
      return :symlink if entry.symlink?
      return :file if entry.file?

      raise Error, "unknown file type for entry '#{entry.name}'"
    end

    # Normalises an entry name to a clean relative path (without a trailing
    # slash) that is guaranteed to stay inside the destination. Raises if
    # the name is unsafe.
    def normalize_entry_name(name)
      raise UnsafeEntryPathError, name.inspect if name.to_s.empty?

      raw = name.to_s
      raise UnsafeEntryPathError, name if raw.include?("\0")
      raise UnsafeEntryPathError, name if raw.include?('\\')
      raise UnsafeEntryPathError, name if raw.start_with?('/')

      clean = Pathname.new(raw).cleanpath
      raise UnsafeEntryPathError, name unless clean.relative?

      key = clean.to_s
      raise UnsafeEntryPathError, name if key == '.' || key.split('/').include?('..')

      key
    end

    # Validates that a symlink entry's declared target never resolves to a
    # location outside the destination directory. Absolute targets and
    # targets whose lexical path escapes the root are rejected.
    def validate_symlink_target(entry, key)
      target = read_symlink_target(entry)
      raise UnsafeSymlinkError.new(entry.name, target) if target.empty?
      raise UnsafeSymlinkError.new(entry.name, target) if target.include?("\0")
      raise UnsafeSymlinkError.new(entry.name, target) if target.start_with?('/')
      # Windows drive paths ("C:foo", "C:\\foo") and UNC paths
      # ("\\\\server\\share") are never safe either.
      raise UnsafeSymlinkError.new(entry.name, target) if target.match?(/\A[A-Za-z]:/)
      raise UnsafeSymlinkError.new(entry.name, target) if target.include?('\\')
      raise UnsafeSymlinkError.new(entry.name, target) if Pathname.new(target).absolute?

      # `key` is a verified safe relative path, so joining and cleaning is
      # enough to determine whether the target stays inside the root.
      resolved = Pathname.new(::File.dirname(key)).join(target).cleanpath
      raise UnsafeSymlinkError.new(entry.name, target) unless
        resolved.relative? && !resolved.to_s.split('/').include?('..')
    end

    def read_symlink_target(entry)
      entry.get_input_stream(&:read).to_s
    end

    # Builds the set of every path the extracted tree will contain: each
    # entry key plus every ancestor directory it implies.
    def all_paths(keys)
      paths = keys.dup
      keys.each do |key|
        Pathname.new(key).dirname.descend do |ancestor|
          ancestor_key = ancestor.to_s
          paths << ancestor_key unless ancestor_key == '.'
        end
      end
      paths
    end

    # Ensures that no entry has a parent path claimed by a file or symlink
    # (a later `a/b` entry cannot exist if `a` itself is a file).
    def check_ancestor_conflicts(seen_paths)
      seen_paths.each_key do |key|
        Pathname.new(key).dirname.descend do |ancestor|
          ancestor_key = ancestor.to_s
          next if ancestor_key == '.' || ancestor_key == key

          ancestor_type = seen_paths[ancestor_key]
          next if ancestor_type.nil? || ancestor_type == :directory

          raise EntryPathConflictError.new(key, ancestor_key)
        end
      end
    end

    # Detects paths (entry paths and their ancestor directories) that would
    # be indistinguishable on a case-insensitive filesystem.
    def check_case_folding_conflicts(keys)
      folded = {}
      all_paths(keys).sort.each do |path|
        existing = folded[path.downcase]
        raise CaseFoldingConflictError.new(existing, path) if existing && existing != path

        folded[path.downcase] = path
      end
    end

    def ordered_plan(planned)
      directories, rest = planned.partition { |_entry, _key, ftype| ftype == :directory }
      symlinks, files = rest.partition { |_entry, _key, ftype| ftype == :symlink }
      directories + symlinks + files
    end

    def extract_into(staging)
      @planned.each do |entry, key, ftype|
        @configure_entry&.call(entry)
        dest_path = ::File.join(staging, key)

        case ftype
        when :directory
          FileUtils.mkdir_p(dest_path)
          apply_entry_attributes(entry, dest_path)
        when :symlink
          create_staged_symlink(entry, key, staging)
        when :file
          extract_file(entry, key, staging)
        end
      end
    ensure
      # The published root needs to be traversable, regardless of any mode
      # the staging directory itself was created with.
      begin
        ::File.chmod(staging_root_mode, staging)
      rescue SystemCallError
        nil
      end
    end

    def create_staged_symlink(entry, key, staging)
      target = read_symlink_target(entry)
      dest_path = ::File.join(staging, key)
      ensure_real_directory_parent(dest_path, staging)
      FileUtils.ln_s(target, dest_path)
    end

    def extract_file(entry, key, staging)
      dest_path = ::File.join(staging, key)
      ensure_real_directory_parent(dest_path, staging)

      ::File.open(dest_path, 'wb') do |output|
        crc = Zlib.crc32
        total = 0
        entry.get_input_stream do |input|
          while (chunk = input.sysread(Decompressor::CHUNK_SIZE)) && !chunk.empty?
            output << chunk
            crc = Zlib.crc32(chunk, crc)
            total += chunk.bytesize
          end
        end
        verify_extracted(entry, crc, total)
      end

      apply_entry_attributes(entry, dest_path)
    end

    # Creates the parent directories of `dest_path` and verifies that none
    # of them is a symlink. The checks run component-by-component *before*
    # directories are created, so mkdir can never follow a symlink (which
    # could create directories outside the declared path).
    def ensure_real_directory_parent(dest_path, staging)
      relative = dest_path.delete_prefix(staging + '/')
      walked = staging
      Pathname.new(relative).dirname.descend do |ancestor|
        next if ancestor.to_s == '.'

        walked = ::File.join(walked, ancestor.basename.to_s)
        if ::File.symlink?(walked)
          raise EntryPathConflictError.new(relative, ancestor.to_s)
        end

        Dir.mkdir(walked) unless ::File.exist?(walked)
      end
    end

    # Verifies the CRC and uncompressed size of the extracted bytes against
    # the central directory, but only when the archive actually carries
    # that metadata (streamed archives with data descriptors may not).
    def verify_extracted(entry, computed_crc, total)
      return if entry.incomplete?

      raise CRCError, entry.name if computed_crc != entry.crc || total != entry.size
    end

    def apply_entry_attributes(entry, path)
      entry.send(:set_extra_attributes_on_path, path)
    end

    # Moves the staged tree into place, backing up and replacing any
    # existing destination. Any failure triggers a best-effort restore of
    # the original destination.
    def publish(staging)
      unless @backup_path
        ::File.rename(staging, @destination)
        return
      end

      # Atomically move the old tree out of the way, then publish the new
      # tree. Both renames stay inside the same parent directory, so they
      # stay on the same filesystem and each rename is atomic.
      ::File.rename(@destination, @backup_path)
      begin
        ::File.rename(staging, @destination)
      rescue StandardError => publish_error
        restore_backup(publish_error)
        raise
      end
      FileUtils.rm_rf(@backup_path)
    end

    def restore_backup(publish_error)
      # The failed publish must not leave anything behind at the
      # destination (rename is atomic, but be defensive before restoring).
      FileUtils.rm_rf(@destination) if destination_exists?
      ::File.rename(@backup_path, @destination)
    rescue StandardError => rollback_error
      raise RollbackError.new(
        "failed to publish '#{@destination}' (#{publish_error.class}: " \
        "#{publish_error.message}), and rollback failed too " \
        "(#{rollback_error.class}: #{rollback_error.message}). The previous " \
        "destination was preserved at '#{@backup_path}'.",
        cause_error: publish_error,
        backup_path: @backup_path
      )
    end

    def staging_root_mode
      0o755
    end

    def make_backup_path
      timestamp = Time.now.strftime('%Y%m%d%H%M%S')
      candidate = "#{@destination}.#{timestamp}.bak"
      suffix = 0
      while destination_exists?(candidate)
        suffix += 1
        candidate = "#{@destination}.#{timestamp}.#{suffix}.bak"
      end
      candidate
    end

    def destination_exists?(path = @destination)
      ::File.exist?(path) || ::File.symlink?(path)
    end

    def staging_prefix
      base = ::File.basename(@destination)
      base = 'extract' if base.empty?
      ".rubyzip-staging-#{base}-"
    end

    # Guesses whether the filesystem at the destination treats file names
    # case-sensitively by creating two differently-cased temporary files
    # in the destination's parent directory.
    def filesystem_case_sensitive?
      Dir.mktmpdir('rubyzip-case-probe', ::File.dirname(@destination)) do |dir|
        lower = ::File.join(dir, 'caseprobe')
        upper = ::File.join(dir, 'CASEPROBE')
        ::File.open(lower, ::File::WRONLY | ::File::CREAT | ::File::EXCL) {}
        begin
          ::File.open(upper, ::File::WRONLY | ::File::CREAT | ::File::EXCL) {}
        rescue SystemCallError
          return false
        end
        true
      end
    rescue StandardError
      # If we cannot probe (permissions, a read-only filesystem, etc.) be
      # strict: refuse ambiguous entries rather than risk clobbering files.
      false
    end
  end
end
