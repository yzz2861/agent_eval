# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'
require 'pathname'

module Zip
  # Performs an all-or-nothing extraction of the entries in a Zip::File into a
  # destination directory.
  #
  # Every entry is first extracted into a private staging directory next to
  # the destination. Only after every entry has been extracted and verified
  # (including CRC checks) is the result published to the destination with an
  # atomic rename. If anything fails at any point, the staging directory is
  # removed and any existing destination is left untouched (or restored), so a
  # destination never ends up containing a partial extraction.
  class TransactionalExtractor
    ON_EXIST_STRATEGIES = %i[raise backup].freeze # :nodoc:
    STAGING_PREFIX = '.rubyzip-staging-'.freeze # :nodoc:
    BACKUP_PREFIX = '.rubyzip-backup-'.freeze # :nodoc:

    # Extracts +entries+ transactionally into +destination+.
    #
    # +on_exist+ controls what happens when +destination+ already exists:
    # +:raise+ (the default) raises Zip::DestinationExistsError, and +:backup+
    # moves the existing destination aside before publishing the new one and
    # removes the backup once the publish has succeeded.
    def self.extract(entries, destination, on_exist: :raise,
                     restore_ownership: DEFAULT_RESTORE_OPTIONS[:restore_ownership],
                     restore_permissions: DEFAULT_RESTORE_OPTIONS[:restore_permissions],
                     restore_times: DEFAULT_RESTORE_OPTIONS[:restore_times])
      new(entries, destination, on_exist: on_exist,
                     restore_ownership: restore_ownership,
                     restore_permissions: restore_permissions,
                     restore_times: restore_times).extract
    end

    def initialize(entries, destination, on_exist: :raise,
                   restore_ownership: false,
                   restore_permissions: true,
                   restore_times: true)
      @entries = entries
      @destination = ::File.expand_path(destination)
      @on_exist = on_exist
      @restore_ownership = restore_ownership
      @restore_permissions = restore_permissions
      @restore_times = restore_times

      unless ON_EXIST_STRATEGIES.include?(@on_exist)
        raise ArgumentError,
              "unknown on_exist strategy #{@on_exist.inspect} " \
              "(expected one of #{ON_EXIST_STRATEGIES.map(&:inspect).join(', ')})"
      end
    end

    # Runs the preflight checks, extracts everything into staging and then
    # publishes the result, rolling back on any failure.
    def extract
      if destination_exists? && @on_exist == :raise
        raise DestinationExistsError, @destination
      end

      planned = preflight
      parent = ::File.dirname(@destination)
      ::FileUtils.mkdir_p(parent)

      staging = Dir::Tmpname.create(STAGING_PREFIX, parent) {}
      backup = nil
      begin
        ::Dir.mkdir(staging)
        stage(planned, staging)
        verify_staged_symlinks(planned, staging)
        if destination_exists?
          backup = move_aside(@destination)
        end
        publish(staging)
      rescue StandardError
        begin
          rollback(staging, backup)
        rescue PublishError => e
          failed_to_restore = true
          raise e
        end
        raise
      ensure
        FileUtils.rm_rf(staging) if ::File.exist?(staging)
        FileUtils.rm_rf(backup) if backup && !failed_to_restore &&
                                  backup_removable?(backup)
      end

      @destination
    end

    private

    def destination_exists?
      ::File.exist?(@destination) || ::File.symlink?(@destination)
    end

    # Validates every entry path before anything is written to disk and
    # returns an Array of [entry, relative_clean_path, type, symlink_target]
    # tuples ordered for extraction (directories first, shallowest first, then
    # files and symlinks).
    def preflight
      planned = @entries.map do |entry|
        relative = validate_path(entry)
        target = symlink_target(entry) if entry.symlink?
        [entry, relative, entry.ftype, target]
      end

      check_duplicate_paths(planned)
      check_case_collisions(planned)
      check_type_conflicts(planned)
      check_symlink_targets(planned)

      directories, others = planned.partition { |_e, _p, type, _t| type == :directory }
      directories.sort_by! { |_e, p, _t, _g| p.each_filename.to_a.size }
      directories + others
    end

    # Returns the clean, relative Pathname of the entry within the
    # destination, or raises if the entry is absolute or escapes the
    # destination.
    def validate_path(entry)
      raw = entry.name.to_s.tr('\\', '/')
      name = Pathname.new(raw)
      clean = name.cleanpath
      components = clean.each_filename.to_a

      if name.absolute? || !clean.relative? || components.empty? ||
         components.include?('..') || components == ['.']
        raise EntryNameError, entry.name
      end

      clean
    end

    # Reads the (raw) target of a symlink entry, or nil if it cannot be read.
    def symlink_target(entry)
      entry.get_input_stream(&:read)
    rescue StandardError
      nil
    end

    def check_duplicate_paths(planned)
      seen = {}
      planned.each do |entry, relative, type, _target|
        key = relative.to_s
        if seen.key?(key)
          seen_type, seen_entry = seen[key]
          if seen_type == type
            raise DuplicateEntryError, key
          else
            raise EntryConflictError.new(entry.name, seen_entry.name)
          end
        end

        seen[key] = [type, entry]
      end
    end

    def check_case_collisions(planned)
      seen = {}
      planned.each do |entry, relative, _type, _target|
        key = relative.to_s.downcase
        if seen.key?(key)
          raise CaseInsensitiveMatchError.new(seen[key].name, entry.name)
        end

        seen[key] = entry
      end
    end

    # Rejects entries where a non-directory component occupies a path that an
    # entry of a different type also occupies (e.g. a file "a" and a file
    # "a/b", or a file and a directory both called "a").
    def check_type_conflicts(planned)
      endpoints = {}
      planned.each do |entry, relative, type, _target|
        endpoints[relative.to_s] = { type: type, entry: entry }
      end

      planned.each do |entry, relative, type, _target|
        components = relative.each_filename.to_a
        components = components[0...-1] if type == :directory
        components.each_with_index do |_component, index|
          path = ::File.join(*components[0..index])
          owner = endpoints[path]
          next if owner.nil?

          final = index == components.length - 1
          if final
            raise EntryConflictError.new(entry.name, owner[:entry].name) if
              owner[:type] != type
          elsif owner[:type] == :file || owner[:type] == :symlink
            raise EntryConflictError.new(entry.name, owner[:entry].name)
          end
        end
      end
    end

    # Ensures no symlink entry resolves to a path outside the destination
    # through itself or other symlink entries.
    def check_symlink_targets(planned)
      links = {}
      planned.each do |_entry, relative, type, target|
        links[relative.to_s] = target if type == :symlink
      end

      planned.each do |_entry, relative, type, target|
        next unless type == :symlink

        unless safe_symlink_target?(relative.to_s, target, links)
          raise SymlinkEscapeError.new(relative.to_s, target.to_s)
        end
      end
    end

    # Resolves +target+ relative to the directory containing +link_path+,
    # following the other symlink entries in +links+, and returns true if the
    # final path stays within the extraction root.
    def safe_symlink_target?(link_path, target, links)
      return false if target.nil? || target.empty?

      base_dir = ::File.dirname(link_path)
      current = target
      seen = {}
      128.times do
        path = Pathname.new(current)
        resolved = if path.absolute?
                     path.cleanpath
                   else
                     Pathname.new(::File.join(base_dir, current)).cleanpath
                   end
        components = resolved.each_filename.to_a
        return false if resolved.absolute? || components.include?('..')

        resolved_s = resolved.to_s
        return false if seen[resolved_s]
        seen[resolved_s] = true

        next_target = links[resolved_s]
        return true if next_target.nil?

        current = next_target
        base_dir = ::File.dirname(resolved_s)
      end
      false
    end

    def stage(planned, staging)
      planned.each do |entry, relative, type, target|
        if type == :symlink
          stage_symlink(staging, relative, target)
        else
          configure_entry(entry)
          stage_filesystem_entry(entry, staging, relative, type)
        end
      end
    end

    def stage_filesystem_entry(entry, staging, relative, type)
      dest_path = ::File.join(staging, relative.to_s)
      ::FileUtils.mkdir_p(::File.dirname(dest_path)) if type == :file
      entry.extract(relative.to_s,
                    destination_directory: staging, verify_crc: true)
    end

    def stage_symlink(staging, relative, target)
      dest_path = ::File.join(staging, relative.to_s)
      ::FileUtils.mkdir_p(::File.dirname(dest_path))
      ::FileUtils.ln_s(target, dest_path)
    end

    # Defense in depth: after everything is on disk, confirm that no symlink
    # (following the symlinks actually created during this extraction)
    # resolves outside of staging. The check is lexical so it also covers
    # dangling links.
    def verify_staged_symlinks(planned, staging)
      links = staged_link_paths(planned, staging)
      planned.each do |_entry, relative, type, _target|
        next unless type == :symlink

        link_path = ::File.join(staging, relative.to_s)
        unless lexically_contained?(link_path, staging, links)
          raise SymlinkEscapeError.new(relative.to_s,
                                      ::File.readlink(link_path))
        end
      end
    end

    # A map of the on-disk path of every extracted symlink to its target.
    def staged_link_paths(planned, staging)
      planned.each_with_object({}) do |(_entry, relative, type, target), links|
        next unless type == :symlink

        links[::File.join(staging, relative.to_s)] = target
      end
    end

    # Lexically resolves the symlink at +link_path+ through any other
    # extracted symlinks in +links+ and returns true if it stays within
    # +root+. Existing non-symlink directories end the resolution.
    def lexically_contained?(link_path, root, links)
      current = ::File.expand_path(::File.readlink(link_path),
                                   ::File.dirname(link_path))
      seen = {}
      128.times do
        return false unless inside?(current, root)
        return true unless links.key?(current)
        return false if seen[current]

        seen[current] = true
        current = ::File.expand_path(links[current], ::File.dirname(current))
      end
      false
    end

    def inside?(path, root)
      path == root || path.start_with?(root + ::File::SEPARATOR)
    end

    def configure_entry(entry)
      entry.restore_ownership = @restore_ownership
      entry.restore_permissions = @restore_permissions
      entry.restore_times = @restore_times
    end

    def move_aside(destination)
      parent = ::File.dirname(destination)
      backup = ::File.join(parent,
                           "#{BACKUP_PREFIX}#{::File.basename(destination)}-" +
                           "#{Process.pid}-#{object_id}")
      ::File.rename(destination, backup)
      backup
    end

    def publish(staging)
      ::File.rename(staging, @destination)
    end

    # Removes staging and restores the backed-up destination, if any.
    # Returns true if the original destination could not be restored (in which
    # case the backup is left on disk for the caller to recover manually).
    # Removes staging and restores the backed-up destination, if any. Raises
    # Zip::PublishError (leaving the backup on disk) if the original
    # destination cannot be restored.
    def rollback(staging, backup)
      FileUtils.rm_rf(staging)
      return if backup.nil?

      FileUtils.rm_rf(@destination) if destination_exists?
      ::File.rename(backup, @destination)
    rescue StandardError => e
      raise PublishError,
            "failed to restore '#{@destination}' after extraction failed: " \
            "#{e.message} (backup left at '#{backup}')"
    end

    def backup_removable?(backup)
      ::File.exist?(backup) || ::File.symlink?(backup)
    end
  end
end
