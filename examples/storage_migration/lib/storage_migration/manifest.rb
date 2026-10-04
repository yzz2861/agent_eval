# frozen_string_literal: true

require "json"
require "time"
require "fileutils"

module StorageMigration
  # Append-only JSONL log that records the outcome of every migration step.
  #
  # The manifest is the single source of truth for resuming an interrupted
  # migration: the executor consults it before touching a record, so objects
  # that were already copied and verified are never uploaded again.
  #
  # Statuses per record key, in lifecycle order:
  #
  #   copied   - object copied to the target storage and verified
  #   switched - attachment column now points at the target object
  #   cleaned  - source object deleted (explicit cleanup phase)
  #   failed   - copy or verification failed, see the "error" field
  #   skipped  - switch refused because the attachment changed, see "reason"
  class Manifest
    STATUSES = %w[copied switched cleaned failed skipped].freeze

    attr_reader :path

    def initialize(path)
      @path    = path
      @entries = {}
      load
    end

    # Appends an entry for the given record key and makes it the current
    # state for that key. Details are JSON-serializable metadata about the
    # step (source id, checksum, target id, error, ...).
    def record(key, status, **details)
      status = status.to_s
      raise ArgumentError, "unknown status: #{status}" unless STATUSES.include?(status)

      entry = {
        "key"    => key,
        "status" => status,
        "at"     => Time.now.utc.iso8601,
      }.merge(details.transform_keys(&:to_s))

      FileUtils.mkdir_p(File.dirname(@path))
      File.open(@path, "a") do |file|
        file.puts(JSON.generate(entry))
        file.fsync
      end

      @entries[key] = entry
    end

    # Latest entry for a record key, or nil.
    def [](key)
      @entries[key]
    end

    def each(&block)
      @entries.each_value(&block)
    end

    def to_a
      @entries.values
    end

    private

    def load
      return unless File.exist?(@path)

      File.foreach(@path) do |line|
        entry = JSON.parse(line)
        @entries[entry.fetch("key")] = entry
      end
    end
  end
end
