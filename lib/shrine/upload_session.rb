# frozen_string_literal: true

require "shrine"
require "securerandom"
require "time"
require "monitor"

class Shrine
  # Base error for all errors raised while working with upload sessions.
  class UploadSessionError < Error; end

  # Raised when the referenced upload session doesn't exist (anymore).
  class UploadSessionNotFound < UploadSessionError; end

  # Raised when a chunk is uploaded past the declared total size.
  class UploadChunkOutOfRange < UploadSessionError; end

  # Raised when a chunk partially overlaps a previously accepted range, or
  # when the same range is uploaded with different content.
  class UploadChunkConflict < UploadSessionError; end

  # Raised when an upload session is finalized before all bytes were
  # received, or when the content checksum doesn't match.
  class UploadSessionIncomplete < UploadSessionError; end

  # Raised when an operation is only allowed on an unfinished upload session.
  class UploadSessionClosed < UploadSessionError; end

  # Value object representing the state of a resumable upload. The state
  # storage is responsible for persisting and retrieving these objects.
  class UploadSession
    ATTRIBUTES = %i[
      id
      total_size
      metadata
      ranges
      checksum_algorithm
      expires_at
      created_at
      updated_at
      uploaded_id
    ].freeze

    attr_accessor(*ATTRIBUTES)

    def initialize(
      id:,
      total_size:,
      metadata: {},
      ranges: [],
      checksum_algorithm: nil,
      expires_at: nil,
      created_at: nil,
      updated_at: nil,
      uploaded_id: nil
    )
      @id                 = id
      @total_size         = Integer(total_size)
      @metadata           = metadata
      @ranges             = ranges.map { |range| self.class.normalize_range(range) }.sort
      @checksum_algorithm = checksum_algorithm
      @expires_at         = expires_at
      @created_at         = created_at
      @updated_at         = updated_at
      @uploaded_id        = uploaded_id
    end

    # Whether the session was already finalized and an UploadedFile was
    # published for it.
    def finalized?
      !uploaded_id.nil?
    end

    # Whether all bytes up to the declared total size were received.
    def complete?
      return ranges.empty? if total_size.zero?

      ranges == [[0, total_size]]
    end

    # Whether the session has passed its expiration time.
    def expired?(now = Time.now)
      expires_at && now >= expires_at
    end

    # Adds an accepted byte range, merging it with any adjacent ranges.
    def add_range!(start_offset, end_offset)
      @ranges = self.class.merge_ranges(ranges + [[start_offset, end_offset]])
      @updated_at = Time.now
    end

    # Merges a list of `[start, finish]` byte ranges (finish exclusive).
    def self.merge_ranges(ranges)
      ranges = ranges.map { |range| normalize_range(range) }.sort

      ranges.each_with_object([]) do |range, merged|
        if merged.empty? || range[0] > merged.last[1]
          merged << range
        else
          merged[-1] = [merged.last[0], [merged.last[1], range[1]].max]
        end
      end
    end

    # Serializes the session state into a hash suitable for persistence.
    def to_h
      {
        "id"                 => id,
        "total_size"         => total_size,
        "metadata"           => metadata,
        "ranges"             => ranges,
        "checksum_algorithm" => checksum_algorithm,
        "expires_at"         => expires_at,
        "created_at"         => created_at,
        "updated_at"         => updated_at,
        "uploaded_id"        => uploaded_id,
      }
    end
    alias to_hash to_h

    # Builds a session from a previously serialized hash. Time values can be
    # given as strings, which makes the hash JSON-compatible.
    def self.from_h(hash)
      hash = hash.transform_keys(&:to_s)

      new(
        id:                 hash["id"],
        total_size:         hash["total_size"],
        metadata:           hash["metadata"] || {},
        ranges:             hash["ranges"] || [],
        checksum_algorithm: hash["checksum_algorithm"],
        expires_at:         parse_time(hash["expires_at"]),
        created_at:         parse_time(hash["created_at"]),
        updated_at:         parse_time(hash["updated_at"]),
        uploaded_id:        hash["uploaded_id"],
      )
    end

    # Generates a random URL-safe session identifier.
    def self.generate_id
      "us-#{SecureRandom.hex(16)}"
    end

    def self.normalize_range(range)
      start_offset, end_offset = range
      [Integer(start_offset), Integer(end_offset)]
    end

    def self.parse_time(value)
      case value
      when nil   then nil
      when Time  then value
      when String then Time.parse(value)
      else
        value
      end
    end

    def inspect
      "#<#{self.class.inspect} id=#{id.inspect} ranges=#{ranges.inspect} total_size=#{total_size.inspect} finalized=#{finalized?}>"
    end

    private_class_method :parse_time
  end

  module UploadSessions
    # Abstract interface for persisting upload session state. A custom store
    # only needs to implement the four primitive methods below; the default
    # {Shrine::UploadSessions::Memory} implementation keeps the state in
    # process memory and is suitable for local testing and single-process
    # setups.
    #
    # The store is intentionally tiny so that it can be backed by Redis, a
    # database table, or any other key-value store:
    #
    #   * #create(session)                 - persist a new session
    #   * #fetch(id) { |session| ... }     - atomically read-modify-write
    #   * #read(id)                        - read without modifying
    #   * #delete(id)                      - remove a session
    #   * #prune_expired!                  - remove expired sessions
    class Store
      # Persists a session that was never persisted before. Raises an error
      # if a session with the same id already exists.
      def create(session)
        fail NotImplementedError, "#{self.class}#create isn't implemented"
      end

      # Retrieves the session with the given id and yields it to the block
      # for an atomic read-modify-write transaction. The return value of
      # the block is returned to the caller. If the block raises, the
      # session state must remain unchanged.
      def fetch(id)
        fail NotImplementedError, "#{self.class}#fetch isn't implemented"
      end

      # Returns the session with the given id without modifying it.
      def read(id)
        fail NotImplementedError, "#{self.class}#read isn't implemented"
      end

      # Removes the session with the given id. Returns the removed session,
      # or nil when no such session existed.
      def delete(id)
        fail NotImplementedError, "#{self.class}#delete isn't implemented"
      end

      # Removes all sessions that have passed their expiration time. Returns
      # the removed sessions.
      def prune_expired!(now = Time.now)
        fail NotImplementedError, "#{self.class}#prune_expired! isn't implemented"
      end
    end

    # In-memory upload session state store. Thread-safe and dependency-free,
    # intended for local testing and single-process deployments.
    class Memory < Store
      def initialize(sessions = {})
        @sessions = sessions
        @mutex    = Monitor.new
      end

      def create(session)
        @mutex.synchronize do
          if @sessions.key?(session.id)
            fail Shrine::UploadSessionError, "upload session #{session.id.inspect} already exists"
          end

          @sessions[session.id] = session
        end
      end

      def fetch(id)
        @mutex.synchronize do
          session = @sessions.fetch(id) do
            raise Shrine::UploadSessionNotFound, "upload session #{id.inspect} not found"
          end

          snapshot = session.to_h

          begin
            yield session
          rescue StandardError
            @sessions[id] = Shrine::UploadSession.from_h(snapshot)
            raise
          end
        end
      end

      def read(id)
        @mutex.synchronize do
          @sessions.fetch(id) do
            raise Shrine::UploadSessionNotFound, "upload session #{id.inspect} not found"
          end
        end
      end

      def delete(id)
        @mutex.synchronize { @sessions.delete(id) }
      end

      def prune_expired!(now = Time.now)
        @mutex.synchronize do
          expired = @sessions.values.select { |session| session.expired?(now) }
          expired.each { |session| @sessions.delete(session.id) }
          expired
        end
      end

      # Removes all sessions. Mainly useful in tests.
      def clear!
        @mutex.synchronize { @sessions.clear }
      end
    end
  end
end
