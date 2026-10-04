# frozen_string_literal: true

require "time"

class Shrine
  class ResumableUpload
    # Represents the state of a single resumable upload session. A session
    # holds the declared total size of the file, an optional expected
    # checksum, the set of byte ranges that have already been confirmed,
    # and the result of a successful finalization.
    class Session
      ATTRIBUTES = %i[
        id
        total_size
        checksum
        filename
        content_type
        ranges
        created_at
        expires_at
        uploaded_file_data
      ].freeze

      attr_accessor(*ATTRIBUTES)

      def initialize(**attributes)
        ATTRIBUTES.each do |name|
          instance_variable_set("@#{name}", attributes[name]) if attributes.key?(name)
        end

        @ranges ||= []
        @created_at ||= Time.now.utc
      end

      # True once every byte of the declared length has been received.
      def complete?
        total_size.to_i.zero? || merged_ranges == [[0, total_size]]
      end

      # True after a successful finalization published the file.
      def finalized?
        !uploaded_file_data.nil?
      end

      def expired?(now = Time.now.utc)
        expires_at && now >= expires_at
      end

      # Number of confirmed bytes.
      def received_size
        merged_ranges.sum { |start_offset, end_offset| end_offset - start_offset }
      end

      # Returns a sorted list of non-overlapping, adjacent ranges that have
      # been received (e.g. `[[0, 100], [100, 250]]`).
      def merged_ranges
        self.class.merge_ranges(ranges)
      end

      # Merges a set of `[start_offset, end_offset)` ranges into a sorted
      # list of disjoint, adjacent ranges.
      def self.merge_ranges(ranges)
        sorted = ranges.sort_by(&:first)

        sorted.each_with_object([]) do |(start_offset, end_offset), merged|
          if merged.empty? || start_offset > merged.last.last
            merged << [start_offset, end_offset]
          elsif end_offset > merged.last.last
            merged[-1] = [merged.last.first, end_offset]
          end
        end
      end

      # Serializes the session state into a JSON-friendly hash. Received
      # chunks are represented as confirmed `[start, end)` ranges.
      def to_h
        {
          "id"         => id,
          "total_size" => total_size,
          "checksum"   => checksum,
          "filename"   => filename,
          "content_type" => content_type,
          "ranges"     => merged_ranges,
          "received_size" => received_size,
          "created_at" => created_at&.iso8601,
          "expires_at" => expires_at&.iso8601,
          "uploaded_file_data" => uploaded_file_data,
        }
      end

      # Builds a session from its serialized hash representation.
      def self.from_h(hash)
        hash = hash.transform_keys(&:to_s)

        new(
          id:         hash["id"],
          total_size: hash["total_size"],
          checksum:   hash["checksum"],
          filename:   hash["filename"],
          content_type: hash["content_type"],
          ranges:     hash["ranges"]&.map { |range| range.map(&:to_i) },
          created_at: hash["created_at"] && Time.iso8601(hash["created_at"]),
          expires_at: hash["expires_at"] && Time.iso8601(hash["expires_at"]),
          uploaded_file_data: hash["uploaded_file_data"],
        )
      end
    end
  end
end
