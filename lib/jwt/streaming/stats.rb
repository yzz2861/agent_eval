# frozen_string_literal: true

module JWT
  module Streaming
    # Read statistics collected while consuming a streaming body.
    class Stats
      # Number of chunks read from the body source.
      attr_reader :reads

      # Total number of payload bytes read.
      attr_reader :bytes_read

      # Largest single chunk returned by the body source.
      attr_reader :max_read_length

      def initialize
        @reads = 0
        @bytes_read = 0
        @max_read_length = 0
      end

      # @api private
      def record(chunk)
        length = chunk.bytesize
        @reads += 1
        @bytes_read += length
        @max_read_length = length if length > @max_read_length
      end
    end
  end
end
