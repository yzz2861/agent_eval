# frozen_string_literal: true

module JWT
  module Streaming
    # Reads a body source in fixed-size chunks without ever buffering the whole
    # content. The source only needs to respond to `read(length)`; it is never
    # rewound, so non-rewindable streams (pipes, sockets, uploads) work as-is.
    class BodyReader
      def initialize(io, chunk_size:, stats: Stats.new)
        unless io.respond_to?(:read)
          raise ArgumentError, 'Streaming body must respond to #read'
        end
        raise ArgumentError, 'chunk_size must be a positive Integer' unless chunk_size.is_a?(Integer) && chunk_size.positive?

        @io = io
        @chunk_size = chunk_size
        @stats = stats
      end

      attr_reader :stats

      # Yields each raw chunk exactly as read from the body source.
      def each
        loop do
          chunk = @io.read(@chunk_size)
          break if chunk.nil?

          unless chunk.is_a?(String)
            raise JWT::StreamReadError, "Body source returned a #{chunk.class}, expected a String"
          end

          @stats.record(chunk)
          yield chunk
        end
      rescue StandardError => e
        raise e if e.is_a?(JWT::StreamReadError)

        raise JWT::StreamReadError, "Failed to read streaming body: #{e.message}"
      end
    end
  end
end
