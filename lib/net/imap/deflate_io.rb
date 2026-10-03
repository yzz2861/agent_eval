# frozen_string_literal: true

require "zlib"
require_relative "buffered_io"

module Net
  class IMAP
    class DeflateIO # :nodoc:
      def initialize(io)
        @io = io
        @deflater = Zlib::Deflate.new(
          Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS
        )
      end

      def print(*args)
        args.each { write(_1) }
      end

      def write(data)
        compressed = @deflater.deflate(data.to_s, Zlib::SYNC_FLUSH)
        @io.write(compressed)
      end

      def flush
        @io.flush
      end

      def to_io
        @io.to_io
      end

      def closed?
        @io.closed?
      end

      def close
        @deflater.close
      end
    end

    class InflateIO < BufferedIO # :nodoc:
      def initialize(io)
        super(io)
        @io = io
        @inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      end

      def close
        @inflater.close
      end

      private

      def read_more
        loop do
          compressed = @io.readpartial(BLOCK_SIZE)
          begin
            decompressed = @inflater.inflate(compressed)
          rescue Zlib::BufError
            next
          end
          return decompressed unless decompressed.empty?
        end
      rescue Zlib::DataError => error
        raise EOFError, error.message
      end
    end
  end
end
