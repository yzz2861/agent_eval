# frozen_string_literal: true

module Net
  class IMAP
    class BufferedIO # :nodoc:
      BLOCK_SIZE = 1024 * 16

      def initialize(io)
        @io = io
        @buffer = String.new.b
        @eof = false
      end

      def gets(separator, limit = nil)
        loop do
          position = @buffer.index(separator)
          if position && (!limit || position < limit)
            return read_buffered(position + separator.bytesize)
          end
          if limit && @buffer.bytesize >= limit
            return read_buffered(limit)
          end
          return flush_buffer unless refill.positive?
        end
      end

      def read(length, outbuf = nil)
        until @buffer.bytesize >= length || @eof
          refill
        end
        return if @buffer.empty?
        result = read_buffered([length, @buffer.bytesize].min)
        outbuf ? outbuf.replace(result) : result
      end

      def readpartial(maxlen, outbuf = nil)
        refill if @buffer.empty? && !@eof
        return if @buffer.empty?
        result = read_buffered([maxlen, @buffer.bytesize].min)
        outbuf ? outbuf.replace(result) : result
      end

      def print(*args)
        @io.print(*args)
      end

      def write(data)
        @io.write(data)
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
        @io.close
      end

      def shutdown(*args)
        @io.to_io.shutdown(*args)
      end

      private

      def refill
        return 0 if @eof
        @buffer << read_more
        @buffer.bytesize
      rescue EOFError
        @eof = true
        0
      end

      def read_more
        @io.readpartial(BLOCK_SIZE)
      end

      def flush_buffer
        return if @buffer.empty?
        read_buffered(@buffer.bytesize)
      end

      def read_buffered(length)
        @buffer.slice!(0, length)
      end
    end
  end
end
