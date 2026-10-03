# frozen_string_literal: true

require "zlib"

module Net
  class IMAP

    # Buffered byte-oriented IO wrapper that preserves bytes read ahead of the
    # current response.  This is essential for protocol upgrades such as
    # STARTTLS and COMPRESS=DEFLATE: a read that retrieves the end of the
    # plain-text handshake response may also pull the first encrypted or
    # compressed bytes from the underlying socket.
    #
    # Only the IO methods used by the IMAP client are implemented (gets,
    # read, readpartial, print/write, and connection management delegation).
    class BufferedIO # :nodoc: all

      READ_SIZE = 1 << 16

      attr_reader :sock

      def initialize(sock)
        @sock  = sock
        @buf   = String.new(encoding: Encoding::ASCII_8BIT)
        @eof   = false
      end

      # --- read side ---

      # IO#gets-compatible: read up to and including +sep+, limited to +limit+
      # bytes when given.
      def gets(sep = $/, limit = nil)
        return read_all if sep.nil?
        if limit
          return "" unless limit.positive?
          fill(limit) until @eof || @buf.bytesize >= limit || @buf.include?(sep)
          return nil if @buf.empty?
          idx = @buf.index(sep)
          if idx && idx < limit
            return take(idx + sep.bytesize)
          end
          return take(limit)
        end
        fill until @eof || @buf.include?(sep)
        return nil if @buf.empty?
        idx = @buf.index(sep)
        idx ? take(idx + sep.bytesize) : take(@buf.bytesize)
      end

      # IO#read-compatible: with a length, read exactly +length+ bytes (or
      # until EOF); without, read to EOF.
      def read(length = nil, outbuf = nil)
        if length.nil?
          result = read_all
        else
          fill until @eof || @buf.bytesize >= length
          result = @buf.empty? ? nil : take(length)
        end
        if outbuf
          outbuf.replace(result || "")
        else
          result
        end
      end

      def readpartial(maxlen = READ_SIZE, outbuf = nil)
        fill if @buf.empty? && !@eof
        chunk = @buf.empty? ? raise(EOFError) : take(maxlen)
        outbuf ? outbuf.replace(chunk) : chunk
      end

      # --- write side ---

      def print(*args)
        args.each { sock.write(_1.to_s) }
        nil
      end

      def write(str) = sock.write(str)

      # --- delegation ---

      def ssl_socket?
        defined?(OpenSSL::SSL::SSLSocket) && sock.is_a?(OpenSSL::SSL::SSLSocket)
      end

      def to_io    = sock.to_io
      def closed?  = sock.closed?
      def close    = sock.close
      def eof?
        @buf.empty? ? sock.eof? : false
      end

      protected

      attr_reader :buf

      # Move the first +n+ bytes out of the buffer.
      def take(n)
        result = @buf.byteslice(0, n) || String.new(encoding: Encoding::ASCII_8BIT)
        @buf = @buf.byteslice(result.bytesize..) ||
          String.new(encoding: Encoding::ASCII_8BIT)
        result
      end

      def fill(maxlen = nil)
        return if @eof
        want = maxlen ? maxlen - @buf.bytesize : READ_SIZE
        @buf << sock.readpartial([want, READ_SIZE].min) if want.positive?
      rescue EOFError
        @eof = true
      end

      private

      def read_all
        fill until @eof
        take(@buf.bytesize)
      end

    end

    # Compression layer for COMPRESS=DEFLATE (RFC 4978).  Wraps a
    # BufferedIO and adds raw DEFLATE inflate/deflate to the two directions.
    #
    # * Raw DEFLATE media type (window bits = -15), per RFC 4978.
    # * Every write is flushed with Zlib::SYNC_FLUSH, so the peer can decode a
    #   complete command without waiting for the stream to close.
    class DeflateSocket < BufferedIO

      RAW_WINDOW_BITS = -Zlib::MAX_WBITS

      def initialize(sock)
        @deflate = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, RAW_WINDOW_BITS)
        @inflate = Zlib::Inflate.new(RAW_WINDOW_BITS)
        @inbuf   = String.new(encoding: Encoding::ASCII_8BIT)
        @src_eof = false
        super
      end

      # --- compressed write direction ---

      def print(*args)
        args.each { write_compressed(_1.to_s) }
        nil
      end

      def write(str)
        write_compressed(str)
        str.bytesize
      end

      def write_compressed(str)
        sock.write(@deflate.deflate(str, Zlib::SYNC_FLUSH))
      end

      def close
        # Always release the zlib streams, even if the transport is already
        # closed (e.g. on an unexpected disconnect).
        @deflate.close
        @inflate.close
      ensure
        super
      end

      private

      # Pull and inflate the next chunk.  The inflater stores any bytes that
      # belong to an incomplete block internally; on Zlib::BufError (an
      # incomplete raw block at the read boundary), the external buffer is
      # retained and combined with the next read.  Consumed bytes are never
      # replayed, which would corrupt the sliding window.
      def fill(maxlen = nil)
        return if @eof
        if !@src_eof && @inbuf.empty?
          begin
            @inbuf << sock.readpartial(maxlen || READ_SIZE)
          rescue EOFError
            @src_eof = true
          end
        end
        if @inbuf.empty?
          @eof = true
          return
        end
        @buf << @inflate.inflate(@inbuf)
        @inbuf.clear
      rescue Zlib::BufError
        # retain @inbuf; if the source is closed the block was truncated
        @eof = true if @src_eof
      end

    end
  end
end
