require 'net/ssh/loggable'

module Net; module SFTP; module Operations

  # A wrapper around an SFTP file handle that was opened in text mode (see
  # Net::SFTP::Session#open_text), exposing a line-oriented interface for
  # reading the remote file. Unlike Operations::File, positions are
  # expressed as logical line numbers (via #seek_line), never as byte
  # offsets: the remote newline sequence may be multiple bytes, and the
  # server is the only authority on where each line begins.
  #
  # A reader is usually created via the Net::SFTP::Operations::FileFactory:
  #
  #   reader = sftp.file.open_text("/path/to/remote")
  #   reader.seek_line(100)
  #   puts reader.gets
  #   reader.close
  #
  # The server must implement version 4 or newer of the SFTP protocol and
  # advertise the "text-seek" extension; otherwise the factory will raise
  # NotImplementedError instead of guessing at line offsets.
  class TextReader
    include Net::SSH::Loggable

    # The newline sequence to assume if the server did not advertise one
    # via the "newline" extension.
    DEFAULT_NEWLINE = "\n"

    # The number of bytes to request from the server at a time.
    CHUNK_SIZE = 8192

    # A reference to the Net::SFTP::Session instance that drives this reader
    attr_reader :sftp

    # The SFTP file handle object that this reader wraps
    attr_reader :handle

    # The newline sequence in effect for this file, as advertised by the
    # server (or DEFAULT_NEWLINE if the server did not say)
    attr_reader :newline

    # The zero-based number of the line that the next call to #gets will
    # return
    attr_reader :lineno

    # Creates a new reader that encapsulates the given +handle+ (such as
    # would be returned by Net::SFTP::Session#open_text!). The +sftp+
    # parameter must be the same Net::SFTP::Session instance that opened
    # the file. +newline+ should be the newline sequence advertised by the
    # server, or nil to assume a single line-feed.
    def initialize(sftp, handle, newline=nil)
      @sftp    = sftp
      @handle  = handle
      @newline = (newline.nil? || newline.empty?) ? DEFAULT_NEWLINE.dup : newline.dup
      @newline.force_encoding(Encoding::BINARY)
      @lineno  = 0
      # Remote byte offset of the start of the line that #gets will return
      # next, and of the first unconsumed byte in @buffer.
      @line_offset = 0
      @buffer  = "".dup.force_encoding(Encoding::BINARY)
      @eof     = false
    end

    # Text readers are positioned by logical line number only. Byte-based
    # positioning (as offered by Operations::File#pos=) is deliberately not
    # available here, because local byte counts cannot be mapped reliably
    # onto remote offsets when newline translation is in effect. Always
    # raises ArgumentError; use #seek_line instead.
    def pos=(offset)
      raise ArgumentError, "byte offsets are not a valid coordinate for a text reader; use #seek_line to position by logical line number"
    end

    # Asks the server to reposition the reader to the start of the
    # (zero-based) logical line +line_number+, using the "text-seek"
    # extension. Returns +line_number+ on success.
    #
    # If the server cannot perform the seek, the underlying exception is
    # allowed to propagate; in that case the read buffer is invalidated and
    # the reader is left positioned at the line it was on before the failed
    # seek, so subsequent reads remain consistent.
    def seek_line(line_number)
      line_number = Integer(line_number)
      raise ArgumentError, "line number must not be negative" if line_number < 0

      begin
        new_offset = sftp.text_seek!(handle, line_number)
      rescue Exception
        invalidate_buffer!
        raise
      end

      @line_offset = new_offset
      @lineno = line_number
      invalidate_buffer!
      line_number
    end

    # Reads the next logical line from the remote file, including the
    # trailing newline sequence (if any--the last line of the file may not
    # be newline-terminated). Returns +nil+ if the end of the file has
    # already been reached. Newline sequences that straddle server
    # responses are recognized incrementally, and empty lines are returned
    # as just the newline sequence.
    def gets
      loop do
        at = @buffer.index(@newline)
        if at
          finish = at + @newline.bytesize
          line, @buffer = @buffer[0, finish], @buffer[finish..-1]
          @line_offset += line.bytesize
          @lineno += 1
          return line
        elsif !fill
          return nil if @buffer.empty?
          line, @buffer = @buffer, "".dup.force_encoding(Encoding::BINARY)
          @line_offset += line.bytesize
          @lineno += 1
          return line
        end
      end
    end

    # Same as #gets, but raises EOFError if the end of the file is reached
    # before any data could be read.
    def readline
      line = gets
      raise EOFError, "end of file reached" if line.nil?
      line
    end

    # Yields each remaining line of the file to the block. Returns an
    # enumerator if no block is given.
    def each_line
      return enum_for(:each_line) unless block_given?
      while (line = gets)
        yield line
      end
      self
    end

    # Returns true if the end of the remote file has been encountered and
    # no buffered data remains. A successful #seek_line resets this flag.
    def eof?
      @eof && @buffer.empty?
    end

    # Closes the underlying file handle and sets it to +nil+. Subsequent
    # operations on this object will fail.
    def close
      sftp.close!(handle)
      @handle = nil
    end

    private

      # Discards any buffered data and clears the EOF flag. Called whenever
      # the remote position may have changed (or become unknown), so that
      # stale bytes are never attributed to the wrong line.
      def invalidate_buffer!
        @buffer = "".dup.force_encoding(Encoding::BINARY)
        @eof = false
      end

      # Fetches the next chunk of data from the server, appending it to the
      # buffer. Returns +true+ if data was read, and +false+ if the server
      # reported EOF before any data could be read.
      def fill
        data = sftp.read!(handle, @line_offset + @buffer.bytesize, CHUNK_SIZE)

        if data.nil?
          @eof = true
          return false
        end

        @buffer << data
        true
      end
  end

end; end; end
