require 'net/sftp/errors'

module Net; module SFTP; module Operations

  # A wrapper around an SFTP file handle that was opened in text mode on a
  # server which supports SFTP protocol version 4 (or later) and the
  # "text-seek" extension.
  #
  # Unlike Net::SFTP::Operations::File, this object never exposes a byte
  # position: text mode permits the server to translate line endings and
  # encodings, so a local byte count is not a valid remote offset. Logical
  # lines are read with #gets/#readline, and the server-side position is
  # moved with #seek_line. The two coordinate spaces (logical lines here
  # versus byte offsets in Operations::File) must never be mixed on the
  # same object.
  #
  # Instances are normally created via Net::SFTP::Session#file and the
  # FileFactory#open_text method:
  #
  #   sftp.file.open_text("/path/to/remote.txt") do |file|
  #     file.seek_line(42)
  #     puts file.gets
  #   end
  class TextFile
    # Number of bytes requested in each remote read.
    READ_SIZE = 8192

    # A reference to the Net::SFTP::Session that drives this wrapper.
    attr_reader :sftp

    # The SFTP file handle object that this object wraps.
    attr_reader :handle

    # Number of logical lines that have been returned from the current
    # server-side position (0-based).
    attr_reader :lineno

    # The byte sequence that the server uses to terminate logical lines on
    # the wire, taken from the server's "newline" extension. Defaults to
    # "\n" when the server does not advertise the extension (per the SFTP
    # specification).
    attr_reader :newline

    # Opens +name+ in text mode using the given +sftp+ session. The
    # negotiated protocol version must be 4 or later, otherwise
    # Net::SFTP::NotSupported is raised before any open packet is sent.
    def self.open(sftp, name, flags="r", mode=nil)
      unless sftp.text_mode?
        raise Net::SFTP::NotSupported,
          "text mode requires SFTP protocol version 4 or greater " \
          "(the server negotiated version #{sftp.version.inspect})"
      end

      handle = sftp.open!(name, flags, :permissions => mode, :text => true)
      new(sftp, handle)
    end

    # Creates a new wrapper around an already-opened text-mode +handle+.
    # Prefer TextFile.open or FileFactory#open_text over calling this
    # directly.
    def initialize(sftp, handle)
      @sftp     = sftp
      @handle   = handle
      @buffer   = String.new.force_encoding(Encoding::ASCII_8BIT)
      @offset   = 0
      @lineno   = 0
      @eof      = false
      @invalid  = false
      @partial_newline = nil
      @newline  = determine_newline
    end

    # Returns true if the server advertised the text-seek extension and
    # this object may use #seek_line.
    def seek_supported?
      sftp.supports?(Constants::Extensions::TEXT_SEEK)
    end

    # Asks the server to position the handle at the start of logical line
    # +line+ (0-based). The line number is interpreted by the server in the
    # file's logical line coordinate space; no local byte offsets are used.
    #
    # Raises Net::SFTP::NotSupported if the server did not advertise the
    # text-seek extension. Raises Net::SFTP::StatusException if the server
    # rejects the request (for example, if +line+ is past end of file). In
    # either case any locally buffered data is invalidated: a failed seek
    # leaves the server-side position unspecified, so subsequent reads are
    # refused until a subsequent seek succeeds.
    #
    # Returns the line number that was sought.
    def seek_line(line)
      raise IOError, "closed stream" if handle.nil?
      invalidate_line = Integer(line)
      raise ArgumentError, "line must be non-negative" if invalidate_line < 0
      unless seek_supported?
        invalidate!
        raise Net::SFTP::NotSupported,
          "the server did not advertise the text-seek extension; " \
          "logical line positioning is not available"
      end

      begin
        sftp.text_seek!(handle, invalidate_line)
      rescue Net::SFTP::StatusException
        invalidate!
        raise
      end

      reset!
      @lineno = invalidate_line
      invalidate_line
    end

    # Reads and returns the next logical line, including the trailing
    # newline bytes. If the final line has no trailing newline it is still
    # returned; nil is returned at end of file.
    def gets
      ensure_open!
      return nil if @eof && @buffer.empty? && @partial_newline.nil?

      loop do
        index = @buffer.index(newline)
        if index
          line = consume(index + newline.bytesize)
          @lineno += 1
          return decode(line)
        end

        unless fill
          break if @partial_newline.nil?
          # The last bytes on the wire were merely a newline prefix; treat
          # them as literal content rather than a complete newline.
          @buffer << @partial_newline
          @partial_newline = nil
          break
        end
      end

      return nil if @buffer.empty?

      line = consume(@buffer.bytesize)
      @lineno += 1
      @eof = true
      decode(line)
    end

    # Equivalent to #gets, but raises EOFError at end of file.
    def readline
      line = gets
      raise EOFError, "end of file reached" if line.nil?
      line
    end

    # Yields each remaining logical line to the block. Returns an enumerator
    # when no block is given.
    def each_line
      return enum_for(:each_line) unless block_given?
      while (line = gets)
        yield line
      end
      self
    end
    alias each each_line

    # Returns true once end of file has been reached and no buffered data
    # remains.
    def eof?
      ensure_open!
      @eof && @buffer.empty?
    end

    # Returns the next line number that #seek_line would use to re-read the
    # line most recently returned (0 before anything has been read).
    def tell_line
      lineno
    end

    # Positions the handle at logical line 0. Requires the text-seek
    # extension; see #seek_line.
    def rewind
      seek_line(0)
    end

    # Closes the underlying handle and sets the handle to +nil+. Subsequent
    # operations on this object will fail.
    def close
      sftp.close!(handle)
      @handle = nil
    end

    private

      # Resets all client-side state after a successful open or seek. The
      # next read must start at offset 0 in the data the server streams.
      def reset!
        @buffer = String.new.force_encoding(Encoding::ASCII_8BIT)
        @offset = 0
        @eof = false
        @invalid = false
        @partial_newline = nil
      end

      # Drops all buffered data and marks the object unusable for reading.
      # This is used when a seek fails, because the server-side position is
      # then unknown.
      def invalidate!
        @buffer = String.new.force_encoding(Encoding::ASCII_8BIT)
        @offset = 0
        @eof = false
        @invalid = true
        @partial_newline = nil
      end

      def ensure_open!
        raise IOError, "closed stream" if handle.nil?
        raise IOError, "buffer is invalid after a failed seek; seek to a known line before reading again" if @invalid
      end

      # Removes +length+ bytes from the front of the buffer. Consuming
      # buffered data does not change the next text-mode read offset, which
      # counts bytes the server has delivered and must never be derived from
      # a local logical-line count.
      def consume(length)
        line = @buffer.byteslice(0, length)
        @buffer = @buffer.byteslice(length, @buffer.bytesize - length) ||
                  String.new.force_encoding(Encoding::ASCII_8BIT)
        line
      end

      # Fetches another chunk from the server. In text mode the offset is a
      # running count of bytes delivered since the last open/seek; it is
      # never a logical-line coordinate. A possible partial newline match
      # at the end of the buffer is carried across to the next response so
      # that newline sequences split across packets are recognized, and the
      # offset backs up to the split point.
      def fill
        @partial_newline = nil
        carried = carry_partial_newline!
        offset = carried ? @offset - carried.bytesize : @offset
        data = sftp.read!(handle, offset, READ_SIZE)

        if data.nil?
          @partial_newline = carried if carried
          @eof = true
          return false
        end

        data = data.dup.force_encoding(Encoding::ASCII_8BIT)
        # A compliant server returns data or EOF, never both; tolerate an
        # empty response by treating it as EOF so reads cannot loop forever.
        if data.empty?
          @partial_newline = carried if carried
          @eof = true
          return false
        end

        @buffer = @buffer + carried + data if carried
        @buffer << data unless carried
        @partial_newline = nil
        @offset += data.bytesize
        true
      end

      # If the buffer ends with a prefix of the newline sequence that cannot
      # yet be matched, removes it (and its bytes are not considered
      # consumed) so it can be compared against the next response.
      def carry_partial_newline!
        max = newline.bytesize - 1
        return nil if max.zero? || @buffer.empty?

        max.downto(1) do |length|
          next if length > @buffer.bytesize
          candidate = @buffer.byteslice(-length, length)
          if newline.start_with?(candidate)
            @buffer = @buffer.byteslice(0, @buffer.bytesize - length)
            return candidate
          end
        end
        nil
      end

      # Tags returned lines as UTF-8, which is the character set that text
      # mode guarantees on the wire. Invalid/unknown byte sequences are left
      # intact rather than being replaced.
      def decode(data)
        data.force_encoding(Encoding::UTF_8)
        data
      end

      def determine_newline
        advertised = sftp.extensions[Constants::Extensions::NEWLINE]
        if advertised.nil? || advertised.empty?
          "\n".b
        else
          advertised.dup.force_encoding(Encoding::ASCII_8BIT)
        end
      end
  end

end; end; end
