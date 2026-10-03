# frozen_string_literal: true

class CSV
  # \CSV::NonBlockingWriter encodes rows into \CSV text and writes the
  # encoded bytes to a non-blocking receiver: any object that responds to
  # <tt>write_nonblock(chunk, exception: false)</tt>, such as an \IO in
  # non-blocking mode or an \OpenSSL socket.
  #
  # The writer is resumable.  When the receiver is temporarily unable to
  # accept more bytes, #write returns <tt>:wait_writable</tt> while
  # keeping the exact byte position.  Calling #write again -- for example
  # after <tt>IO.select</tt> or \IO#wait_writable reports the receiver as
  # writable -- resumes from that position.  Bytes are discarded only
  # after the receiver has confirmed them, so a short write is never
  # duplicated on resume, even when it ends in the middle of a quoted
  # field, an escaped quote character, or a multi-byte character.
  #
  # Rows are pulled lazily from the given one-shot +rows+ enumerator: the
  # next row is not consumed until the current row has been written
  # completely.  When <tt>write_headers: true</tt> is given, the header
  # line is encoded exactly once, before the first row.
  #
  # All other keyword options are the usual \CSV generating options and
  # behave exactly as they do for \CSV.new / \CSV.generate:
  # <tt>:col_sep</tt>, <tt>:row_sep</tt>, <tt>:quote_char</tt>,
  # <tt>:headers</tt>, <tt>:write_headers</tt>, <tt>:force_quotes</tt>,
  # <tt>:encoding</tt>, <tt>:write_converters</tt>, and so on.
  #
  # Example:
  #   rows = [["1", "Alice"], ["2", "Bob"]].each
  #   writer = CSV::NonBlockingWriter.new(rows,
  #                                       headers: ["id", "name"],
  #                                       write_headers: true)
  #   loop do
  #     case writer.write(socket)
  #     when :wait_writable
  #       socket.wait_writable
  #     when :done
  #       break
  #     end
  #   end
  #
  # Only temporary back-pressure is reported as <tt>:wait_writable</tt>.
  # Permanent receiver failures (for example \Errno::EPIPE, or \IOError
  # on a closed stream) are raised from #write as-is.
  class NonBlockingWriter
    # The number of rows consumed from the row enumerator so far.
    attr_reader :lineno

    def initialize(rows, **options)
      @rows = rows.respond_to?(:next) ? rows : rows.to_enum
      @lineno = 0
      string = +""
      encoding = options[:encoding]
      string.force_encoding(encoding) if encoding
      @io = StringIO.new(string)
      @csv = CSV.new(@io, **options)
      @offset = 0
      @done = false
    end

    # Writes as much pending output as +receiver+ currently accepts.
    #
    # Returns <tt>:wait_writable</tt> when the receiver is temporarily
    # unable to accept more bytes; call #write again once the receiver is
    # writable to resume at the exact byte position.  Returns <tt>:done</tt>
    # when every row has been encoded and flushed.  Permanent receiver
    # errors are raised.
    def write(receiver)
      loop do
        fill_buffer if @offset == @io.string.bytesize
        return :done if @done

        chunk = @io.string.byteslice(@offset..-1)
        begin
          written = receiver.write_nonblock(chunk, exception: false)
        rescue IO::WaitWritable
          return :wait_writable
        end
        return :wait_writable if written == :wait_writable
        @offset += written
      end
    end

    # Whether every row has been encoded and flushed to the receiver.
    def done?
      @done
    end

    private

    def fill_buffer
      return if @done

      @io.truncate(0)
      @io.rewind
      @offset = 0
      begin
        row = @rows.next
      rescue StopIteration
        @done = true
      else
        @csv << row
        @lineno += 1
      end
    end
  end
end
