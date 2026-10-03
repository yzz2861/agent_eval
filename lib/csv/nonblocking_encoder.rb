# frozen_string_literal: true

class CSV
  # Encodes CSV rows for a non-blocking output.
  #
  # The encoder keeps the current encoded row and a byte offset. When the
  # receiver returns +:wait_writable+, call #resume again after the output is
  # writable. Bytes already accepted by the receiver are not sent again.
  #
  # Rows are fetched from a one-time Enumerator only after the current row has
  # been written completely.
  #
  #   encoder = CSV::NonblockingEncoder.new(rows, headers: headers)
  #   loop do
  #     case encoder.resume(socket)
  #     when :wait_writable
  #       socket.wait_writable
  #     when :complete
  #       break
  #     end
  #   end
  #
  # A block may be supplied for a receiver that does not use the
  # <tt>write_nonblock(string, exception: false)</tt> convention. The block
  # must return the number of bytes written, +:wait_writable+, or a permanent
  # error symbol such as +:EPIPE+.
  class NonblockingEncoder
    # Raised when a non-blocking write receiver reports an unrecoverable result.
    class PermanentWriteError < StandardError
    end

    attr_reader :status

    def initialize(rows, **options)
      @rows = case rows
              when Enumerator
                rows
              else
                rows.to_enum(:each)
              end
      @buffer = String.new.force_encoding(Encoding::BINARY)
      @offset = 0
      @status = :active
      @failed = false

      output = Object.new
      buffer = @buffer
      output.define_singleton_method(:<<) do |line|
        buffer << line.b
        self
      end
      @csv = CSV.new(output, **options)
    end

    def complete?
      @status == :complete
    end

    def bytes_pending
      @buffer.bytesize - @offset
    end

    def lineno
      @csv.lineno
    end

    # Writes as many buffered bytes as the receiver accepts now.
    #
    # Returns +:wait_writable+ until the receiver can accept more bytes and
    # +:complete+ after every row has been written. Permanent receiver errors
    # are raised and mark the encoder failed.
    def resume(output = nil, &writer)
      if @failed
        raise PermanentWriteError,
              "non-blocking CSV encoder has failed"
      end
      return @status if complete?
      unless output || writer
        raise ArgumentError, "an output or writer block is required"
      end

      loop do
        fill_buffer if @buffer.empty?
        return @status if complete?

        chunk = @buffer.byteslice(@offset, @buffer.bytesize - @offset)
        result = if writer
                   writer.call(chunk)
                 else
                   output.write_nonblock(chunk, exception: false)
                 end
        count = normalize_result(result, chunk.bytesize)
        @offset += count

        if @offset == @buffer.bytesize
          @buffer.clear
          @offset = 0
        end
      end
    rescue IO::WaitWritable
      @status = :wait_writable
      @status
    rescue StandardError
      @failed = true
      @status = :failed
      raise
    end

    private
    def fill_buffer
      row = @rows.next
    rescue StopIteration
      @status = :complete
    else
      @csv << row
      @status = :active
    end

    def normalize_result(result, bytesize)
      case result
      when :wait_writable
        raise IO::EAGAINWaitWritable, "resource temporarily unavailable"
      when Integer
        if result <= 0 || result > bytesize
          raise PermanentWriteError,
                "invalid non-blocking write result: #{result.inspect}"
        end
        result
      when Symbol
        error_class = Errno.const_get(result) if Errno.const_defined?(result)
        if error_class
          raise error_class
        else
          raise PermanentWriteError,
                "permanent non-blocking write failure: #{result.inspect}"
        end
      else
        raise PermanentWriteError,
              "unsupported non-blocking write result: #{result.inspect}"
      end
    end
  end
end
