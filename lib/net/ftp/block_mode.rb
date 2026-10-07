# frozen_string_literal: true

module Net
  class FTP < Protocol
    # Block Mode (MODE B) data transfer support, as specified in RFC 959
    # section 3.4 (transmission modes).
    #
    # A block mode data connection is a sequence of independent blocks.  Each
    # block starts with a three-byte header: a one-byte descriptor followed by
    # a 16-bit big-endian byte count, followed by exactly that many data bytes.
    #
    # The descriptor flags are:
    #
    # 128 (0x80):: restart marker.  The block data is a printable-character
    #            marker, never file content.
    # 64  (0x40):: end of data (EOF).  The data connection closes after this
    #             block.
    # 32  (0x20):: end of record (EOR).
    # 16  (0x10):: the sender detected an error.
    #
    # Headers and block bodies may be split arbitrarily by TCP, and a single
    # record may span any number of blocks.  The codec in this module performs
    # the required stream reassembly and descriptor validation.
    module BlockMode
      # Size of a block header, in bytes (descriptor + byte count).
      HEADER_SIZE = 3

      # Maximum size of a single block body, imposed by the 16-bit count.
      MAX_BLOCK_SIZE = 65535

      RESTART_MARKER = 0x80
      END_OF_DATA = 0x40
      END_OF_RECORD = 0x20
      BLOCK_ERROR = 0x10

      DESCRIPTOR_MASK = RESTART_MARKER | END_OF_DATA |
                        END_OF_RECORD | BLOCK_ERROR

      PRINTABLE_MARKER = /\A[\x20-\x7e]+\z/n

      # Builds a block mode data stream from records, arbitrary byte chunks,
      # and restart markers.
      #
      # Every emitted block body is bounded by the encoder's block size (at
      # most MAX_BLOCK_SIZE bytes), and +finish+ always emits the end-of-data
      # block so that a clean upload is distinguishable from an aborted one.
      class BlockEncoder
        # The maximum number of data bytes written into one block.
        attr_reader :block_size

        # Creates an encoder writing framed blocks to +output+ (an IO-like
        # object responding to #write).
        def initialize(output, block_size: MAX_BLOCK_SIZE)
          unless block_size.is_a?(Integer) &&
                 block_size >= 1 && block_size <= MAX_BLOCK_SIZE
            raise ArgumentError,
                  "block_size must be an Integer between 1 and #{MAX_BLOCK_SIZE}"
          end
          @output = output
          @block_size = block_size
          @pending = String.new(encoding: Encoding::ASCII_8BIT)
          @pending_eor = false
          @eof_sent = false
          @finished = false
        end

        # Returns +true+ after #finish has been called.
        def closed?
          @finished
        end

        # Frames arbitrary file bytes.  Bytes may belong to the middle of a
        # record; record boundaries are marked with #write_record.
        def write(data)
          ensure_open
          data = String(data).b
          @pending.concat(data)
          flush_pending(false)
          data.bytesize
        end

        # Frames one record.  The last emitted block carrying the record's
        # bytes gets the end-of-record flag (an empty EOR block is emitted
        # when the record length is an exact multiple of the block size).
        def write_record(record)
          ensure_open
          record = String(record).b
          @pending.concat(record)
          @pending_eor = true
          flush_pending(false)
          record.bytesize
        end

        # Frames a restart marker.  Markers must be non-empty printable ASCII
        # and are delivered separately from file data.
        def write_restart_marker(marker)
          ensure_open
          marker = String(marker).b
          unless PRINTABLE_MARKER.match?(marker)
            raise ArgumentError,
                  "restart marker must be non-empty printable ASCII"
          end
          while @pending.bytesize >= @block_size
            emit(0, @pending.slice!(0, @block_size))
          end
          unless @pending.empty?
            emit(0, @pending.slice!(0, @pending.bytesize))
          end
          emit(RESTART_MARKER, marker)
          marker.bytesize
        end

        # Flushes all buffered data and emits the end-of-data block.  Raises
        # IOError when called more than once.
        def finish
          ensure_open
          flush_pending(true)
          unless @eof_sent
            emit(END_OF_DATA, String.new(encoding: Encoding::ASCII_8BIT))
          end
          @finished = true
          nil
        end

        private

        def ensure_open
          raise IOError, "block encoder is closed" if @finished
        end

        def flush_pending(final)
          if @pending_eor
            while @pending.bytesize >= @block_size
              emit(0, @pending.slice!(0, @block_size))
            end
            descriptor = END_OF_RECORD
            descriptor |= END_OF_DATA if final
            emit(descriptor, @pending.slice!(0, @pending.bytesize))
            @pending_eor = false
          else
            while @pending.bytesize >= @block_size
              emit(0, @pending.slice!(0, @block_size))
            end
            if final && !@pending.empty?
              emit(END_OF_DATA, @pending.slice!(0, @pending.bytesize))
            end
          end
        end

        def emit(descriptor, data)
          @output.write([descriptor, data.bytesize].pack("Cn"))
          @output.write(data) unless data.empty?
          @eof_sent = true if (descriptor & END_OF_DATA) != 0
        end
      end

      # Reassembles a block mode data stream delivered in arbitrary chunks.
      #
      # Chunks are passed to #feed, which yields events as soon as complete
      # blocks arrive:
      #
    # +:data+:: file bytes (mode +:bytes+).
      # +:record+:: a complete record (mode +:records+, the default).
      # +:block+:: +[descriptor, body]+ for a data block (mode +:blocks+).
      # +:restart_marker+:: a restart marker, never part of the file data.
      # +:eof+:: emitted once with +nil+ when the end-of-data block arrives.
      #
      # #finish must be called when the data connection has closed; it raises
      # FTPBlockTruncated if no end-of-data block was seen.
      class BlockDecoder
        # The event mode given to #new.
        attr_reader :mode

        # Creates a decoder.  +mode+ is one of +:records+ (records are
        # reassembled across blocks), +:bytes+ (file bytes only), or
        # +:blocks+ (raw descriptor/body pairs).
        def initialize(mode: :records)
          unless [:records, :bytes, :blocks].include?(mode)
            raise ArgumentError,
                  "mode must be :records, :bytes, or :blocks"
          end
          @mode = mode
          @buffer = String.new(encoding: Encoding::ASCII_8BIT)
          @record = String.new(encoding: Encoding::ASCII_8BIT)
          @record_pending = false
          @eof = false
        end

        # Drains an IO-like data connection until it is half-closed,
        # forwarding each generated event to the given block.
        def feed_stream(input, read_size: 65536, &block)
          while chunk = input.read(read_size)
            feed(chunk, &block)
          end
          self
        end

        # Returns +true+ once the end-of-data block has been processed.
        def eof?
          @eof
        end

        # Feeds one arbitrary chunk read from the data connection and yields
        # zero or more events.  Returns the decoder.
        def feed(chunk, &block)
          raise ArgumentError, "a block is required" unless block
          if @eof && !String(chunk).empty?
            raise FTPBlockDataAfterEOF,
                  "data received after end-of-data block"
          end
          @buffer.concat(String(chunk).b)
          loop do
            break if @buffer.bytesize < HEADER_SIZE
            descriptor = @buffer.getbyte(0)
            count = (@buffer.getbyte(1) << 8) | @buffer.getbyte(2)
            frame_size = HEADER_SIZE + count
            break if @buffer.bytesize < frame_size
            @buffer.slice!(0, HEADER_SIZE)
            body = @buffer.slice!(0, count)
            process_block(descriptor, body, block)
            if @eof
              unless @buffer.empty?
                raise FTPBlockDataAfterEOF,
                      "data received after end-of-data block"
              end
              break
            end
          end
          self
        end

        # Validates end-of-stream state after the data connection closed.
        def finish
          unless @eof
            raise FTPBlockTruncated,
                  "data connection closed before end-of-data block"
          end
          self
        end

        private

        def process_block(descriptor, body, block)
          flags = descriptor & DESCRIPTOR_MASK
          unless descriptor & 0x0f == 0
            raise FTPBlockProtocolError,
                  format("reserved descriptor bits set: 0x%02x", descriptor)
          end
          if (flags & BLOCK_ERROR) != 0
            unless flags == BLOCK_ERROR
              raise FTPBlockProtocolError,
                    format("invalid descriptor flag combination: 0x%02x",
                           descriptor)
            end
            message = "block error reported by sender"
            message += ": #{body.b}" unless body.empty?
            raise FTPBlockError, message
          end
          if (flags & RESTART_MARKER) != 0
            unless flags == RESTART_MARKER
              raise FTPBlockProtocolError,
                    format("invalid descriptor flag combination: 0x%02x",
                           descriptor)
            end
            unless PRINTABLE_MARKER.match?(body)
              raise FTPBlockProtocolError, "malformed restart marker"
            end
            block.call(:restart_marker, body)
            return
          end

          eor = (flags & END_OF_RECORD) != 0
          eof = (flags & END_OF_DATA) != 0
          if body.empty? && !eor && !eof
            raise FTPBlockProtocolError,
                  "zero-length data block without EOR or EOF"
          end

          case @mode
          when :blocks
            block.call(:block, [descriptor, body])
            block.call(:eof, nil) if eof
          when :bytes
            block.call(:data, body) unless body.empty?
            block.call(:eof, nil) if eof
          when :records
            unless body.empty?
              @record.concat(body)
              @record_pending = true
            end
            if eor
              block.call(:record, @record)
              @record = String.new(encoding: Encoding::ASCII_8BIT)
              @record_pending = false
            end
            if eof
              if @record_pending
                block.call(:record, @record)
                @record = String.new(encoding: Encoding::ASCII_8BIT)
                @record_pending = false
              end
              block.call(:eof, nil)
            end
          end

          @eof = true if eof
        end
      end

    end
  end
end
