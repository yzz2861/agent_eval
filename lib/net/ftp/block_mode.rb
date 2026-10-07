# frozen_string_literal: true
#
# = net/ftp/block_mode.rb - FTP block mode (MODE B) codec
#
# Implementation of the block mode data representation of RFC 959.
# Each data block is prefixed with a three byte header: a one byte
# descriptor code followed by the two byte (big endian) byte count of
# the block body.  This file is internal to net/ftp.

unless defined?(Net::FTP)
  raise LoadError, "net/ftp/block_mode must be loaded by net/ftp"
end

module Net
  class FTP
    module BlockMode
      # Length in bytes of a block mode header (descriptor + byte count).
      HEADER_SIZE = 3

      # Maximum byte count expressible in the two byte length field.
      MAX_BLOCK_LENGTH = 65535

      # The last byte of the block is the end of a record.
      DESCRIPTOR_END_OF_RECORD = 0x80

      # The last byte of the block is the end of the file.
      DESCRIPTOR_END_OF_FILE = 0x40

      # The block is suspected of containing errors.
      DESCRIPTOR_SUSPECTED_ERRORS = 0x20

      # The block body is a restart marker rather than file data.
      DESCRIPTOR_RESTART_MARKER = 0x10

      # Bits 1-4 of the descriptor are reserved and must be zero.
      DESCRIPTOR_RESERVED_MASK = 0x0f

      KNOWN_FLAGS = DESCRIPTOR_END_OF_RECORD |
                    DESCRIPTOR_END_OF_FILE |
                    DESCRIPTOR_SUSPECTED_ERRORS |
                    DESCRIPTOR_RESTART_MARKER

      #
      # A decoded block mode event.
      #
      # +type+ is one of:
      # +:data+::           +payload+ contains file data.  The end_of_record?,
      #                     end_of_file? and suspected_errors? predicates
      #                     expose the descriptor flags of the block.
      # +:record+::         +payload+ contains a complete record assembled by
      #                     Net::FTP#retrrecords.
      # +:restart_marker+:: +payload+ contains the printable restart marker.
      #                     Restart markers are never file contents.
      #
      Event = Struct.new(:type, :payload, keyword_init: true) do
        # The raw descriptor flags for +:data+ events coming from a
        # Decoder, or the synthesized flags of +:record+ events.
        attr_accessor :descriptor_flags

        def data? # :nodoc:
          type == :data
        end

        def record? # :nodoc:
          type == :record
        end

        def restart_marker? # :nodoc:
          type == :restart_marker
        end

        # Returns true if the block ends a record.
        def end_of_record?
          (descriptor_flags.to_i & DESCRIPTOR_END_OF_RECORD) != 0
        end

        # Returns true if the block ends the file.
        def end_of_file?
          (descriptor_flags.to_i & DESCRIPTOR_END_OF_FILE) != 0
        end

        # Returns true if the sender marked the block as suspect.
        def suspected_errors?
          (descriptor_flags.to_i & DESCRIPTOR_SUSPECTED_ERRORS) != 0
        end
      end

      # Creates a record event for use with Net::FTP#storrecords.
      def self.record(payload)
        Event.new(type: :record, payload: payload)
      end

      # Creates a restart marker event for use with Net::FTP#storrecords.
      def self.restart_marker(marker)
        Event.new(type: :restart_marker, payload: marker)
      end

      #
      # Encodes one data block.  +flags+ is a combination of the
      # DESCRIPTOR_* constants (DESCRIPTOR_RESTART_MARKER excluded).
      #
      # Raises ArgumentError if the payload does not fit the two byte
      # length field or if the flag combination is invalid.
      #
      def self.encode_data(payload, flags = 0)
        payload = binary_string(payload)
        if payload.bytesize > MAX_BLOCK_LENGTH
          raise ArgumentError,
                "block body too large: #{payload.bytesize} bytes " \
                "(maximum is #{MAX_BLOCK_LENGTH})"
        end
        validate_data_flags(flags)
        encode_header(flags, payload.bytesize) << payload
      end

      #
      # Encodes a restart marker block.  The marker must be a non empty
      # sequence of printable ASCII characters and must fit the length
      # field.  Restart marker blocks always stand alone.
      #
      def self.encode_restart_marker(marker)
        marker = validate_marker(marker)
        encode_header(DESCRIPTOR_RESTART_MARKER, marker.bytesize) << marker
      end

      #
      # Splits records from +records+ into bounded block frames and yields
      # each frame.  Records larger than +blocksize+ span several blocks;
      # only the final block of a record carries the end of record flag.
      # The end of file flag is carried by the final block (merged with
      # end of record when the last record ends there); a zero length
      # end of file block is emitted only when there are no records.
      #
      # +records+ may be any enumerable yielding Strings (treated as
      # records), or Event objects created by ::record or
      # ::restart_marker.
      #
      def self.encode_records(records, blocksize = MAX_BLOCK_LENGTH)
        if !blocksize.is_a?(Integer) || blocksize <= 0 ||
           blocksize > MAX_BLOCK_LENGTH
          raise ArgumentError,
                "blocksize must be between 1 and #{MAX_BLOCK_LENGTH}"
        end
        last_data_frame = nil
        records.each do |item|
          event = coerce_event(item)
          case event.type
          when :record
            flush_frame(last_data_frame) { |frame| yield frame }
            last_data_frame = nil
            encode_record(event.payload, blocksize) do |frame|
              flush_frame(last_data_frame) { |out| yield out }
              last_data_frame = frame
            end
          when :restart_marker
            flush_frame(last_data_frame) { |frame| yield frame }
            last_data_frame = nil
            yield encode_restart_marker(event.payload)
          else
            raise ArgumentError,
                  "unsupported record event: #{event.type.inspect}"
          end
        end
        if last_data_frame
          yield with_eof_flag(last_data_frame)
        else
          yield encode_data("", DESCRIPTOR_END_OF_FILE)
        end
      end

      #
      # Decodes a complete block mode transfer in +string+ and returns
      # the array of Event objects.  Raises Net::FTPProtoError for a
      # truncated header or body, an invalid descriptor, data following
      # the end of file block, or a missing end of file block.
      #
      def self.decode(string)
        decoder = Decoder.new
        events = []
        decoder.feed(string) { |event| events << event }
        decoder.finish
        events
      end

      def self.binary_string(value) # :nodoc:
        String(value).dup.force_encoding(Encoding::ASCII_8BIT)
      end

      def self.validate_data_flags(flags) # :nodoc:
        unless flags.is_a?(Integer) && (flags & ~KNOWN_FLAGS) == 0
          raise ArgumentError, "invalid block descriptor flags: #{flags.inspect}"
        end
        if (flags & DESCRIPTOR_RESTART_MARKER) != 0
          raise ArgumentError,
                "restart marker blocks must be encoded with " \
                "encode_restart_marker"
        end
      end

      def self.validate_marker(marker) # :nodoc:
        marker = binary_string(marker)
        if marker.empty?
          raise ArgumentError, "restart marker must not be empty"
        end
        if marker.bytesize > MAX_BLOCK_LENGTH
          raise ArgumentError,
                "restart marker too long: #{marker.bytesize} bytes " \
                "(maximum is #{MAX_BLOCK_LENGTH})"
        end
        unless marker.bytes.all? { |byte| byte >= 0x20 && byte <= 0x7e }
          raise ArgumentError,
                "restart marker must consist of printable ASCII characters"
        end
        marker
      end

      def self.encode_header(flags, length) # :nodoc:
        [flags, length].pack("Cn")
      end

      def self.encode_record(payload, blocksize) # :nodoc:
        payload = binary_string(payload)
        if payload.empty?
          yield encode_data("", DESCRIPTOR_END_OF_RECORD)
          return
        end
        offset = 0
        loop do
          chunk = payload.byteslice(offset, blocksize)
          break if chunk.nil? || chunk.empty?
          offset += chunk.bytesize
          if offset >= payload.bytesize
            yield encode_data(chunk, DESCRIPTOR_END_OF_RECORD)
            break
          else
            yield encode_data(chunk, 0)
          end
        end
      end

      def self.flush_frame(frame) # :nodoc:
        yield frame if frame
      end

      def self.with_eof_flag(frame) # :nodoc:
        flags = frame.getbyte(0) | DESCRIPTOR_END_OF_FILE
        encode_header(flags, frame.bytesize - HEADER_SIZE) <<
          frame.byteslice(HEADER_SIZE, frame.bytesize - HEADER_SIZE)
      end

      def self.coerce_event(item) # :nodoc:
        case item
        when Event
          item
        when String
          record(item)
        else
          raise ArgumentError,
                "records must be Strings or Net::FTP::BlockMode::Event " \
                "objects: #{item.inspect}"
        end
      end

      #
      # Streaming decoder for block mode transfers.  Feed arbitrary TCP
      # fragments to #feed; complete events are yielded to the given
      # block.  Call #finish after the data connection has been closed to
      # verify that the transfer contained an end of file block.
      #
      class Decoder
        def initialize
          @buffer = String.new.force_encoding(Encoding::ASCII_8BIT)
          @end_of_file = false
        end

        # Returns true once an end of file block has been decoded.
        def end_of_file?
          @end_of_file
        end

        # Feeds an arbitrary fragment of wire data and yields every Event
        # that can be completely decoded from the accumulated buffer.
        def feed(chunk)
          unless chunk.nil?
            @buffer << String(chunk).dup.force_encoding(Encoding::ASCII_8BIT)
          end
          loop do
            if @end_of_file
              unless @buffer.empty?
                raise Net::FTPProtoError,
                      "data received after end of file block"
              end
              return
            end
            return if @buffer.bytesize < HEADER_SIZE
            flags = @buffer.getbyte(0)
            length = (@buffer.getbyte(1) << 8) | @buffer.getbyte(2)
            validate_descriptor(flags)
            total = HEADER_SIZE + length
            return if @buffer.bytesize < total
            @buffer.slice!(0, HEADER_SIZE)
            payload = @buffer.slice!(0, length)
            emit(flags, payload) { |event| yield event }
          end
        end

        # Verifies that a complete transfer was received.  Raises
        # Net::FTPProtoError if a block header or body was truncated or
        # if the end of file block was missing.
        def finish
          if !@buffer.empty?
            raise Net::FTPProtoError,
                  "truncated block at end of data connection"
      end
      unless @end_of_file
        raise Net::FTPProtoError,
              "data connection closed before end of file block"
      end
        end

        private

        def validate_descriptor(flags)
          if (flags & DESCRIPTOR_RESERVED_MASK) != 0 ||
             (flags & ~KNOWN_FLAGS) != 0
            raise Net::FTPProtoError,
                  "invalid block descriptor: 0x%02x" % flags
          end
          if (flags & DESCRIPTOR_RESTART_MARKER) != 0 &&
             flags != DESCRIPTOR_RESTART_MARKER
            raise Net::FTPProtoError,
                  "restart marker block must stand alone: 0x%02x" % flags
          end
        end

        def emit(flags, payload)
          if flags == DESCRIPTOR_RESTART_MARKER
            if payload.empty?
              raise Net::FTPProtoError, "empty restart marker"
            end
            unless payload.bytes.all? { |byte| byte >= 0x20 && byte <= 0x7e }
              raise Net::FTPProtoError,
                    "restart marker contains non-printable characters"
            end
            event = Event.new(type: :restart_marker, payload: payload)
            event.descriptor_flags = flags
            yield event
          else
            if (flags & DESCRIPTOR_END_OF_FILE) != 0
              @end_of_file = true
            end
            event = Event.new(type: :data, payload: payload)
            event.descriptor_flags = flags
            yield event
          end
        end
      end

      private_class_method :binary_string, :validate_data_flags,
                           :validate_marker, :encode_header,
                           :encode_record, :coerce_event, :flush_frame,
                           :with_eof_flag
    end
  end
end
