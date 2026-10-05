# frozen_string_literal: true

require 'zlib'

module Faraday
  # Amazon EventStream (application/vnd.amazon.eventstream) framing support.
  #
  # The wire format frames every message as:
  #
  #   [total length: 4][headers length: 4][prelude CRC32: 4]
  #   [typed headers][payload][message CRC32: 4]
  #
  # {EventStream::Decoder} turns an arbitrarily chunked byte stream into
  # fully validated {EventStream::Message} objects. The prelude CRC is
  # verified before its length fields are trusted, and a message is only
  # handed to the caller after its message CRC has been verified too.
  module EventStream
    # Bytes in a message prelude: total length + headers length + prelude CRC.
    PRELUDE_LENGTH = 12
    # Bytes in the trailing message CRC.
    MESSAGE_CRC_LENGTH = 4
    # Smallest possible message: prelude plus message CRC, no headers/payload.
    MIN_MESSAGE_LENGTH = PRELUDE_LENGTH + MESSAGE_CRC_LENGTH

    # Header value types defined by the EventStream protocol.
    HEADER_TYPE_BOOL_TRUE = 0
    HEADER_TYPE_BOOL_FALSE = 1
    HEADER_TYPE_BYTE = 2
    HEADER_TYPE_SHORT = 3
    HEADER_TYPE_INTEGER = 4
    HEADER_TYPE_LONG = 5
    HEADER_TYPE_BYTES = 6
    HEADER_TYPE_STRING = 7
    HEADER_TYPE_TIMESTAMP = 8
    HEADER_TYPE_UUID = 9

    # A single decoded and fully validated EventStream message.
    class Message
      # @return [Hash{String => Object}] decoded headers. Headers whose names
      #   are not known to Faraday are legal and preserved as-is.
      attr_reader :headers

      # @return [String] raw (binary) payload bytes.
      attr_reader :payload

      def initialize(headers:, payload:)
        @headers = headers.freeze
        @payload = payload.freeze
      end

      def ==(other)
        other.is_a?(Message) && headers == other.headers && payload == other.payload
      end
      alias eql? ==

      def inspect
        "#<#{self.class} headers=#{headers.inspect} payload=#{payload.bytesize} bytes>"
      end
    end

    # Base class for EventStream decoding errors.
    #
    # Carries the sequence number of the message being decoded and the
    # absolute byte offset in the stream where the problem was detected.
    # Payload bytes are never included in the error message.
    class Error < Faraday::Error
      # @return [Integer] 0-based index of the message being decoded.
      attr_reader :message_index

      # @return [Integer] absolute byte offset in the stream.
      attr_reader :byte_offset

      def initialize(message, message_index:, byte_offset:)
        @message_index = message_index
        @byte_offset = byte_offset
        super("#{message} (message #{message_index}, byte #{byte_offset})")
      end
    end

    # The prelude CRC did not match the prelude bytes.
    class PreludeCrcError < Error; end

    # The message CRC did not match the message bytes.
    class MessageCrcError < Error; end

    # The stream ended in the middle of a message.
    class TruncationError < Error; end

    # The frame structure itself violates the protocol.
    class ProtocolError < Error; end

    # A header value type byte outside the protocol-defined 0-9 range.
    class InvalidHeaderTypeError < ProtocolError; end

    # Incrementally decodes an Amazon EventStream byte stream.
    #
    # Chunks of any size may be fed; complete messages are emitted as soon as
    # they are fully buffered and validated. Call {#finish} at end of stream
    # to ensure no partial message is left over.
    #
    # @example
    #   decoder = Faraday::EventStream::Decoder.new
    #   decoder.feed(chunk) { |message| handle(message) }
    #   decoder.finish
    class Decoder
      # @return [Integer] index of the message currently at the head of the
      #   buffer, i.e. the number of messages delivered so far.
      attr_reader :message_index

      def initialize
        @buffer = +''
        @message_index = 0
        @message_offset = 0 # absolute stream offset of the buffered message
      end

      # Feeds a chunk of the stream, returning (and optionally yielding) every
      # message that became complete and validated with this chunk.
      #
      # @param chunk [String] raw bytes, may split a message at any point.
      # @yieldparam message [Faraday::EventStream::Message]
      # @return [Array<Faraday::EventStream::Message>]
      def feed(chunk)
        @buffer << chunk
        messages = []
        while (message = next_message)
          messages << message
          yield message if block_given?
        end
        messages
      end
      alias call feed

      # Signals the end of the stream.
      #
      # @raise [Faraday::EventStream::TruncationError] if a partial message
      #   remains buffered.
      # @return [nil]
      def finish
        return if @buffer.empty?

        raise TruncationError.new(
          "stream ended with #{@buffer.bytesize} byte(s) of an incomplete message",
          message_index: @message_index,
          byte_offset: @message_offset + @buffer.bytesize
        )
      end

      private

      def next_message
        return if @buffer.bytesize < PRELUDE_LENGTH

        total_length, headers_length = read_prelude
        return if @buffer.bytesize < total_length

        extract_message(total_length, headers_length)
      end

      # The prelude CRC is verified before the length fields are trusted.
      def read_prelude
        total_length, headers_length, expected_crc = @buffer.unpack('N3')
        actual_crc = Zlib.crc32(@buffer.byteslice(0, 8))
        unless actual_crc == expected_crc
          raise PreludeCrcError.new('prelude CRC mismatch',
                                    message_index: @message_index,
                                    byte_offset: @message_offset)
        end
        if total_length < MIN_MESSAGE_LENGTH
          raise ProtocolError.new("invalid total length #{total_length}",
                                  message_index: @message_index,
                                  byte_offset: @message_offset)
        end
        if headers_length > total_length - MIN_MESSAGE_LENGTH
          raise ProtocolError.new('headers length exceeds total length',
                                  message_index: @message_index,
                                  byte_offset: @message_offset + 4)
        end
        [total_length, headers_length]
      end

      def extract_message(total_length, headers_length)
        raw = @buffer.byteslice(0, total_length)
        verify_message_crc(raw, total_length)

        headers = parse_headers(raw.byteslice(PRELUDE_LENGTH, headers_length) || +'')
        payload_offset = PRELUDE_LENGTH + headers_length
        payload = raw.byteslice(payload_offset,
                                total_length - payload_offset - MESSAGE_CRC_LENGTH) || +''

        @buffer = @buffer.byteslice(total_length..-1) || +''
        @message_offset += total_length
        @message_index += 1
        Message.new(headers: headers, payload: payload)
      end

      def verify_message_crc(raw, total_length)
        crc_offset = total_length - MESSAGE_CRC_LENGTH
        expected_crc = raw.byteslice(crc_offset, MESSAGE_CRC_LENGTH).unpack1('N')
        actual_crc = Zlib.crc32(raw.byteslice(0, crc_offset))
        return if actual_crc == expected_crc

        raise MessageCrcError.new('message CRC mismatch',
                                  message_index: @message_index,
                                  byte_offset: @message_offset + crc_offset)
      end

      def parse_headers(data)
        headers = {}
        pos = 0
        while pos < data.bytesize
          name, pos = read_header_name(data, pos)
          type = data.getbyte(pos)
          if type.nil?
            raise ProtocolError.new('header value type missing',
                                    message_index: @message_index,
                                    byte_offset: header_offset(pos))
          end
          value, pos = read_header_value(type, data, pos + 1)
          headers[name] = value
        end
        headers
      end

      def read_header_name(data, pos)
        name_length = data.getbyte(pos)
        bytes, finish = read_bytes(data, pos + 1, name_length, 'header name')
        [bytes.force_encoding(Encoding::UTF_8), finish]
      end

      # Decodes every value type defined by the protocol. A type byte outside
      # the 0-9 range is illegal and raises InvalidHeaderTypeError; header
      # names unknown to Faraday are legal and simply kept in the hash.
      def read_header_value(type, data, pos)
        case type
        when HEADER_TYPE_BOOL_TRUE then [true, pos]
        when HEADER_TYPE_BOOL_FALSE then [false, pos]
        when HEADER_TYPE_BYTE then read_signed(data, pos, 1)
        when HEADER_TYPE_SHORT then read_unpacked(data, pos, 2, 's>')
        when HEADER_TYPE_INTEGER then read_unpacked(data, pos, 4, 'l>')
        when HEADER_TYPE_LONG then read_unpacked(data, pos, 8, 'q>')
        when HEADER_TYPE_BYTES then read_byte_sequence(data, pos)
        when HEADER_TYPE_STRING then read_string(data, pos)
        when HEADER_TYPE_TIMESTAMP then read_timestamp(data, pos)
        when HEADER_TYPE_UUID then read_uuid(data, pos)
        else
          raise InvalidHeaderTypeError.new("invalid header value type #{type}",
                                           message_index: @message_index,
                                           byte_offset: header_offset(pos - 1))
        end
      end

      def read_signed(data, pos, size)
        bytes, finish = read_bytes(data, pos, size, 'header value')
        value = bytes.unpack1('C')
        value -= 256 if value > 127
        [value, finish]
      end

      def read_unpacked(data, pos, size, directive)
        bytes, finish = read_bytes(data, pos, size, 'header value')
        [bytes.unpack1(directive), finish]
      end

      def read_byte_sequence(data, pos)
        length_bytes, pos = read_bytes(data, pos, 2, 'header value length')
        read_bytes(data, pos, length_bytes.unpack1('n'), 'header value')
      end

      def read_string(data, pos)
        bytes, finish = read_byte_sequence(data, pos)
        [bytes.force_encoding(Encoding::UTF_8), finish]
      end

      def read_timestamp(data, pos)
        millis, finish = read_unpacked(data, pos, 8, 'q>')
        [Time.at(Rational(millis, 1000)).utc, finish]
      end

      def read_uuid(data, pos)
        bytes, finish = read_bytes(data, pos, 16, 'header value')
        [bytes.unpack('H8H4H4H4H12').join('-'), finish]
      end

      def read_bytes(data, pos, length, what)
        finish = pos + length
        if finish > data.bytesize
          raise ProtocolError.new("#{what} overruns the headers section",
                                  message_index: @message_index,
                                  byte_offset: header_offset(pos))
        end
        [data.byteslice(pos, length), finish]
      end

      def header_offset(pos)
        @message_offset + PRELUDE_LENGTH + pos
      end
    end
  end
end
