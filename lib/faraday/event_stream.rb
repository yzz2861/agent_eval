# frozen_string_literal: true

require 'zlib'

module Faraday
  # Streaming decoder for Amazon EventStream messages.
  module EventStream
    PRELUDE_LENGTH = 8
    PRELUDE_CRC_LENGTH = 4
    MESSAGE_CRC_LENGTH = 4
    FIXED_FRAME_LENGTH = PRELUDE_LENGTH + PRELUDE_CRC_LENGTH + MESSAGE_CRC_LENGTH

    MAX_HEADERS_BYTE_LENGTH = 128 * 1024 - 13
    MAX_PAYLOAD_BYTE_LENGTH = 16 * 1024 * 1024 - 1
    MAX_TOTAL_BYTE_LENGTH =
      24 * 1024 * 1024

    HEADER_TYPES = {
      0 => :bool_true,
      1 => :bool_false,
      2 => :byte,
      3 => :short,
      4 => :integer,
      5 => :long,
      6 => :byte_array,
      7 => :string,
      8 => :timestamp,
      9 => :uuid
    }.freeze

    # Base error for messages that do not follow the EventStream framing rules.
    class Error < Faraday::Error
      attr_reader :message_number, :byte_position

      def initialize(message, message_number:, byte_position:)
        @message_number = message_number
        @byte_position = byte_position
        super(message)
      end

      alias byte_offset byte_position
      alias position byte_position
    end

    class ProtocolError < Error; end
    class TruncatedMessageError < ProtocolError; end
    class PreludeCrcError < ProtocolError; end
    class MessageCrcError < ProtocolError; end
    class InvalidLengthError < ProtocolError; end
    class InvalidTotalLengthError < InvalidLengthError; end
    class InvalidHeaderLengthError < InvalidLengthError; end
    class InvalidHeadersLengthError < InvalidHeaderLengthError; end
    class InvalidPayloadLengthError < InvalidLengthError; end
    class InvalidHeaderError < ProtocolError; end
    class InvalidHeaderTypeError < ProtocolError; end
    class UnknownHeaderTypeError < ProtocolError; end
    class InvalidHeaderValueError < ProtocolError; end

    # A typed EventStream header value.
    class HeaderValue
      attr_reader :type, :type_code, :value

      def initialize(type, type_code, value)
        @type = type
        @type_code = type_code
        @value = value
      end
    end
    Header = HeaderValue

    # A complete, verified EventStream message.
    class Message
      attr_reader :headers, :payload

      def initialize(headers, payload)
        @headers = headers.freeze
        @payload = payload.dup.freeze
      end

      def [](header_name)
        headers[header_name]&.value
      end
    end

    # Buffers arbitrary response chunks and yields complete, verified messages.
    class Decoder
      attr_reader :message_count, :received_bytes

      def initialize(on_message = nil, &block)
        @on_message = on_message || block
        unless @on_message.respond_to?(:call)
          raise ArgumentError, 'a message callback is required'
        end

        @buffer = +''.b
        @received_bytes = 0
        @message_count = 0
        @finished = false
      end

      # Consumes one adapter response chunk.
      def call(chunk, _overall_received_bytes = nil, env = nil)
        feed(chunk, env)
      end

      def feed(chunk, env = nil)
        ensure_not_finished!
        return self if chunk.nil? || chunk.bytesize.zero?

        @buffer << chunk.b
        @received_bytes += chunk.bytesize
        decode(env)
        self
      end

      # Verifies that no partial frame remains when the response ends.
      def finish
        return self if @finished
        unless @buffer.empty?
          raise TruncatedMessageError.new(
            'eventstream message was truncated',
            message_number: next_message_number,
            byte_position: current_frame_position
          )
        end

        @finished = true
        self
      end
      alias close finish

      private

      def decode(env)
        while @buffer.bytesize >= PRELUDE_LENGTH + PRELUDE_CRC_LENGTH
          frame_position = current_frame_position
          number = next_message_number

          total_length, headers_length, prelude_crc = @buffer.unpack('NNN')
          verify_prelude_crc!(number, frame_position, prelude_crc)
          verify_lengths!(number, frame_position, total_length, headers_length)
          break unless @buffer.bytesize >= total_length

          frame = @buffer.byteslice(0, total_length)
          verify_message_crc!(frame, number, frame_position)

          headers, payload = parse_message(frame, headers_length, number, frame_position)
          message = Message.new(headers, payload)
          @message_count += 1
          remaining = @buffer.bytesize - total_length
          @buffer = remaining.zero? ? +''.b : @buffer.byteslice(total_length, remaining)
          deliver(message, env)
        end
      end

      def verify_prelude_crc!(number, position, expected_crc)
        actual_crc = Zlib.crc32(@buffer.byteslice(0, PRELUDE_LENGTH))
        return if actual_crc == expected_crc

        raise PreludeCrcError.new(
          "eventstream prelude CRC mismatch (expected #{expected_crc}, got #{actual_crc})",
          message_number: number,
          byte_position: position
        )
      end

      def verify_lengths!(number, position, total_length, headers_length)
        if total_length < FIXED_FRAME_LENGTH || total_length > MAX_TOTAL_BYTE_LENGTH
          raise InvalidTotalLengthError.new(
            "eventstream total length is outside allowed bounds: #{total_length}",
            message_number: number,
            byte_position: position
          )
        end

        if headers_length > MAX_HEADERS_BYTE_LENGTH ||
           headers_length > total_length - FIXED_FRAME_LENGTH
          raise InvalidHeaderLengthError.new(
            "eventstream headers length is invalid: #{headers_length}",
            message_number: number,
            byte_position: position + 4
          )
        end

        payload_length = total_length - FIXED_FRAME_LENGTH - headers_length
        return if payload_length <= MAX_PAYLOAD_BYTE_LENGTH

        raise InvalidPayloadLengthError.new(
          "eventstream payload length is invalid: #{payload_length}",
          message_number: number,
          byte_position: position + 4
        )
      end

      def verify_message_crc!(frame, number, position)
        crc_offset = frame.bytesize - MESSAGE_CRC_LENGTH
        expected_crc = frame.byteslice(crc_offset, MESSAGE_CRC_LENGTH).unpack1('N')
        actual_crc = Zlib.crc32(frame.byteslice(0, frame.bytesize - MESSAGE_CRC_LENGTH))
        return if actual_crc == expected_crc

        raise MessageCrcError.new(
          "eventstream message CRC mismatch (expected #{expected_crc}, got #{actual_crc})",
          message_number: number,
          byte_position: position
        )
      end

      def parse_message(frame, headers_length, number, frame_position)
        headers_data = frame.byteslice(12, headers_length)
        payload_length = frame.bytesize - FIXED_FRAME_LENGTH - headers_length
        payload = frame.byteslice(12 + headers_length, payload_length)

        [parse_headers(headers_data, number, frame_position), payload]
      end

      def parse_headers(data, number, frame_position)
        headers = {}
        offset = 0

        while offset < data.bytesize
          name_length_position = frame_position + 12 + offset
          name_length = data.getbyte(offset)

          unless offset + 1 + name_length <= data.bytesize
            raise invalid_header_error(number, name_length_position)
          end

          name = data.byteslice(offset + 1, name_length)
          type_position = offset + 1 + name_length
          if type_position >= data.bytesize
            raise invalid_header_error(number, frame_position + 12 + type_position)
          end
          type_code = data.getbyte(type_position)
          absolute_type_position = frame_position + 12 + type_position
          value, value_size = parse_header_value(data, type_position, type_code, number,
                                                absolute_type_position, frame_position)

          header_type = HEADER_TYPES.fetch(type_code)
          headers[name] = HeaderValue.new(header_type, type_code, value)
          offset = type_position + 1 + value_size
        end

        headers
      end

      def parse_header_value(data, type_position, type_code, number,
                             absolute_type_position, frame_position)
        type = HEADER_TYPES[type_code]

        if type_code > 127
          raise InvalidHeaderTypeError.new(
            "eventstream header type is invalid: #{type_code}",
            message_number: number,
            byte_position: absolute_type_position
          )
        end

        unless type
          raise UnknownHeaderTypeError.new(
            "eventstream header type is unknown: #{type_code}",
            message_number: number,
            byte_position: absolute_type_position
          )
        end

        parse_known_header_value(data, type_position, type, number, frame_position)
      end

      def parse_known_header_value(data, type_position, type, number, frame_position)
        value_position = type_position + 1
        absolute_value_position = frame_position + 12 + value_position

        case type
        when :bool_true
          [true, 0]
        when :bool_false
          [false, 0]
        when :byte
          require_bytes!(data, value_position, 1, number, absolute_value_position)
          [data.byteslice(value_position, 1).unpack1('c'), 1]
        when :short
          require_bytes!(data, value_position, 2, number, absolute_value_position)
          [data.byteslice(value_position, 2).unpack1('s>'), 2]
        when :integer
          require_bytes!(data, value_position, 4, number, absolute_value_position)
          [data.byteslice(value_position, 4).unpack1('l>'), 4]
        when :long
          require_bytes!(data, value_position, 8, number, absolute_value_position)
          [data.byteslice(value_position, 8).unpack1('q>'), 8]
        when :timestamp
          require_bytes!(data, value_position, 8, number, absolute_value_position)
          milliseconds = data.byteslice(value_position, 8).unpack1('q>')
          [Time.at(milliseconds / 1000r).utc, 8]
        when :uuid
          require_bytes!(data, value_position, 16, number, absolute_value_position)
          [format_uuid(data.byteslice(value_position, 16)), 16]
        when :byte_array, :string
          require_bytes!(data, value_position, 2, number, absolute_value_position)
          length = data.byteslice(value_position, 2).unpack1('n')
          value_start = value_position + 2
          require_bytes!(data, value_start, length, number,
                           frame_position + 12 + value_start)
          value = data.byteslice(value_start, length)
          if type == :string
            value = decode_string(value, number,
                                 frame_position + 12 + value_start)
          end
          [value, 2 + length]
        end
      end

      def require_bytes!(data, start, length, number, position)
        return if start + length <= data.bytesize

        raise invalid_header_error(number, position)
      end

      def decode_string(value, number, position)
        decoded = value.dup.force_encoding(Encoding::UTF_8)
        unless decoded.valid_encoding?
          raise InvalidHeaderValueError.new(
            'eventstream string header contains invalid UTF-8',
            message_number: number,
            byte_position: position
          )
        end

        decoded
      end

      def format_uuid(data)
        time_low, time_mid, time_high, clock_seq, node = data.unpack('NnnnH12')
        format('%08x-%04x-%04x-%04x-%s', time_low, time_mid, time_high, clock_seq, node)
      end

      def invalid_header_error(number, position)
        InvalidHeaderError.new(
          'eventstream headers are malformed',
          message_number: number,
          byte_position: position || current_frame_position
        )
      end

      def deliver(message, env)
        if pass_env_to_callback?
          @on_message.call(message, env)
        else
          @on_message.call(message)
        end
      end

      def pass_env_to_callback?
        arity = @on_message.arity
        arity == 2 || arity.negative?
      end

      def next_message_number
        @message_count + 1
      end

      def current_frame_position
        @received_bytes - @buffer.bytesize
      end

      def ensure_not_finished!
        return unless @finished

        raise ProtocolError.new(
          'eventstream decoder has already been finished',
          message_number: next_message_number,
          byte_position: @received_bytes
        )
      end
    end
  end
end
