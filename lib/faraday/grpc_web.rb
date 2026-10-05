# frozen_string_literal: true

module Faraday
  # Lightweight unary gRPC-Web framing support.
  module GRPCWeb
    BINARY_CONTENT_TYPE = 'application/grpc-web+proto'
    TEXT_CONTENT_TYPE = 'application/grpc-web-text+proto'

    DATA_FRAME_TYPE = 0x00
    TRAILER_FRAME_TYPE = 0x80
    FRAME_HEADER_SIZE = 5
    DEFAULT_MAX_FRAME_SIZE = 4 * 1024 * 1024

    BASE64_GROUP_REGEX = %r{\A[A-Za-z0-9+/]{4}\z}.freeze
    BASE64_FINAL_REGEX = %r{
      \A(?:[A-Za-z0-9+/]{4})*
      (?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\z
    }x.freeze

    # Base error for gRPC-Web protocol and transport failures.
    class Error < Faraday::Error; end

    # Raised when a frame, trailer set, or base64 stream is malformed.
    class ProtocolError < Error; end
    FrameError = ProtocolError
    TruncatedError = ProtocolError

    # Raised when the HTTP response status is not 200.
    class HTTPError < Error; end
    HTTPStatusError = HTTPError

    # Raised when the gRPC trailer status is not OK.
    class StatusError < Error
      # @return [Integer, nil] the canonical gRPC status code.
      attr_reader :code

      # @return [Hash, nil] trailers returned by the gRPC-Web response.
      attr_reader :trailers

      # @param message [String] error message.
      # @param response [Faraday::Response, nil] completed Faraday response.
      # @param code [Integer, nil] canonical gRPC status code.
      # @param trailers [Hash, nil] parsed gRPC trailers.
      def initialize(message, response = nil, code = nil, trailers = nil)
        @code = code
        @trailers = trailers
        super(message, response)
      end
    end
    GRPCStatusError = StatusError

    # Parsed unary response. Data is absent for trailers-only error responses.
    class Response
      # @return [String, nil] unframed protobuf message bytes.
      attr_reader :data
      # @return [Hash, nil] parsed trailer frame.
      attr_reader :trailers

      def initialize
        @data = nil
        @trailers = nil
        @data_received = false
      end

      def data?
        @data_received
      end

      def trailers?
        !@trailers.nil?
      end

      def data=(value)
        @data_received = true
        @data = value
      end

      def trailers=(value)
        @trailers = value
      end
    end

    # Incrementally decodes framed gRPC-Web response chunks.
    class StreamDecoder
      # @param mode [:binary, :text] wire encoding.
      # @param max_frame_size [Integer] maximum accepted frame payload size.
      def initialize(mode: :binary, max_frame_size: DEFAULT_MAX_FRAME_SIZE)
        @mode = mode.to_sym
        @max_frame_size = max_frame_size
        @frame_buffer = String.new(encoding: Encoding::BINARY)
        @base64_buffer = String.new(encoding: Encoding::BINARY)
        @base64_padded = false
        @response = Response.new

        validate_options!
      end

      # Feeds one HTTP response chunk. Chunks may split frames or base64 quads.
      # @param chunk [String] encoded response chunk.
      # @return [StreamDecoder] self.
      def feed(chunk)
        binary_chunk = chunk.to_str.dup.force_encoding(Encoding::BINARY)
        if @mode == :text
          feed_base64(binary_chunk)
        else
          @frame_buffer << binary_chunk
        end

        drain_frames
        self
      end
      alias << feed

      # Completes the stream and validates that the unary response ended cleanly.
      # @return [Response] parsed response.
      def finish
        decode_base64_tail if @mode == :text
        drain_frames

        if @frame_buffer.bytesize.positive?
          raise ProtocolError, 'gRPC-Web response ended in the middle of a frame'
        end
        if @response.data? && !@response.trailers?
          raise ProtocolError, 'gRPC-Web unary response is missing its trailer frame'
        end

        @response
      end

      private

      def validate_options!
        unless %i[binary text].include?(@mode)
          raise ArgumentError, "unknown gRPC-Web mode: #{@mode.inspect}"
        end
        unless @max_frame_size.is_a?(Integer) && @max_frame_size.positive?
          raise ArgumentError, 'max_frame_size must be a positive Integer'
        end
      end

      def feed_base64(chunk)
        raise ProtocolError, 'gRPC-Web base64 data received after padding' if @base64_padded

        @base64_buffer << chunk
        while @base64_buffer.bytesize >= 4
          group = @base64_buffer.byteslice(0, 4)
          if group.include?('=')
            @base64_padded = true
            break
          end
          unless group.match?(BASE64_GROUP_REGEX)
            raise ProtocolError, 'invalid gRPC-Web base64 response'
          end

          @frame_buffer << group.unpack1('m0')
          @base64_buffer.slice!(0, 4)
        end
      end

      def decode_base64_tail
        return if @base64_buffer.empty?

        padded_group =
          case @base64_buffer.bytesize
          when 2 then @base64_buffer + '=='
          when 3 then @base64_buffer + '='
          when 4 then @base64_buffer
          else
            raise ProtocolError, 'invalid gRPC-Web base64 response'
          end

        unless padded_group.match?(BASE64_FINAL_REGEX)
          raise ProtocolError, 'invalid gRPC-Web base64 response'
        end

        @frame_buffer << padded_group.unpack1('m0')
        @base64_buffer.clear
      end

      def drain_frames
        while @frame_buffer.bytesize >= FRAME_HEADER_SIZE
          frame_type = @frame_buffer.getbyte(0)
          payload_length = @frame_buffer.byteslice(1, 4).unpack1('N')

          check_frame_size!(payload_length)
          break if @frame_buffer.bytesize < FRAME_HEADER_SIZE + payload_length

          payload = @frame_buffer.byteslice(FRAME_HEADER_SIZE, payload_length)
          @frame_buffer.slice!(0, FRAME_HEADER_SIZE + payload_length)
          handle_frame(frame_type, payload)
        end
      end

      def check_frame_size!(payload_length)
        return if payload_length <= @max_frame_size

        raise ProtocolError, "gRPC-Web frame exceeds maximum size of #{@max_frame_size} bytes"
      end

      def handle_frame(frame_type, payload)
        case frame_type
        when DATA_FRAME_TYPE
          if @response.data?
            raise ProtocolError, 'gRPC-Web unary response contains more than one data frame'
          end
          if @response.trailers?
            raise ProtocolError, 'gRPC-Web data frame received after trailer frame'
          end

          @response.data = payload
        when TRAILER_FRAME_TYPE
          if @response.trailers?
            raise ProtocolError, 'gRPC-Web response contains more than one trailer frame'
          end

          @response.trailers = parse_trailers(payload)
        else
          raise ProtocolError, "unsupported gRPC-Web frame type: 0x#{format('%02x', frame_type)}"
        end
      end

      def parse_trailers(payload)
        trailers = {}

        payload.split("\n").each do |line|
          line = line.delete_suffix("\r")
          next if line.empty?

          key, value = line.split(':', 2)
          if value.nil? || key.empty?
            raise ProtocolError, 'invalid gRPC-Web trailer frame'
          end

          key = key.downcase
          if trailers.key?(key)
            raise ProtocolError, %(duplicate gRPC-Web trailer "#{key}")
          end

          value = value.sub(/\A[ \t]+/, '').sub(/[ \t]+\z/, '')
          trailers[key] = value
        end

        trailers
      end
    end

    class << self
      # @param mode [:binary, :text] wire encoding.
      # @return [String] gRPC-Web content type for the encoding.
      def content_type(mode)
        mode = mode.to_sym
        validate_mode!(mode)
        mode == :text ? TEXT_CONTENT_TYPE : BINARY_CONTENT_TYPE
      end

      # Frames an already-encoded protobuf message.
      # @param message [String] encoded protobuf bytes.
      # @param mode [:binary, :text] wire encoding.
      # @param max_frame_size [Integer] maximum request payload size.
      # @return [String] framed request body.
      def encode_request(message, mode: :binary, max_frame_size: DEFAULT_MAX_FRAME_SIZE)
        mode = mode.to_sym
        validate_mode!(mode)
        payload = message.to_str.dup.force_encoding(Encoding::BINARY)
        check_message_size!(payload.bytesize, max_frame_size)

        frame = String.new(encoding: Encoding::BINARY)
        frame << DATA_FRAME_TYPE.chr
        frame << [payload.bytesize].pack('N')
        frame << payload
        mode == :text ? [frame].pack('m0') : frame
      end

      # Decodes a complete body or an Array of HTTP response chunks.
      # @param body [String, Array<String>] framed response body or chunks.
      # @param mode [:binary, :text] wire encoding.
      # @param max_frame_size [Integer] maximum accepted frame payload size.
      # @return [Response] parsed response.
      def decode_response(body, mode: :binary, max_frame_size: DEFAULT_MAX_FRAME_SIZE)
        decoder = StreamDecoder.new(mode: mode, max_frame_size: max_frame_size)
        pieces = body.is_a?(Array) ? body : [body]
        pieces.each do |chunk|
          next if chunk.nil?

          decoder.feed(chunk)
        end
        decoder.finish
      end

      # Decodes RFC 3986 percent escapes used by grpc-message without CGI's + rule.
      # @param value [String] metadata value.
      # @return [String] decoded binary-compatible string.
      def decode_metadata(value)
        result = String.new(encoding: Encoding::BINARY)
        index = 0

        while index < value.bytesize
          byte = value.getbyte(index)
          if byte == '%'.ord
            hex = value.byteslice(index + 1, 2)
            unless hex&.match?(/\A[0-9a-fA-F]{2}\z/)
              raise ProtocolError, 'invalid percent-encoded gRPC metadata'
            end

            result << hex.to_i(16).chr
            index += 3
          else
            result << byte.chr
            index += 1
          end
        end

        result
      end

      private

      def validate_mode!(mode)
        return if %i[binary text].include?(mode)

        raise ArgumentError, "unknown gRPC-Web mode: #{mode.inspect}"
      end

      def check_message_size!(size, max_frame_size)
        return if size <= max_frame_size

        raise ProtocolError, "gRPC-Web frame exceeds maximum size of #{max_frame_size} bytes"
      end
    end
  end
end
