# frozen_string_literal: true

module Faraday
  module GrpcWeb
    # Size in bytes of a gRPC-Web frame header (1 flag byte + 4 length bytes).
    FRAME_HEADER_SIZE = 5

    # Frame flag for an uncompressed data (message) frame.
    DATA_FLAG = 0x00

    # Frame flag marking the trailers frame.
    TRAILER_FLAG = 0x80

    # Frame flag marking a compressed data frame (not supported).
    COMPRESSED_FLAG = 0x01

    # Default upper bound for a single frame payload, in bytes (4 MiB).
    DEFAULT_MAX_FRAME_SIZE = 4 * 1024 * 1024

    # Strict base64 alphabet with optional end padding.
    BASE64_REGEX = /\A[A-Za-z0-9+\/]*={0,2}\z/

    # A single decoded gRPC-Web frame.
    Frame = Struct.new(:type, :payload)

    # The decoded result of a unary gRPC-Web call: the raw protobuf message
    # bytes (nil when the response carries no data frame) and the response
    # trailers as a Hash of downcased String keys to String values.
    Result = Struct.new(:message, :trailers) do
      # @return [Integer, nil] the grpc-status trailer, if present
      def grpc_status
        value = trailers && trailers['grpc-status']
        value && value.to_i
      end

      # @return [String, nil] the percent-decoded grpc-message trailer
      def grpc_message
        trailers && trailers['grpc-message']
      end
    end

    class << self
      # Encodes a payload into a single gRPC-Web frame.
      #
      # @param payload [String] raw bytes to frame
      # @param trailer [Boolean] whether to mark the frame as trailers
      # @return [String] the encoded frame (binary)
      def encode_frame(payload, trailer: false)
        flag = trailer ? TRAILER_FLAG : DATA_FLAG
        [flag, payload.bytesize].pack('CN') + payload
      end

      # Validates the frames of a unary response and builds a Result.
      #
      # A unary response carries at most one data frame followed by exactly
      # one trailers frame, which must be the last frame of the stream.
      #
      # @param frames [Array<Frame>] decoded frames in arrival order
      # @return [Result]
      # @raise [ProtocolError] on extra data frames, missing or misplaced
      #   trailers, or a missing grpc-status trailer
      def build_unary_result(frames)
        data_frames = frames.select { |frame| frame.type == :data }
        trailer_frames = frames.select { |frame| frame.type == :trailers }

        if data_frames.size > 1
          raise ProtocolError,
                'expected at most one data frame in a unary response, ' \
                'got ' + data_frames.size.to_s
        end
        raise ProtocolError, 'response is missing a trailers frame' if trailer_frames.empty?
        raise ProtocolError, 'response has more than one trailers frame' if trailer_frames.size > 1

        unless frames.last.equal?(trailer_frames.first)
          raise ProtocolError, 'unexpected frame after the trailers frame'
        end

        trailers = parse_trailers(trailer_frames.first.payload)
        unless trailers.key?('grpc-status')
          raise ProtocolError, 'trailers frame is missing grpc-status'
        end
        unless trailers['grpc-status'].match?(/\A\d+\z/)
          raise ProtocolError,
                'invalid grpc-status trailer: ' + trailers['grpc-status'].inspect
        end

        Result.new(data_frames.first&.payload, trailers)
      end

      # Parses a trailers frame payload into a Hash of downcased header
      # names to values. grpc-message values are percent-decoded.
      #
      # @param payload [String] raw trailers block (HTTP/1 style lines)
      # @return [Hash{String => String}]
      # @raise [ProtocolError] on malformed trailer lines
      def parse_trailers(payload)
        trailers = {}
        payload.split("\r\n").each do |line|
          next if line.empty?

          key, value = line.split(':', 2)
          raise ProtocolError, 'malformed trailer line: ' + line.inspect unless value

          key = key.strip.downcase
          value = value.strip
          value = percent_decode(value) if key == 'grpc-message'
          trailers[key] = value
        end
        trailers
      end

      private

      # Decodes gRPC percent-encoding (%XX) without treating '+' specially.
      def percent_decode(value)
        value.gsub(/%[0-9A-Fa-f]{2}/) { |match| match[1, 2].hex.chr }
      end
    end

    # Incremental parser for a gRPC-Web frame stream.
    #
    # Chunks of arbitrary size can be appended with {#<<}; frame boundaries
    # never have to align with chunk boundaries. In text mode the stream is
    # base64 encoded and chunks may also split base64 quartets.
    #
    # @example
    #   parser = Faraday::GrpcWeb::FrameParser.new
    #   parser << chunk1
    #   parser << chunk2
    #   frames = parser.finish
    class FrameParser
      # @param text [Boolean] true for application/grpc-web-text (base64)
      # @param max_frame_size [Integer] maximum accepted frame payload size
      def initialize(text: false, max_frame_size: DEFAULT_MAX_FRAME_SIZE)
        @text = text
        @max_frame_size = max_frame_size
        @buffer = +''
        @base64_rest = +''
        @base64_terminated = false
        @frames = []
        @finished = false
      end

      # Frames decoded so far.
      # @return [Array<Frame>]
      attr_reader :frames

      # Appends a chunk of the response stream.
      #
      # @param chunk [String]
      # @return [self]
      # @raise [ProtocolError] on invalid base64, unknown frame flags, or
      #   frames exceeding the configured maximum size
      def <<(chunk)
        raise ProtocolError, 'cannot append to a finished parser' if @finished

        @buffer << (@text ? decode_base64(chunk) : chunk.dup)
        drain
        self
      end

      # Signals the end of the stream.
      #
      # @return [Array<Frame>] all decoded frames
      # @raise [ProtocolError] if the stream ends mid-frame or with an
      #   incomplete base64 quartet
      def finish
        unless @base64_rest.empty?
          raise ProtocolError, 'truncated base64 data at end of stream'
        end
        unless @buffer.empty?
          raise ProtocolError, 'truncated gRPC-Web frame at end of stream'
        end

        @finished = true
        @frames
      end

      private

      def decode_base64(chunk)
        data = @base64_rest + chunk
        decodable = data.bytesize / 4 * 4
        @base64_rest = data.byteslice(decodable..) || +''
        return +'' if decodable.zero?

        part = data.byteslice(0, decodable)
        if @base64_terminated
          raise ProtocolError, 'base64 data found after end padding'
        end

        unless part.match?(BASE64_REGEX)
          raise ProtocolError, 'invalid base64 data in gRPC-Web text stream'
        end

        @base64_terminated = part.include?('=')
        part.unpack1('m')
      end

      def drain
        loop do
          break if @buffer.bytesize < FRAME_HEADER_SIZE

          flag, length = @buffer.unpack('CN')
          if length > @max_frame_size
            raise ProtocolError,
                  'gRPC-Web frame of ' + length.to_s + ' bytes exceeds the ' \
                  'limit of ' + @max_frame_size.to_s + ' bytes'
          end
          type = frame_type(flag)
          break if @buffer.bytesize < FRAME_HEADER_SIZE + length
          payload = @buffer.byteslice(FRAME_HEADER_SIZE, length)
          @buffer = @buffer.byteslice(FRAME_HEADER_SIZE + length..) || +''
          @frames << Frame.new(type, payload)
        end
      end

      def frame_type(flag)
        if (flag & COMPRESSED_FLAG).positive?
          raise ProtocolError, 'compressed gRPC-Web frames are not supported'
        end

        case flag
        when DATA_FLAG then :data
        when TRAILER_FLAG then :trailers
        else
          raise ProtocolError, 'unknown gRPC-Web frame flag: ' + flag.to_s
        end
      end
    end
  end
end
